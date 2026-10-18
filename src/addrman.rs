//! Annuaire des pairs, sur le modèle d'« addrman » de Bitcoin Core.
//!
//! Deux listes :
//! - **nouvelles** : adresses entendues mais jamais essayées avec succès ;
//! - **testées** : adresses où une connexion sortante a vraiment fonctionné.
//!
//! Protections contre l'empoisonnement (un pirate qui remplit l'annuaire de fausses adresses
//! pour isoler un nœud, attaque « éclipse ») :
//! - les adresses sont rangées par **quartier d'Internet** (/16 en IPv4, /32 en IPv6) : un pirate
//!   qui possède beaucoup d'adresses dans le même quartier n'occupe que quelques places ;
//! - un même pair (quartier source) ne peut apporter qu'un nombre limité d'adresses ;
//! - les adresses privées, locales ou réservées sont refusées (elles viennent de la découverte
//!   locale, pas d'un inconnu sur Internet) ;
//! - quand une liste est pleine, on remplace une entrée **au hasard** dans le quartier le plus
//!   représenté, jamais toujours la même ;
//! - les sorties choisissent au plus un pair par quartier (voir node.rs).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Taille maximale de la liste des adresses nouvelles.
pub const NEW_MAX: usize = 1024;
/// Taille maximale de la liste des adresses testées.
pub const TRIED_MAX: usize = 256;
/// Au plus 8 adresses nouvelles par quartier d'Internet.
pub const PER_GROUP_NEW: usize = 8;
/// Au plus 4 adresses testées par quartier d'Internet.
pub const PER_GROUP_TRIED: usize = 4;
/// Au plus 64 adresses nouvelles apportées par un même quartier source.
pub const PER_SOURCE_NEW: usize = 64;
/// Une adresse jamais joignable est oubliée après ce nombre d'essais.
const MAX_FAILURES: u32 = 10;
/// On ne réessaie pas une même adresse avant ce délai.
const RETRY_DELAY: Duration = Duration::from_secs(60);

/// « Quartier d'Internet » d'une adresse IP : les 2 premiers octets en IPv4, les 4 premiers en IPv6.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Group([u8; 5]);

pub fn group(ip: &IpAddr) -> Group {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Group([4, o[0], o[1], 0, 0])
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => group(&IpAddr::V4(v4)),
            None => {
                let o = v6.octets();
                Group([6, o[0], o[1], o[2], o[3]])
            }
        },
    }
}

/// Quartier fictif pour les adresses trouvées dans l'annuaire mondial (DHT).
pub const DHT_SOURCE: Group = Group([0xD4, 0, 0, 0, 0]);

/// Vrai si l'adresse IP est privée, locale ou réservée (box, réseau local, etc.).
pub fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 (CGNAT)
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_ip(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xFE00) == 0xFC00 // fc00::/7, adresses locales uniques
                || (s[0] & 0xFFC0) == 0xFE80 // fe80::/10, lien local
                || (s[0] == 0x2001 && s[1] == 0x0DB8) // documentation
        }
    }
}

/// Adresse acceptable dans l'annuaire : publique et avec un port.
pub fn routable(addr: &SocketAddr) -> bool {
    addr.port() != 0 && !is_local_ip(&addr.ip())
}

#[derive(Clone, Debug)]
struct Entry {
    source: Group,
    failures: u32,
    last_try: Option<Instant>,
    succeeded: bool,
}

#[derive(Default)]
pub struct AddrMan {
    new: HashMap<SocketAddr, Entry>,
    tried: HashMap<SocketAddr, Entry>,
}

/// Nombre aléatoire dans 0..n (n > 0).
fn rand_below(n: usize) -> usize {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    (u64::from_le_bytes(b) % n as u64) as usize
}

fn count_group(t: &HashMap<SocketAddr, Entry>, g: Group) -> usize {
    t.keys().filter(|a| group(&a.ip()) == g).count()
}

/// Choisit au hasard une entrée du quartier le plus représenté (pour faire de la place).
fn victim(t: &HashMap<SocketAddr, Entry>, only: Option<Group>) -> Option<SocketAddr> {
    let target = match only {
        Some(g) => g,
        None => {
            let mut counts: HashMap<Group, usize> = HashMap::new();
            for a in t.keys() {
                *counts.entry(group(&a.ip())).or_default() += 1;
            }
            *counts.iter().max_by_key(|(_, c)| **c)?.0
        }
    };
    let list: Vec<SocketAddr> = t.keys().filter(|a| group(&a.ip()) == target).copied().collect();
    if list.is_empty() { None } else { Some(list[rand_below(list.len())]) }
}

impl AddrMan {
    pub fn len(&self) -> usize {
        self.new.len() + self.tried.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn tried_len(&self) -> usize {
        self.tried.len()
    }
    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.new.contains_key(addr) || self.tried.contains_key(addr)
    }

    /// Ajoute une adresse entendue. `source` : quartier du pair qui nous l'a donnée.
    /// Renvoie vrai si l'adresse a été ajoutée.
    pub fn add(&mut self, addr: SocketAddr, source: Group) -> bool {
        if !routable(&addr) || self.contains(&addr) {
            return false;
        }
        let g = group(&addr.ip());
        if count_group(&self.new, g) >= PER_GROUP_NEW {
            return false;
        }
        if self.new.values().filter(|e| e.source == source).count() >= PER_SOURCE_NEW {
            return false;
        }
        if self.new.len() >= NEW_MAX {
            // D'abord une adresse « sans espoir » (jamais joignable), sinon au hasard dans le plus gros quartier.
            let hopeless = self.new.iter().find(|(_, e)| !e.succeeded && e.failures >= 3).map(|(a, _)| *a);
            match hopeless.or_else(|| victim(&self.new, None)) {
                Some(v) => {
                    self.new.remove(&v);
                }
                None => return false,
            }
        }
        self.new.insert(addr, Entry { source, failures: 0, last_try: None, succeeded: false });
        true
    }

    /// Une connexion sortante vers `addr` a réussi : l'adresse passe dans la liste des testées.
    pub fn good(&mut self, addr: SocketAddr) {
        if !routable(&addr) {
            return;
        }
        let mut e = self.new.remove(&addr).or_else(|| self.tried.remove(&addr)).unwrap_or(Entry {
            source: group(&addr.ip()),
            failures: 0,
            last_try: None,
            succeeded: false,
        });
        e.succeeded = true;
        e.failures = 0;
        let g = group(&addr.ip());
        // Place limitée par quartier et au total : l'entrée remplacée retourne dans les nouvelles.
        let evict = if count_group(&self.tried, g) >= PER_GROUP_TRIED {
            victim(&self.tried, Some(g))
        } else if self.tried.len() >= TRIED_MAX {
            victim(&self.tried, None)
        } else {
            None
        };
        if let Some(v) = evict {
            if let Some(old) = self.tried.remove(&v) {
                if count_group(&self.new, group(&v.ip())) < PER_GROUP_NEW && self.new.len() < NEW_MAX {
                    self.new.insert(v, old);
                }
            }
        }
        self.tried.insert(addr, e);
    }

    /// On essaie de se connecter à `addr` (compté comme un échec tant que `good` n'est pas appelé).
    pub fn attempt(&mut self, addr: &SocketAddr) {
        let now = Instant::now();
        if let Some(e) = self.tried.get_mut(addr) {
            e.last_try = Some(now);
            e.failures += 1;
            return;
        }
        let forget = match self.new.get_mut(addr) {
            Some(e) => {
                e.last_try = Some(now);
                e.failures += 1;
                e.failures >= MAX_FAILURES
            }
            None => false,
        };
        if forget {
            self.new.remove(addr);
        }
    }

    pub fn remove(&mut self, addr: &SocketAddr) {
        self.new.remove(addr);
        self.tried.remove(addr);
    }

    /// Choisit une adresse à essayer : moitié du temps dans les testées, moitié dans les nouvelles,
    /// en évitant les quartiers où l'on a déjà une connexion sortante.
    pub fn select(&self, exclude: &HashSet<Group>) -> Option<SocketAddr> {
        let ok = |a: &SocketAddr, e: &Entry| !exclude.contains(&group(&a.ip())) && e.last_try.is_none_or(|t| t.elapsed() >= RETRY_DELAY);
        let tried: Vec<SocketAddr> = self.tried.iter().filter(|(a, e)| ok(a, e)).map(|(a, _)| *a).collect();
        let new: Vec<SocketAddr> = self.new.iter().filter(|(a, e)| ok(a, e)).map(|(a, _)| *a).collect();
        let list = match (tried.is_empty(), new.is_empty()) {
            (true, true) => return None,
            (false, true) => tried,
            (true, false) => new,
            (false, false) => {
                if rand_below(2) == 0 { tried } else { new }
            }
        };
        Some(list[rand_below(list.len())])
    }

    /// Échantillon aléatoire d'adresses à partager avec un pair (au plus `max`).
    pub fn sample(&self, max: usize) -> Vec<SocketAddr> {
        let mut all: Vec<SocketAddr> = self.tried.keys().chain(self.new.keys()).copied().collect();
        let mut out = Vec::new();
        while !all.is_empty() && out.len() < max {
            out.push(all.swap_remove(rand_below(all.len())));
        }
        out
    }

    /// Texte enregistré dans peers.txt (une adresse par ligne, précédée de « testee » ou « nouvelle »).
    pub fn to_text(&self) -> String {
        let mut lines: Vec<String> = self.tried.keys().map(|a| format!("testee {a}")).collect();
        lines.extend(self.new.keys().map(|a| format!("nouvelle {a}")));
        lines.sort();
        lines.join("\n")
    }

    /// Relit peers.txt (les anciennes lignes sans préfixe sont rangées dans les nouvelles).
    pub fn from_text(text: &str) -> Self {
        let mut m = Self::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (tried, a) = match line.split_once(' ') {
                Some(("testee", a)) => (true, a),
                Some(("nouvelle", a)) => (false, a),
                _ => (false, line),
            };
            let Ok(addr) = a.trim().parse::<SocketAddr>() else { continue };
            if tried {
                m.good(addr);
            } else {
                m.add(addr, group(&addr.ip()));
            }
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn adresses_privees_et_reservees_refusees() {
        let mut m = AddrMan::default();
        let src = group(&"8.8.8.8".parse().unwrap());
        for bad in ["127.0.0.1:6910", "192.168.1.20:6910", "10.0.0.5:6910", "172.16.3.4:6910", "100.64.1.1:6910", "0.1.2.3:6910", "169.254.1.1:6910", "5.6.7.8:0", "[::1]:6910", "[fe80::1]:6910", "[fd00::1]:6910", "[::ffff:192.168.1.1]:6910"] {
            assert!(!m.add(a(bad), src), "{bad} aurait dû être refusée");
        }
        assert!(m.add(a("5.6.7.8:6910"), src));
        assert!(m.add(a("[2a01:e0a::1]:6910"), src));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn un_quartier_ne_peut_pas_tout_remplir() {
        let mut m = AddrMan::default();
        // Le pirate possède tout le quartier 66.66.x.x et envoie 1 000 adresses depuis plusieurs sources.
        for i in 0..1000u32 {
            let addr = SocketAddr::new(IpAddr::V4([66, 66, (i / 256) as u8, (i % 256) as u8].into()), 6910);
            let src = group(&IpAddr::V4([(i % 200) as u8 + 1, 1, 1, 1].into()));
            m.add(addr, src);
        }
        assert_eq!(m.len(), PER_GROUP_NEW);
        // Une seule source ne peut pas apporter plus de PER_SOURCE_NEW adresses, même réparties partout.
        let mut m = AddrMan::default();
        let src = group(&"9.9.9.9".parse().unwrap());
        for i in 0..1000u32 {
            m.add(SocketAddr::new(IpAddr::V4([(i % 200) as u8 + 1, (i / 200) as u8, 1, 1].into()), 6910), src);
        }
        assert_eq!(m.len(), PER_SOURCE_NEW);
    }

    #[test]
    fn adresses_testees_protegees_et_limitees_par_quartier() {
        let mut m = AddrMan::default();
        for i in 1..=10u8 {
            m.good(SocketAddr::new(IpAddr::V4([80, 12, i, 1].into()), 6910));
        }
        assert_eq!(m.tried_len(), PER_GROUP_TRIED);
        // Les adresses sorties des testées retournent dans les nouvelles (dans la limite du quartier).
        assert!(m.len() <= PER_GROUP_TRIED + PER_GROUP_NEW);
    }

    #[test]
    fn choix_hors_des_quartiers_deja_utilises() {
        let mut m = AddrMan::default();
        m.good(a("80.12.1.1:6910"));
        m.add(a("91.2.3.4:6910"), group(&"1.1.1.1".parse().unwrap()));
        let mut ex = HashSet::new();
        ex.insert(group(&"80.12.200.200".parse().unwrap()));
        for _ in 0..20 {
            assert_eq!(m.select(&ex), Some(a("91.2.3.4:6910")));
        }
        ex.insert(group(&"91.2.0.0".parse().unwrap()));
        assert_eq!(m.select(&ex), None);
    }

    #[test]
    fn adresse_injoignable_oubliee() {
        let mut m = AddrMan::default();
        let x = a("91.2.3.4:6910");
        m.add(x, group(&"1.1.1.1".parse().unwrap()));
        for _ in 0..MAX_FAILURES {
            m.attempt(&x);
        }
        assert!(!m.contains(&x));
    }

    #[test]
    fn sauvegarde_et_relecture() {
        let mut m = AddrMan::default();
        m.good(a("80.12.1.1:6910"));
        m.add(a("91.2.3.4:6910"), group(&"1.1.1.1".parse().unwrap()));
        let r = AddrMan::from_text(&m.to_text());
        assert_eq!(r.tried_len(), 1);
        assert_eq!(r.len(), 2);
        // Ancien format (une adresse par ligne) et lignes piégées.
        let r = AddrMan::from_text("91.2.3.4:6910\n192.168.1.5:6910\nn'importe quoi\n");
        assert_eq!(r.len(), 1);
    }
}
