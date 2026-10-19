//! Ouverture automatique du port sur la box, et message d'état en clair.
//!
//! Deux protocoles sont essayés, dans cet ordre (comme Bitcoin Core) :
//!   1. UPnP (voir node.rs) ;
//!   2. NAT-PMP (RFC 6886), utilisé par de nombreuses box et routeurs quand l'UPnP est coupé.
//!
//! Ce module contient NAT-PMP, la recherche de l'adresse de la box, et `PortState`,
//! l'état affiché à l'utilisateur dans l'accueil et les Réglages.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Port UDP sur lequel une box répond en NAT-PMP.
pub const NATPMP_PORT: u16 = 5351;

/// État de l'ouverture du port, vu par l'utilisateur.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum PortState {
    /// Recherche de la box en cours (premières secondes après le démarrage).
    #[default]
    Searching,
    /// Port ouvert, et l'adresse de la box est publique : tout le monde peut se connecter à ce PC.
    Open { port: u16, via: &'static str },
    /// Port ouvert sur la box, mais l'adresse de la box n'est pas publique (adresse partagée par
    /// l'opérateur, 4G/5G, « CGNAT ») : personne ne peut se connecter à ce PC en premier.
    Shared { port: u16 },
    /// Aucune box n'a répondu (UPnP et NAT-PMP coupés ou absents).
    NoRouter,
    /// Une box a répondu, mais refuse d'ouvrir le port.
    Refused,
}

impl PortState {
    /// Vrai si les autres peuvent se connecter à ce PC depuis Internet.
    pub fn joignable(&self) -> bool {
        matches!(self, PortState::Open { .. })
    }

    /// Niveau pour l'affichage : 0 = en cours, 1 = bon, 2 = à améliorer.
    pub fn niveau(&self) -> u8 {
        match self {
            PortState::Searching => 0,
            PortState::Open { .. } => 1,
            _ => 2,
        }
    }

    /// Titre court (une ligne), en français ou en anglais selon la langue choisie.
    pub fn titre(&self) -> String {
        use crate::tf;
        match self {
            PortState::Searching => crate::i18n::t("Recherche de ta box…", "Looking for your router…").to_string(),
            PortState::Open { port, .. } => tf!(
                "Port {port} ouvert automatiquement : les autres peuvent se connecter à toi",
                "Port {port} opened automatically: others can connect to you"
            ),
            PortState::Shared { .. } => crate::i18n::t(
                "Ton accès Internet est partagé : personne ne peut se connecter à toi en premier",
                "Your Internet access is shared: nobody can connect to you first",
            )
            .to_string(),
            PortState::NoRouter => crate::i18n::t(
                "Ta box ne répond pas à l'ouverture automatique du port",
                "Your router does not answer the automatic port opening",
            )
            .to_string(),
            PortState::Refused => crate::i18n::t(
                "Ta box refuse d'ouvrir le port",
                "Your router refuses to open the port",
            )
            .to_string(),
        }
    }

    /// Explication détaillée : pourquoi, et quoi faire. Vide si tout va bien.
    pub fn explication(&self) -> String {
        use crate::i18n::t;
        match self {
            PortState::Searching | PortState::Open { .. } => String::new(),
            PortState::Shared { .. } => t(
                "Ton opérateur te donne une adresse Internet partagée avec d'autres abonnés (4G/5G, ou fibre avec « CGNAT »). \
                 Aucun logiciel ne peut y ouvrir de port. NumFranc fonctionne quand même : il se connecte aux autres, tu peux miner et envoyer normalement. \
                 Pour être joignable, demande à ton opérateur une adresse IPv4 publique (gratuite chez la plupart, par exemple dans l'espace abonné), \
                 ou branche-toi sur une autre connexion.",
                "Your provider gives you an Internet address shared with other customers (4G/5G, or fibre with « CGNAT »). \
                 No software can open a port there. NumFranc still works: it connects to others, mines and sends normally. \
                 To be reachable, ask your provider for a public IPv4 address (free with most, often in the customer area), \
                 or use another connection.",
            )
            .to_string(),
            PortState::NoRouter => t(
                "NumFranc a cherché ta box en UPnP et en NAT-PMP sans réponse. Dans les réglages de ta box, active « UPnP » (parfois appelé « ouverture de ports automatique »), \
                 puis relance NumFranc. Ce n'est pas obligatoire : NumFranc fonctionne quand même et se connecte aux autres, \
                 mais les autres ne peuvent pas se connecter à toi en premier.",
                "NumFranc looked for your router with UPnP and NAT-PMP and got no answer. In your router settings, turn on « UPnP » \
                 (sometimes called « automatic port opening »), then restart NumFranc. It is not required: NumFranc still works and connects to others, \
                 but others cannot connect to you first.",
            )
            .to_string(),
            PortState::Refused => t(
                "Ta box a répondu mais refuse l'ouverture (ports déjà pris, ou UPnP limité). Ferme les autres logiciels de partage sur ce réseau \
                 et relance NumFranc. Chez Free, demande l'IPv4 fixe « full-stack » dans l'Espace Abonné. NumFranc fonctionne quand même, \
                 mais les autres ne peuvent pas se connecter à toi en premier.",
                "Your router answered but refuses to open the port (ports already taken, or limited UPnP). Close other sharing software on this network \
                 and restart NumFranc. NumFranc still works, but others cannot connect to you first.",
            )
            .to_string(),
        }
    }
}

/// Vrai si l'adresse peut être jointe depuis Internet (ni privée, ni locale, ni 100.64.0.0/10 des opérateurs).
pub fn est_publique(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || (o[0] == 100 && (64..128).contains(&o[1])))
}

// ---------------------------------------------------------------------------
// NAT-PMP
// ---------------------------------------------------------------------------

fn requete(sock: &UdpSocket, paquet: &[u8], attendu: usize) -> Result<Vec<u8>, String> {
    let mut tampon = [0u8; 64];
    // La norme demande 250 ms puis on double ; deux essais suffisent pour une box locale.
    for delai in [500u64, 1_000] {
        sock.set_read_timeout(Some(Duration::from_millis(delai))).map_err(|e| e.to_string())?;
        sock.send(paquet).map_err(|e| e.to_string())?;
        if let Ok(n) = sock.recv(&mut tampon) {
            if n >= attendu {
                return Ok(tampon[..n].to_vec());
            }
        }
    }
    Err("pas de réponse".to_string())
}

fn controle(rep: &[u8], op: u8) -> Result<(), String> {
    if rep.len() < 8 || rep[0] != 0 || rep[1] != op {
        return Err("réponse invalide".to_string());
    }
    match u16::from_be_bytes([rep[2], rep[3]]) {
        0 => Ok(()),
        c => Err(format!("refus (code {c})")),
    }
}

/// Demande à la box (`passerelle`, port 5351 en vrai) d'ouvrir le port TCP `interne` vers ce PC.
/// Renvoie (adresse publique de la box, port public obtenu).
pub fn natpmp_ouvrir(
    passerelle: SocketAddr,
    interne: u16,
    souhaite: u16,
    duree_s: u32,
) -> Result<(Ipv4Addr, u16), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect(passerelle).map_err(|e| e.to_string())?;
    // 1. Adresse publique de la box.
    let rep = requete(&sock, &[0, 0], 12)?;
    controle(&rep, 128)?;
    let ip = Ipv4Addr::new(rep[8], rep[9], rep[10], rep[11]);
    // 2. Ouverture du port (opération 2 = TCP).
    let mut req = [0u8; 12];
    req[1] = 2;
    req[4..6].copy_from_slice(&interne.to_be_bytes());
    req[6..8].copy_from_slice(&souhaite.to_be_bytes());
    req[8..12].copy_from_slice(&duree_s.to_be_bytes());
    let rep = requete(&sock, &req, 16)?;
    controle(&rep, 130)?;
    let obtenu = u16::from_be_bytes([rep[10], rep[11]]);
    if obtenu == 0 {
        return Err("port refusé".to_string());
    }
    Ok((ip, obtenu))
}

/// Adresse de la box (« passerelle par défaut »), sans service ni bibliothèque en plus.
pub fn passerelle_par_defaut() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let t = std::fs::read_to_string("/proc/net/route").ok()?;
        for l in t.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() > 3 && c[1] == "00000000" {
                let v = u32::from_str_radix(c[2], 16).ok()?;
                // /proc/net/route donne l'adresse en ordre « petit boutiste ».
                return Some(Ipv4Addr::from(v.swap_bytes()));
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let s = std::process::Command::new("/sbin/route").args(["-n", "get", "default"]).output().ok()?;
        analyser_mac(&String::from_utf8_lossy(&s.stdout))
    }
    #[cfg(target_os = "windows")]
    {
        let racine = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let exe = std::path::Path::new(&racine).join("System32").join("route.exe");
        let s = std::process::Command::new(exe).args(["print", "-4", "0.0.0.0"]).output().ok()?;
        analyser_windows(&String::from_utf8_lossy(&s.stdout))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[allow(dead_code)]
fn analyser_mac(sortie: &str) -> Option<Ipv4Addr> {
    sortie.lines().find_map(|l| l.trim().strip_prefix("gateway:")).and_then(|g| g.trim().parse().ok())
}

#[allow(dead_code)]
fn analyser_windows(sortie: &str) -> Option<Ipv4Addr> {
    // Ligne du type : "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     25"
    sortie.lines().find_map(|l| {
        let c: Vec<&str> = l.split_whitespace().collect();
        if c.len() >= 3 && c[0] == "0.0.0.0" && c[1] == "0.0.0.0" { c[2].parse().ok() } else { None }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fausse box NAT-PMP : répond comme la norme, sur un port local libre.
    fn fausse_box(refuse: bool) -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 64];
            while let Ok((n, de)) = s.recv_from(&mut b) {
                let rep: Vec<u8> = if n == 2 {
                    vec![0, 128, 0, 0, 0, 0, 0, 1, 81, 12, 34, 56]
                } else {
                    let code: u8 = if refuse { 2 } else { 0 };
                    // port public donné par la box : 40000
                    vec![0, 130, 0, code, 0, 0, 0, 1, b[4], b[5], 0x9C, 0x40, 0, 0, 0x04, 0xB0]
                };
                let _ = s.send_to(&rep, de);
            }
        });
        addr
    }

    #[test]
    fn natpmp_ouvre_le_port() {
        let (ip, port) = natpmp_ouvrir(fausse_box(false), 6910, 6910, 1200).unwrap();
        assert_eq!(ip, Ipv4Addr::new(81, 12, 34, 56));
        assert_eq!(port, 40_000);
    }

    #[test]
    fn natpmp_refus_signale() {
        assert!(natpmp_ouvrir(fausse_box(true), 6910, 6910, 1200).unwrap_err().contains("refus"));
    }

    #[test]
    fn natpmp_sans_box_ne_bloque_pas() {
        // Un port où personne n'écoute : échec rapide, pas de blocage.
        let t = std::time::Instant::now();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = s.local_addr().unwrap();
        assert!(natpmp_ouvrir(addr, 6910, 6910, 1200).is_err());
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn adresses_publiques() {
        assert!(est_publique(Ipv4Addr::new(81, 12, 34, 56)));
        assert!(!est_publique(Ipv4Addr::new(192, 168, 1, 5)));
        assert!(!est_publique(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!est_publique(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!est_publique(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(est_publique(Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!est_publique(Ipv4Addr::new(169, 254, 1, 1)));
    }

    #[test]
    fn passerelle_lue_sur_les_trois_systemes() {
        assert_eq!(analyser_mac("   route to: default\n    gateway: 192.168.1.254\n  interface: en0"), Some(Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(
            analyser_windows("          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     25"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(analyser_mac("rien"), None);
    }
}
