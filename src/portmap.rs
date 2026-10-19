//! Ouverture automatique du port sur la box, et message d'état en clair.
//!
//! Trois protocoles sont essayés, dans cet ordre :
//!   1. UPnP (voir node.rs), d'abord par diffusion, puis en s'adressant directement à la box ;
//!   2. NAT-PMP (RFC 6886), utilisé par de nombreuses box et routeurs quand l'UPnP est coupé ;
//!   3. PCP (RFC 6887), le successeur de NAT-PMP, présent sur les routeurs récents.
//!
//! Ce module contient NAT-PMP et PCP, la recherche de l'adresse de la box, le guide de réglage
//! manuel (`AideBox`) et `PortState`, l'état affiché à l'utilisateur dans l'accueil et les Réglages.

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
    /// Aucune box n'a répondu (UPnP, NAT-PMP et PCP coupés ou absents).
    NoRouter,
    /// Une box a répondu, mais refuse d'ouvrir le port.
    Refused,
    /// L'utilisateur dit avoir ouvert le port à la main ; aucun nœud ne s'est encore connecté.
    ManualWaiting { port: u16 },
    /// Preuve : un autre nœud s'est connecté à ce PC depuis Internet (port ouvert, par la box ou à la main).
    Confirmed { port: u16 },
}

impl PortState {
    /// Vrai si les autres peuvent se connecter à ce PC depuis Internet.
    pub fn joignable(&self) -> bool {
        matches!(self, PortState::Open { .. } | PortState::Confirmed { .. })
    }

    /// Faut-il montrer le guide de réglage manuel (adresse de la box, bouton, étapes) ?
    pub fn guide_utile(&self) -> bool {
        matches!(self, PortState::NoRouter | PortState::Refused | PortState::Shared { .. } | PortState::ManualWaiting { .. })
    }

    /// Niveau pour l'affichage : 0 = en cours, 1 = bon, 2 = à améliorer.
    pub fn niveau(&self) -> u8 {
        match self {
            PortState::Searching => 0,
            PortState::Open { .. } | PortState::Confirmed { .. } => 1,
            PortState::ManualWaiting { .. } => 0,
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
            PortState::Confirmed { port } => tf!(
                "Port {port} ouvert : un autre nœud s'est connecté à toi depuis Internet",
                "Port {port} open: another node connected to you from the Internet"
            ),
            PortState::ManualWaiting { .. } => crate::i18n::t(
                "Port ouvert à la main : en attente d'un premier nœud qui se connecte à toi",
                "Port opened by hand: waiting for a first node to connect to you",
            )
            .to_string(),
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
            PortState::Searching | PortState::Open { .. } | PortState::Confirmed { .. } => String::new(),
            PortState::Shared { .. } => t(
                "Ton opérateur te donne une adresse Internet partagée avec d'autres abonnés (4G/5G, ou fibre avec « CGNAT »). \
                 Aucun logiciel ne peut y ouvrir de port. NumFranc fonctionne quand même : il se connecte aux autres, tu peux miner et envoyer normalement. \
                 Pour être joignable, demande à ton opérateur une adresse IPv4 publique (souvent gratuite, dans l'espace client), \
                 ou branche-toi sur une autre connexion.",
                "Your provider gives you an Internet address shared with other customers (4G/5G, or fibre with « CGNAT »). \
                 No software can open a port there. NumFranc still works: it connects to others, mines and sends normally. \
                 To be reachable, ask your provider for a public IPv4 address (often free, in the customer area), \
                 or use another connection.",
            )
            .to_string(),
            PortState::NoRouter => t(
                "NumFranc a cherché ta box avec UPnP, NAT-PMP et PCP, sans réponse. Ce n'est pas grave : NumFranc fonctionne quand même, \
                 se connecte aux autres, mine et envoie normalement. Seulement, les autres ne peuvent pas se connecter à toi en premier. \
                 Pour y remédier, suis le guide ci-dessous (quelques minutes, une seule fois).",
                "NumFranc looked for your router with UPnP, NAT-PMP and PCP and got no answer. That is fine: NumFranc still works, \
                 connects to others, mines and sends normally. It just means others cannot connect to you first. \
                 To fix it, follow the guide below (a few minutes, once).",
            )
            .to_string(),
            PortState::Refused => t(
                "Ta box a répondu mais refuse d'ouvrir le port (ports déjà pris, réglage limité, ou adresse partagée par ton opérateur). \
                 Ferme les autres logiciels de partage de fichiers sur ce réseau et relance NumFranc, ou suis le guide ci-dessous. \
                 NumFranc fonctionne quand même, mais les autres ne peuvent pas se connecter à toi en premier.",
                "Your router answered but refuses to open the port (ports already taken, limited settings, or an address shared by your provider). \
                 Close other file-sharing software on this network and restart NumFranc, or follow the guide below. \
                 NumFranc still works, but others cannot connect to you first.",
            )
            .to_string(),
            PortState::ManualWaiting { .. } => t(
                "Tu as indiqué avoir ouvert le port toi-même. Dès qu'un autre nœud se connecte à toi, ce message devient vert (cela peut prendre quelques heures). \
                 Si rien ne vient après une journée, vérifie la redirection : bon port, type TCP, et adresse de ce PC (voir le guide ci-dessous).",
                "You said you opened the port yourself. As soon as another node connects to you, this message turns green (it can take a few hours). \
                 If nothing happens after a day, check the forwarding: right port, TCP type, and this computer's address (see the guide below).",
            )
            .to_string(),
        }
    }

    /// Les étapes à suivre sur la page de la box (valables partout, sans nom de marque).
    pub fn etapes() -> String {
        crate::i18n::t(
            "1. Ouvre la page de ta box avec le bouton ci-dessous (son mot de passe est souvent écrit sous la box ou dans sa notice).\n\
             2. Cherche « UPnP » et active-le. Si tu ne le trouves pas, cherche « redirection de ports », « Port forwarding », « NAT » ou « Serveur virtuel ».\n\
             3. Redirige le port TCP indiqué ci-dessous vers l'adresse de cet ordinateur (aussi ci-dessous), puis coche la case « J'ai ouvert le port moi-même » et relance NumFranc.",
            "1. Open your router's page with the button below (its password is often printed under the router or in its leaflet).\n\
             2. Look for « UPnP » and turn it on. If you cannot find it, look for « port forwarding », « NAT » or « virtual server ».\n\
             3. Forward the TCP port shown below to this computer's address (also below), then tick « I opened the port myself » and restart NumFranc.",
        )
        .to_string()
    }
}

/// Ce qu'il faut savoir pour régler la box à la main : adresse de la box, adresse de ce PC, port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AideBox {
    pub box_ip: Option<Ipv4Addr>,
    pub pc_ip: Option<std::net::IpAddr>,
    pub port: u16,
}

/// Cherche l'adresse de la box et celle de ce PC sur le réseau local (rien n'est envoyé sur Internet).
pub fn aide_box(port: u16) -> AideBox {
    let box_ip = passerelle_par_defaut();
    let cible = SocketAddr::new(std::net::IpAddr::V4(box_ip.unwrap_or(Ipv4Addr::new(1, 1, 1, 1))), 9);
    // Un « connect » UDP n'envoie aucun paquet : il sert seulement à savoir quelle adresse locale serait utilisée.
    let pc_ip = UdpSocket::bind("0.0.0.0:0").ok().and_then(|s| s.connect(cible).ok().map(|_| s)).and_then(|s| s.local_addr().ok()).map(|a| a.ip());
    AideBox { box_ip, pc_ip, port }
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

// ---------------------------------------------------------------------------
// PCP (RFC 6887), opération MAP
// ---------------------------------------------------------------------------

/// Demande à la box (`passerelle`, port 5351 en vrai) d'ouvrir le port TCP `interne` vers ce PC
/// (`local` : l'adresse de ce PC vue par la box). Renvoie (adresse publique, port public obtenu).
pub fn pcp_ouvrir(
    passerelle: SocketAddr,
    local: Ipv4Addr,
    interne: u16,
    souhaite: u16,
    duree_s: u32,
) -> Result<(std::net::IpAddr, u16), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect(passerelle).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
    let mut req = [0u8; 60];
    req[0] = 2; // version
    req[1] = 1; // opération MAP, requête
    req[4..8].copy_from_slice(&duree_s.to_be_bytes());
    // Adresse du client, au format IPv6 (IPv4 précédée de ::ffff:).
    req[18] = 0xff;
    req[19] = 0xff;
    req[20..24].copy_from_slice(&local.octets());
    req[24..36].copy_from_slice(&nonce);
    req[36] = 6; // TCP
    req[40..42].copy_from_slice(&interne.to_be_bytes());
    req[42..44].copy_from_slice(&souhaite.to_be_bytes());
    let rep = requete(&sock, &req, 60)?;
    if rep[0] != 2 || rep[1] != 0x81 {
        return Err("réponse invalide".to_string());
    }
    if rep[3] != 0 {
        return Err(format!("refus (code {})", rep[3]));
    }
    // Le nonce doit être le nôtre : sinon la réponse n'est pas pour nous.
    if rep[24..36] != nonce {
        return Err("réponse invalide".to_string());
    }
    let obtenu = u16::from_be_bytes([rep[42], rep[43]]);
    if obtenu == 0 {
        return Err("port refusé".to_string());
    }
    let mut oct = [0u8; 16];
    oct.copy_from_slice(&rep[44..60]);
    let v6 = std::net::Ipv6Addr::from(oct);
    let ip = match v6.to_ipv4_mapped() {
        Some(v4) => std::net::IpAddr::V4(v4),
        None => std::net::IpAddr::V6(v6),
    };
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

    /// Fausse box PCP : recopie le nonce, donne le port 40000 et l'adresse 81.12.34.56.
    fn fausse_box_pcp(refuse: bool) -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 128];
            while let Ok((n, de)) = s.recv_from(&mut b) {
                if n < 60 {
                    continue;
                }
                let mut rep = vec![0u8; 60];
                rep[0] = 2;
                rep[1] = 0x81;
                rep[3] = if refuse { 2 } else { 0 };
                rep[24..36].copy_from_slice(&b[24..36]);
                rep[36] = 6;
                rep[40..42].copy_from_slice(&b[40..42]);
                rep[42..44].copy_from_slice(&40_000u16.to_be_bytes());
                rep[54] = 0xff;
                rep[55] = 0xff;
                rep[56..60].copy_from_slice(&[81, 12, 34, 56]);
                let _ = s.send_to(&rep, de);
            }
        });
        addr
    }

    #[test]
    fn pcp_ouvre_le_port() {
        let (ip, port) = pcp_ouvrir(fausse_box_pcp(false), Ipv4Addr::new(192, 168, 1, 20), 6910, 6910, 1200).unwrap();
        assert_eq!(ip, std::net::IpAddr::V4(Ipv4Addr::new(81, 12, 34, 56)));
        assert_eq!(port, 40_000);
    }

    #[test]
    fn pcp_refus_signale() {
        assert!(pcp_ouvrir(fausse_box_pcp(true), Ipv4Addr::new(192, 168, 1, 20), 6910, 6910, 1200).unwrap_err().contains("refus"));
    }

    #[test]
    fn pcp_sans_box_ne_bloque_pas() {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let t = std::time::Instant::now();
        assert!(pcp_ouvrir(s.local_addr().unwrap(), Ipv4Addr::new(192, 168, 1, 20), 6910, 6910, 1200).is_err());
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn aide_box_donne_une_adresse_locale() {
        let a = aide_box(6910);
        assert_eq!(a.port, 6910);
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
