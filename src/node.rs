//! Nœud complet : réseau P2P, synchronisation, minage multi-cœurs et portefeuille.

use crate::addrman::{group, is_local_ip, AddrMan, Group, DHT_SOURCE};
use crate::block::{new_header, Block};
use crate::chain::{Added, Chain, ChainError};
use crate::config::*;
use crate::emission::{block_reward, total_before};
use crate::mempool::Mempool;
use crate::portmap::{self, PortState};
use crate::p2p::{read_message, write_message, Message};
use crate::tx::{Transaction, TxOut};
use crate::wallet::{format_amount, Wallet};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct Options {
    pub data_dir: PathBuf,
    pub port: u16,
    pub peers: Vec<String>,
    pub threads: usize,
    pub mine: bool,
    /// Adresse fixe qui reçoit les récompenses (nœud permanent) ; None = le portefeuille.
    pub reward_to: Option<crate::tx::Address>,
}

struct Peer {
    addr: SocketAddr,
    label: String,
    outbound: bool,
    writer: Arc<Mutex<TcpStream>>,
    /// Hauteur PROUVÉE : celle du meilleur bloc valide que ce pair nous a livré.
    height: u64,
    /// Hauteur ANNONCÉE (Version, Tip) : sert seulement à savoir s'il faut lui demander des blocs.
    claimed: u64,
    /// Dernière fois que ce pair nous a livré un bloc valide (preuve de travail vérifiée).
    last_valid: Option<Instant>,
    sync_from: Option<u64>,
    remote_nonce: u64,
    /// Limite de débit des demandes de blocs (comme Bitcoin : une à la fois, sans excès).
    last_getblocks: Option<Instant>,
    excess_getblocks: u32,
    /// Jetons pour recevoir des adresses (0,1 par seconde, plus 1 000 après notre demande GetAddr).
    addr_tokens: f64,
    addr_refill: Instant,
    /// On ne répond qu'une fois par connexion à GetAddr (comme Bitcoin).
    addr_answered: bool,
    /// Transactions refusées récemment (au-delà de la limite, le pair est déconnecté).
    rejects: u32,
    rejects_since: Instant,
    /// Blocs orphelins reçus depuis `orphans_since` (limités par minute).
    orphans: u32,
    orphans_since: Instant,
}

impl Peer {
    fn new(addr: SocketAddr, label: String, outbound: bool, writer: Arc<Mutex<TcpStream>>) -> Self {
        Peer {
            addr,
            label,
            outbound,
            writer,
            height: 0,
            claimed: 0,
            last_valid: None,
            sync_from: None,
            remote_nonce: 0,
            last_getblocks: None,
            excess_getblocks: 0,
            addr_tokens: 1.0,
            addr_refill: Instant::now(),
            addr_answered: false,
            rejects: 0,
            rejects_since: Instant::now(),
            orphans: 0,
            orphans_since: Instant::now(),
        }
    }

    fn proven_ahead(&self, ours: u64) -> bool {
        proven_ahead(self.claimed.max(self.height), self.last_valid, ours)
    }
}

/// Un pair n'est « en avance » que s'il l'annonce ET qu'il nous a livré récemment un bloc valide
/// (preuve de travail vérifiée). Une annonce seule, même énorme, ne suspend jamais notre minage.
fn proven_ahead(announced: u64, last_valid: Option<Instant>, ours: u64) -> bool {
    announced > ours && last_valid.is_some_and(|t| t.elapsed() < Duration::from_secs(PROVEN_PEER_SECS))
}

/// Au plus 4 connexions entrantes par quartier d'Internet (les adresses locales ne sont pas limitées).
const MAX_INBOUND_PER_GROUP: usize = 4;
/// Au-delà de 100 transactions refusées en 10 minutes, le pair est déconnecté.
const MAX_REJECTS: u32 = 100;
/// Au-delà de 20 blocs orphelins (parent inconnu) en une minute, le pair est déconnecté (sans être exclu).
const MAX_ORPHANS_PER_MIN: u32 = 20;
/// Au-delà de 60 demandes de blocs trop rapprochées, le pair est déconnecté.
const MAX_EXCESS_GETBLOCKS: u32 = 60;

pub struct Node {
    pub chain: Mutex<Chain>,
    pub mempool: Mutex<Mempool>,
    pub wallet: Mutex<Wallet>,
    peers: Mutex<HashMap<u64, Peer>>,
    next_peer: AtomicU64,
    /// Annuaire des pairs (modèle « addrman » de Bitcoin : adresses nouvelles et testées).
    addrman: Mutex<AddrMan>,
    addrman_saved: Mutex<Instant>,
    attempts: Mutex<HashMap<String, Instant>>,
    banned: Mutex<HashMap<IpAddr, Instant>>,
    tip_version: AtomicU64,
    pub hashes: AtomicU64,
    /// Connexions inconnues bloquées sans bruit (robots qui sondent Internet).
    pub blocked_unknown: AtomicU64,
    /// Nombre de cœurs utilisés pour miner (modifiable pendant que le nœud tourne).
    pub threads: AtomicUsize,
    pub hashrate: AtomicU64,
    pub mining: AtomicBool,
    nonce: u64,
    pub opts: Options,
    last_log: Mutex<Instant>,
    started: Instant,
    /// Port annoncé aux autres nœuds (peut différer du port local si la box en a attribué un autre).
    public_port: AtomicU16,
    /// Vrai si la box a accepté d'ouvrir un port (avec une adresse publique) : ce PC peut alors s'annoncer au monde.
    mapped: AtomicBool,
    /// Adresse publique de la box (pour ne pas se compter soi-même dans l'annuaire).
    public_ip: Mutex<Option<IpAddr>>,
    /// État de l'ouverture du port tel que la box le dit (sans la preuve par connexion entrante).
    port_state: Mutex<PortState>,
    /// Vrai dès qu'un nœud, depuis une adresse publique, s'est connecté à nous : preuve que le port est ouvert.
    inbound_public: AtomicBool,
    /// Vrai si l'utilisateur dit avoir ouvert le port à la main.
    manual_port: AtomicBool,
    /// Adresse de la box, de ce PC et port : pour le guide de réglage manuel.
    aide: Mutex<Option<portmap::AideBox>>,
}

/// 8 premiers octets du hash du genesis : seuls les nœuds du même réseau se répondent.
const GENESIS_HASH_PREFIX: [u8; 8] = [0x7e, 0x0e, 0x17, 0xa3, 0xe2, 0x83, 0xa0, 0x29];

/// Socket UDP partagée (plusieurs nœuds peuvent écouter sur la même machine).
fn discovery_socket() -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.set_broadcast(true)?;
    let addr: SocketAddr = ([0, 0, 0, 0], DISCOVERY_PORT).into();
    s.bind(&addr.into())?;
    Ok(s.into())
}

/// Pourquoi l'ouverture a échoué : pas de box, ou box qui refuse.
enum EchecPort {
    PasDeBox,
    Refus,
}

/// Durée de la réservation sur la box. Elle est renouvelée avant la fin ; si NumFranc se ferme
/// ou plante, la box referme donc le port d'elle-même en moins de 20 minutes.
const BAIL_PORT_S: u32 = 1_200;
/// Délai entre deux renouvellements (port ouvert) ou deux nouveaux essais (échec).
const RENOUVELLEMENT_S: u64 = 600;
const REESSAI_S: u64 = 300;

/// Ports essayés, dans l'ordre : le port voulu, puis un port dans chaque quart de la plage
/// (les IPv4 partagées, comme chez Free, n'autorisent qu'une partie des ports).
fn ports_candidats(port: u16, previous: Option<u16>) -> Vec<u16> {
    let mut c: Vec<u16> = previous.into_iter().collect();
    c.extend([port, port.wrapping_add(1), 26_910, 36_910, 56_910, 16_910, 46_910]);
    c.dedup();
    c
}

/// Ouvre le port TCP `port` sur la box via UPnP.
/// Renvoie (adresse publique de la box, port public obtenu).
fn open_port_upnp(port: u16, previous: Option<u16>, direct: Option<Ipv4Addr>) -> Result<(IpAddr, u16), EchecPort> {
    use igd_next::{search_gateway, PortMappingProtocol, SearchOptions};
    let mut opts = SearchOptions::default();
    opts.timeout = Some(Duration::from_secs(5));
    // Seconde chance : certaines box ignorent la diffusion mais répondent si on leur parle directement.
    if let Some(box_ip) = direct {
        opts.broadcast_address = SocketAddr::new(IpAddr::V4(box_ip), 1900);
    }
    let gw = search_gateway(opts).map_err(|_| EchecPort::PasDeBox)?;
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|_| EchecPort::PasDeBox)?;
    probe.connect(gw.addr).map_err(|_| EchecPort::PasDeBox)?;
    let local_ip = probe.local_addr().map_err(|_| EchecPort::PasDeBox)?.ip();
    let local = SocketAddr::new(local_ip, port);
    let mut public_port = None;
    for c in ports_candidats(port, previous) {
        if gw.add_port(PortMappingProtocol::TCP, c, local, BAIL_PORT_S, "NumFranc").is_ok() {
            public_port = Some(c);
            break;
        }
    }
    let public_port = match public_port {
        Some(p) => p,
        None => gw
            .add_any_port(PortMappingProtocol::TCP, local, BAIL_PORT_S, "NumFranc")
            .map_err(|_| EchecPort::Refus)?,
    };
    let ip = gw.get_external_ip().map_err(|_| EchecPort::Refus)?;
    Ok((ip, public_port))
}

/// Même chose en NAT-PMP, quand l'UPnP ne répond pas.
fn open_port_natpmp(port: u16, previous: Option<u16>) -> Result<(IpAddr, u16), EchecPort> {
    let gw = portmap::passerelle_par_defaut().ok_or(EchecPort::PasDeBox)?;
    let addr = SocketAddr::new(IpAddr::V4(gw), portmap::NATPMP_PORT);
    let mut refus = false;
    for c in ports_candidats(port, previous) {
        match portmap::natpmp_ouvrir(addr, port, c, BAIL_PORT_S) {
            Ok((ip, p)) => return Ok((IpAddr::V4(ip), p)),
            // Pas de réponse du tout : inutile d'insister avec d'autres ports.
            Err(e) if e == "pas de réponse" => return Err(if refus { EchecPort::Refus } else { EchecPort::PasDeBox }),
            Err(_) => refus = true,
        }
    }
    Err(EchecPort::Refus)
}

/// Même chose en PCP (RFC 6887), le successeur de NAT-PMP.
fn open_port_pcp(port: u16, previous: Option<u16>) -> Result<(IpAddr, u16), EchecPort> {
    let gw = portmap::passerelle_par_defaut().ok_or(EchecPort::PasDeBox)?;
    let addr = SocketAddr::new(IpAddr::V4(gw), portmap::NATPMP_PORT);
    let local = match portmap::aide_box(port).pc_ip {
        Some(IpAddr::V4(v4)) => v4,
        _ => return Err(EchecPort::PasDeBox),
    };
    let mut refus = false;
    for c in ports_candidats(port, previous) {
        match portmap::pcp_ouvrir(addr, local, port, c, BAIL_PORT_S) {
            Ok(r) => return Ok(r),
            Err(e) if e == "pas de réponse" => return Err(if refus { EchecPort::Refus } else { EchecPort::PasDeBox }),
            Err(_) => refus = true,
        }
    }
    Err(EchecPort::Refus)
}

fn log(msg: &str) {
    crate::events::log(msg);
}

impl Node {
    /// Démarre le nœud avec un portefeuille déjà ouvert (voir wallet.rs).
    pub fn start(opts: Options, wallet: Wallet) -> Result<Arc<Self>, String> {
        std::fs::create_dir_all(&opts.data_dir).map_err(|e| format!("dossier de données : {e}"))?;
        crate::install::single_instance(&opts.data_dir)?;
        log(crate::i18n::t("Chargement de la chaîne...", "Loading the chain..."));
        let chain = Chain::open(&opts.data_dir.join("blocks.dat")).map_err(|e| e.to_string())?;
        let mut nonce_bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut nonce_bytes);
        let addrman = AddrMan::from_text(&std::fs::read_to_string(opts.data_dir.join("peers.txt")).unwrap_or_default());
        let node = Arc::new(Node {
            chain: Mutex::new(chain),
            mempool: Mutex::new(Mempool::default()),
            wallet: Mutex::new(wallet),
            peers: Mutex::new(HashMap::new()),
            next_peer: AtomicU64::new(1),
            addrman: Mutex::new(addrman),
            addrman_saved: Mutex::new(Instant::now()),
            attempts: Mutex::new(HashMap::new()),
            banned: Mutex::new(HashMap::new()),
            tip_version: AtomicU64::new(0),
            hashes: AtomicU64::new(0),
            hashrate: AtomicU64::new(0),
            mining: AtomicBool::new(opts.mine),
            threads: AtomicUsize::new(opts.threads.max(1)),
            blocked_unknown: AtomicU64::new(0),
            nonce: u64::from_be_bytes(nonce_bytes),
            opts: opts.clone(),
            last_log: Mutex::new(Instant::now() - Duration::from_secs(60)),
            started: Instant::now(),
            public_port: AtomicU16::new(opts.port),
            mapped: AtomicBool::new(false),
            public_ip: Mutex::new(None),
            port_state: Mutex::new(PortState::Searching),
            inbound_public: AtomicBool::new(false),
            manual_port: AtomicBool::new(false),
            aide: Mutex::new(None),
        });

        let listener = TcpListener::bind(("0.0.0.0", opts.port))
            .map_err(|e| format!("impossible d'écouter sur le port {} : {e}", opts.port))?;
        let n = node.clone();
        std::thread::spawn(move || n.accept_loop(listener));
        let n = node.clone();
        std::thread::spawn(move || n.connect_loop());
        let n = node.clone();
        std::thread::spawn(move || n.miner_loop());
        let n = node.clone();
        std::thread::spawn(move || n.hashrate_loop());
        let n = node.clone();
        std::thread::spawn(move || n.upnp_loop());
        let n = node.clone();
        std::thread::spawn(move || n.dht_loop());
        match discovery_socket() {
            Ok(sock) => {
                let sock = Arc::new(sock);
                let (n, s2) = (node.clone(), sock.clone());
                std::thread::spawn(move || n.discovery_listen(s2));
                let n = node.clone();
                std::thread::spawn(move || n.discovery_announce(sock));
            }
            Err(e) => log(&crate::tf!("[!] Découverte automatique indisponible : {e}", "[!] Automatic discovery unavailable: {e}")),
        }
        Ok(node)
    }

    // ---------- Réseau ----------

    fn is_banned(&self, ip: &IpAddr) -> bool {
        let mut b = self.banned.lock().unwrap();
        b.retain(|_, until| *until > Instant::now());
        b.contains_key(ip)
    }

    fn ban(&self, id: u64, reason: &str) {
        let peer = self.peers.lock().unwrap().remove(&id);
        if let Some(p) = peer {
            if p.remote_nonce != 0 {
                // Un vrai nœud NumFranc qui se comporte mal : on le signale.
                log(&crate::tf!("[!] Pair {} exclu 24 h : {reason}", "[!] Peer {} banned for 24 h: {reason}", p.addr));
            } else {
                // Connexion inconnue (robots qui sondent Internet) : bloquée sans bruit.
                self.blocked_unknown.fetch_add(1, Ordering::Relaxed);
            }
            self.banned.lock().unwrap().insert(p.addr.ip(), Instant::now() + Duration::from_secs(86_400));
            let _ = p.writer.lock().unwrap().shutdown(std::net::Shutdown::Both);
        }
    }

    /// Coupe la connexion avec un pair (sans l'exclure 24 h).
    fn disconnect(&self, id: u64, reason: &str) {
        if let Some(p) = self.peers.lock().unwrap().remove(&id) {
            log(&crate::tf!("[i] Pair {} déconnecté : {reason}", "[i] Peer {} disconnected: {reason}", p.addr));
            let _ = p.writer.lock().unwrap().shutdown(std::net::Shutdown::Both);
        }
    }

    /// Enregistre l'annuaire dans peers.txt (au plus une fois par minute, ou tout de suite si `now`).
    fn save_addrman(&self, now: bool) {
        let mut last = self.addrman_saved.lock().unwrap();
        if now || last.elapsed() > Duration::from_secs(60) {
            *last = Instant::now();
            let text = self.addrman.lock().unwrap().to_text();
            let _ = std::fs::write(self.opts.data_dir.join("peers.txt"), text);
        }
    }

    fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming().flatten() {
            let Ok(addr) = stream.peer_addr() else { continue };
            let (inbound, same_group) = {
                let peers = self.peers.lock().unwrap();
                let g = group(&addr.ip());
                (
                    peers.values().filter(|p| !p.outbound).count(),
                    peers.values().filter(|p| !p.outbound && group(&p.addr.ip()) == g).count(),
                )
            };
            // Comme Bitcoin : pas toutes les places entrantes pour un même quartier d'Internet.
            let crowded = !is_local_ip(&addr.ip()) && same_group >= MAX_INBOUND_PER_GROUP;
            if inbound >= MAX_INBOUND || crowded || self.is_banned(&addr.ip()) {
                continue;
            }
            let n = self.clone();
            std::thread::spawn(move || n.handle(stream, addr.to_string(), false));
        }
    }

    fn connect_loop(self: Arc<Self>) {
        loop {
            let (outbound, connected, groups): (usize, HashSet<String>, HashSet<Group>) = {
                let p = self.peers.lock().unwrap();
                (
                    p.values().filter(|p| p.outbound).count(),
                    p.values().map(|p| p.label.clone()).collect(),
                    // Comme Bitcoin : au plus une connexion sortante par quartier d'Internet.
                    p.values().filter(|p| p.outbound && !is_local_ip(&p.addr.ip())).map(|p| group(&p.addr.ip())).collect(),
                )
            };
            if outbound < MAX_OUTBOUND {
                // Pairs choisis à la main (noeuds.txt, --pair) et nœuds d'amorçage : toujours essayés.
                let mut candidates: Vec<String> = self.opts.peers.clone();
                candidates.extend(DEFAULT_SEEDS.iter().map(|s| s.to_string()));
                // Puis des adresses de l'annuaire, chacune dans un quartier différent.
                {
                    let mut am = self.addrman.lock().unwrap();
                    let mut exclude = groups.clone();
                    for _ in outbound..MAX_OUTBOUND {
                        let Some(a) = am.select(&exclude) else { break };
                        exclude.insert(group(&a.ip()));
                        am.attempt(&a);
                        candidates.push(a.to_string());
                    }
                }
                for c in candidates {
                    if connected.contains(&c) || connected.iter().any(|l| l.starts_with(&format!("{c}:"))) {
                        continue;
                    }
                    {
                        let mut a = self.attempts.lock().unwrap();
                        if a.get(&c).is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                            continue;
                        }
                        a.insert(c.clone(), Instant::now());
                    }
                    let n = self.clone();
                    std::thread::spawn(move || n.connect_to(c));
                }
            }
            self.save_addrman(false);
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    pub fn connect_to(self: Arc<Self>, target: String) {
        // Nœud d'amorçage écrit sans port (ex. « numfranc.duckdns.org ») : on essaie les ports habituels.
        if !target.contains(':') {
            let Some(ip) = (target.as_str(), 0).to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| a.ip()) else { return };
            // C'est notre propre adresse publique (on est chez le nœud d'amorçage) : inutile de se joindre soi-même.
            if self.is_reachable() && *self.public_ip.lock().unwrap() == Some(ip) {
                return;
            }
            for port in SEED_PORTS {
                let addr = SocketAddr::new(ip, port);
                if self.is_banned(&ip) {
                    return;
                }
                if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(4)) {
                    self.handle(stream, format!("{target}:{port}"), true);
                    return;
                }
            }
            return;
        }
        let Some(addr) = target.to_socket_addrs().ok().and_then(|mut a| a.next()) else { return };
        if self.is_banned(&addr.ip()) {
            return;
        }
        if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            self.handle(stream, target, true);
        }
    }

    fn handle(self: Arc<Self>, stream: TcpStream, label: String, outbound: bool) {
        let Ok(addr) = stream.peer_addr() else { return };
        let _ = stream.set_nodelay(true);
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
        let Ok(writer) = stream.try_clone() else { return };
        let id = self.next_peer.fetch_add(1, Ordering::SeqCst);
        let writer = Arc::new(Mutex::new(writer));
        self.peers.lock().unwrap().insert(id, Peer::new(addr, label, outbound, writer));
        let height = self.chain.lock().unwrap().height();
        let listen_port = self.public_port.load(Ordering::SeqCst);
        self.send(id, &Message::Version { version: PROTOCOL_VERSION, height, listen_port, nonce: self.nonce });

        let mut reader = std::io::BufReader::new(stream);
        loop {
            match read_message(&mut reader) {
                Ok(Ok(msg)) => {
                    if !self.peers.lock().unwrap().contains_key(&id) {
                        break;
                    }
                    self.process(id, msg);
                }
                Ok(Err(e)) => {
                    self.ban(id, &format!("message invalide : {e}"));
                    break;
                }
                Err(_) => break,
            }
        }
        self.peers.lock().unwrap().remove(&id);
    }

    fn send(&self, id: u64, msg: &Message) {
        let w = self.peers.lock().unwrap().get(&id).map(|p| p.writer.clone());
        if let Some(w) = w {
            let _ = write_message(&mut *w.lock().unwrap(), msg);
        }
    }

    fn broadcast(&self, msg: &Message, except: Option<u64>) {
        let writers: Vec<_> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| Some(**id) != except)
            .map(|(_, p)| p.writer.clone())
            .collect();
        // Un fil par pair : un pair lent (réseau saturé, connexion à moitié morte) ne retarde plus les autres.
        // L'envoi à un pair garde de toute façon sa limite de 30 s (set_write_timeout).
        if writers.len() <= 1 {
            for w in writers {
                let _ = write_message(&mut *w.lock().unwrap(), msg);
            }
            return;
        }
        let msg = Arc::new(msg.clone());
        for w in writers {
            let msg = msg.clone();
            let _ = std::thread::Builder::new().name("diffusion".into()).spawn(move || {
                let _ = write_message(&mut *w.lock().unwrap(), &msg);
            });
        }
    }

    fn request_blocks(&self, id: u64) {
        let (loc, h) = {
            let c = self.chain.lock().unwrap();
            (c.locator(), c.height())
        };
        if let Some(p) = self.peers.lock().unwrap().get_mut(&id) {
            p.sync_from = Some(h);
        }
        self.send(id, &Message::GetBlocks(loc));
    }

    fn process(&self, id: u64, msg: Message) {
        match msg {
            Message::Version { version, height, listen_port, nonce } => {
                if nonce == self.nonce || version != PROTOCOL_VERSION {
                    if let Some(p) = self.peers.lock().unwrap().remove(&id) {
                        let _ = p.writer.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        if nonce == self.nonce && p.outbound {
                            // Connexion à nous-mêmes : on oublie cette adresse.
                            if let Ok(a) = p.label.parse::<SocketAddr>() {
                                self.addrman.lock().unwrap().remove(&a);
                            }
                        }
                    }
                    return;
                }
                // Même nœud déjà connecté par un autre chemin : on garde une seule connexion.
                // On exige la même adresse IP : sinon un pirate pourrait recopier le numéro
                // d'un nœud honnête pour le faire rejeter.
                {
                    let mut peers = self.peers.lock().unwrap();
                    let ip = peers.get(&id).map(|p| p.addr.ip());
                    // Exception : si les deux adresses sont « chez nous » (réseau local, ou notre propre adresse
                    // publique vue à travers la box), un pirate d'Internet ne peut pas les imiter : on fusionne.
                    let chez_nous = |a: &IpAddr| self.chez_nous(a);
                    if peers.iter().any(|(pid, p)| {
                        *pid != id && p.remote_nonce == nonce && (Some(p.addr.ip()) == ip || (chez_nous(&p.addr.ip()) && ip.as_ref().is_some_and(chez_nous)))
                    }) {
                        if let Some(p) = peers.remove(&id) {
                            let _ = p.writer.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        }
                        return;
                    }
                    if let Some(p) = peers.get_mut(&id) {
                        p.remote_nonce = nonce;
                    }
                }
                if let Some(p) = self.peers.lock().unwrap().get_mut(&id) {
                    p.claimed = height;
                    // Notre demande GetAddr ci-dessous autorise une réponse de 1 000 adresses.
                    p.addr_tokens += 1_000.0;
                    if p.outbound {
                        // Connexion sortante réussie : l'adresse passe dans les « testées ».
                        self.addrman.lock().unwrap().good(p.addr);
                    } else if listen_port != 0 {
                        // Un vrai nœud NumFranc, venu d'une adresse publique, a réussi à nous joindre :
                        // preuve que notre port est ouvert.
                        if !self.chez_nous(&p.addr.ip()) && !self.inbound_public.swap(true, Ordering::SeqCst) {
                            log(&crate::tf!(
                                "[ ] Un autre nœud s'est connecté à toi depuis Internet : ton port est bien ouvert.",
                                "[ ] Another node connected to you from the Internet: your port is open."
                            ));
                        }
                        let a = SocketAddr::new(p.addr.ip(), listen_port);
                        p.label = a.to_string();
                        self.addrman.lock().unwrap().add(a, group(&p.addr.ip()));
                    }
                }
                self.send(id, &Message::Verack);
                self.send(id, &Message::GetAddr);
                if height > self.chain.lock().unwrap().height() {
                    self.request_blocks(id);
                }
            }
            Message::Verack | Message::Pong(_) => {}
            Message::Ping(n) => self.send(id, &Message::Pong(n)),
            Message::GetAddr => {
                // Une seule réponse par connexion, avec un échantillon au hasard (comme Bitcoin).
                let first = self.peers.lock().unwrap().get_mut(&id).is_some_and(|p| !std::mem::replace(&mut p.addr_answered, true));
                if first {
                    let list: Vec<String> = self.addrman.lock().unwrap().sample(250).iter().map(|a| a.to_string()).collect();
                    self.send(id, &Message::Addr(list));
                }
            }
            Message::Addr(list) => {
                // Débit limité : 0,1 adresse par seconde, plus la réponse à notre propre demande.
                let (source, mut allowed) = {
                    let mut peers = self.peers.lock().unwrap();
                    let Some(p) = peers.get_mut(&id) else { return };
                    p.addr_tokens = (p.addr_tokens + p.addr_refill.elapsed().as_secs_f64() * 0.1).min(1_000.0 + 1.0);
                    p.addr_refill = Instant::now();
                    let allowed = (p.addr_tokens.floor() as usize).min(list.len());
                    p.addr_tokens -= allowed as f64;
                    (group(&p.addr.ip()), allowed)
                };
                let mut am = self.addrman.lock().unwrap();
                for a in list {
                    if allowed == 0 {
                        break;
                    }
                    allowed -= 1;
                    if let Ok(addr) = a.parse::<SocketAddr>() {
                        am.add(addr, source);
                    }
                }
            }
            Message::GetBlocks(loc) => {
                // Comme Bitcoin : pas de rafale de demandes ; les blocs sont lus et envoyés un par un,
                // jusqu'à MAX_BLOCKS_PER_REPLY blocs ou MAX_BYTES_PER_REPLY octets.
                let (accepted, excess) = {
                    let mut peers = self.peers.lock().unwrap();
                    let Some(p) = peers.get_mut(&id) else { return };
                    if p.last_getblocks.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                        p.excess_getblocks += 1;
                        (false, p.excess_getblocks)
                    } else {
                        p.last_getblocks = Some(Instant::now());
                        (true, p.excess_getblocks)
                    }
                };
                if excess > MAX_EXCESS_GETBLOCKS {
                    self.disconnect(id, "trop de demandes de blocs");
                    return;
                }
                if !accepted {
                    return;
                }
                let (hashes, h) = {
                    let c = self.chain.lock().unwrap();
                    (c.hashes_after(&loc, MAX_BLOCKS_PER_REPLY), c.height())
                };
                let mut sent = 0usize;
                for hash in hashes {
                    let Some(b) = self.chain.lock().unwrap().get_block(&hash) else { break };
                    sent += b.serialize().len();
                    self.send(id, &Message::Block(b));
                    if sent >= MAX_BYTES_PER_REPLY {
                        break;
                    }
                }
                self.send(id, &Message::Tip(h));
            }
            Message::Tip(h) => {
                let (ours, last) = {
                    let ours = self.chain.lock().unwrap().height();
                    let mut p = self.peers.lock().unwrap();
                    let last = p.get_mut(&id).map(|p| {
                        p.claimed = h;
                        p.sync_from.take()
                    });
                    (ours, last.flatten())
                };
                // On redemande la suite seulement si le lot précédent nous a fait avancer.
                if h > ours && last != Some(ours) {
                    self.request_blocks(id);
                }
            }
            Message::Block(b) => self.on_block(b, Some(id)),
            Message::Tx(tx) => self.on_tx(id, tx),
        }
    }

    /// Transaction reçue d'un pair. Comme Bitcoin : vérifications de la moins chère à la plus chère,
    /// signatures en dernier et hors des verrous ; une signature fausse vaut exclusion.
    fn on_tx(&self, id: u64, tx: Transaction) {
        if tx.size() > MAX_RELAY_TX_SIZE {
            self.reject_tx(id, "transaction trop grande pour être relayée");
            return;
        }
        let pre = {
            let c = self.chain.lock().unwrap();
            let mp = self.mempool.lock().unwrap();
            if mp.contains(&tx.txid()) {
                return; // déjà reçue d'un autre pair : normal
            }
            mp.precheck(&tx, &c)
        };
        if let Err(e) = pre {
            self.reject_tx(id, &e);
            return;
        }
        if let Err(e) = tx.check_stateless() {
            self.ban(id, &format!("transaction avec signature invalide : {}", e.0));
            return;
        }
        let res = {
            let c = self.chain.lock().unwrap();
            self.mempool.lock().unwrap().accept_verified(tx.clone(), &c)
        };
        if res.is_ok() {
            self.tip_version.fetch_add(1, Ordering::SeqCst);
            self.broadcast(&Message::Tx(tx), Some(id));
        }
    }

    /// Transaction refusée sans preuve de mauvaise foi (pièce déjà dépensée, course entre nœuds…) :
    /// on compte ; au-delà de MAX_REJECTS en 10 minutes, le pair est déconnecté.
    fn reject_tx(&self, id: u64, _why: &str) {
        let too_many = {
            let mut peers = self.peers.lock().unwrap();
            let Some(p) = peers.get_mut(&id) else { return };
            if p.rejects_since.elapsed() > Duration::from_secs(600) {
                p.rejects = 0;
                p.rejects_since = Instant::now();
            }
            p.rejects += 1;
            p.rejects > MAX_REJECTS
        };
        if too_many {
            self.disconnect(id, "trop de transactions refusées");
        }
    }

    /// Traite un bloc reçu d'un pair (`from`) ou miné localement (`None`).
    /// Annonce les paiements reçus dans un nouveau bloc (hors récompenses de minage et monnaie rendue).
    fn notify_received(&self, block: &Block) {
        let w = self.wallet.lock().unwrap();
        for tx in block.txs.iter().filter(|t| !t.is_coinbase()) {
            if tx.inputs.iter().any(|i| w.is_mine(&crate::tx::address_of_pubkey(&i.pubkey))) {
                continue;
            }
            let amount: u64 = tx.outputs.iter().filter(|o| w.is_mine(&o.address)).map(|o| o.amount).sum();
            if amount > 0 {
                let memo = tx.memo_text();
                let memo = if memo.is_empty() { String::new() } else { crate::tf!(" — message : « {memo} »", " — message: “{memo}”") };
                log(&crate::tf!("[€] Paiement reçu : {}{memo}", "[€] Payment received: {}{memo}", format_amount(amount)));
            }
        }
    }

    pub fn on_block(&self, block: Block, from: Option<u64>) {
        // Hauteur lue dans la coinbase : elle n'est crue qu'APRÈS validation du bloc (voir plus bas).
        let height_hint = block.txs.first().and_then(|t| t.coinbase_height()).unwrap_or(0);
        let reward_to_me = from.is_none();
        let res = {
            let mut c = self.chain.lock().unwrap();
            let r = c.add_block(block.clone(), now());
            if matches!(r, Ok(Added::Extended) | Ok(Added::Reorganized { .. })) {
                self.mempool.lock().unwrap().revalidate(&c);
            }
            r
        };
        // Bloc valide (preuve de travail vérifiée) : le pair a prouvé sa hauteur.
        if let (Some(id), Ok(_)) = (from, &res) {
            if let Some(p) = self.peers.lock().unwrap().get_mut(&id) {
                p.height = p.height.max(height_hint);
                p.last_valid = Some(Instant::now());
            }
        }
        match res {
            Ok(Added::Extended) | Ok(Added::Reorganized { .. }) => {
                self.tip_version.fetch_add(1, Ordering::SeqCst);
                if let Ok(Added::Reorganized { depth }) = res {
                    log(&crate::tf!("[~] Réorganisation de {depth} bloc(s)", "[~] Reorganization of {depth} block(s)"));
                }
                if block.header.timestamp + 3_600 > now() {
                    self.notify_received(&block);
                }
                if reward_to_me {
                    self.wallet.lock().unwrap().rotate_mining_address();
                    let amount = block.txs[0].output_sum().unwrap_or(0);
                    log(&crate::tf!("[+] Bloc #{height_hint} trouvé ! Récompense : {}", "[+] Block #{height_hint} found! Reward: {}", format_amount(amount)));
                } else {
                    let mut last = self.last_log.lock().unwrap();
                    if last.elapsed() > Duration::from_secs(5) {
                        *last = Instant::now();
                        log(&crate::tf!("[ ] Chaîne à jour : bloc #{height_hint}", "[ ] Chain up to date: block #{height_hint}"));
                    }
                }
                if block.header.timestamp + 3_600 > now() {
                    self.broadcast(&Message::Block(block), from);
                }
            }
            Ok(Added::SideChain) | Err(ChainError::AlreadyKnown) => {}
            Err(ChainError::Orphan) => {
                if let Some(id) = from {
                    // Au plus MAX_ORPHANS_PER_MIN blocs orphelins par minute et par pair : au-delà, on coupe
                    // (sinon un pair pourrait nous faire redemander la chaîne en boucle).
                    let abusif = {
                        let mut peers = self.peers.lock().unwrap();
                        match peers.get_mut(&id) {
                            Some(p) => {
                                if p.orphans_since.elapsed() > Duration::from_secs(60) {
                                    p.orphans = 0;
                                    p.orphans_since = Instant::now();
                                }
                                p.orphans += 1;
                                p.orphans > MAX_ORPHANS_PER_MIN
                            }
                            None => false,
                        }
                    };
                    if abusif {
                        self.disconnect(id, "trop de blocs orphelins");
                    } else {
                        self.request_blocks(id);
                    }
                }
            }
            Err(ChainError::ReorgTooDeep { depth }) => {
                log(&crate::tf!(
                    "[!] Chaîne concurrente REFUSÉE : elle réécrirait {depth} blocs (max {MAX_REORG_DEPTH}). Attaque possible.",
                    "[!] Competing chain REJECTED: it would rewrite {depth} blocks (max {MAX_REORG_DEPTH}). Possible attack."
                ));
            }
            Err(ChainError::FutureTime) => {
                // Pas de punition : l'horloge de l'un des deux ordinateurs est peut-être décalée.
                let mut last = self.last_log.lock().unwrap();
                if last.elapsed() > Duration::from_secs(60) {
                    *last = Instant::now();
                    log(&crate::tf!(
                        "[i] Bloc daté de plus de 2 h dans le futur ignoré : vérifie l'heure de ton ordinateur (réglage automatique conseillé).",
                        "[i] Block dated more than 2 h in the future ignored: check your computer's clock (automatic time setting recommended)."
                    ));
                }
            }
            Err(ChainError::KnownBad(e)) => {
                if let Some(id) = from {
                    // Le pair ne sait peut-être pas encore que ce bloc est faux : on coupe, sans l'exclure 24 h.
                    self.disconnect(id, &e);
                }
            }
            Err(ChainError::Invalid(e)) => match from {
                Some(id) => self.ban(id, &format!("bloc invalide : {e}")),
                None => log(&crate::tf!("[!] Bloc miné refusé : {e}", "[!] Mined block rejected: {e}")),
            },
        }
    }

    /// Ouvre le coffre avec le code de dépense SANS tenir aucun verrou (l'Argon2 dure plusieurs secondes :
    /// pendant ce temps, la chaîne, le minage et la fenêtre continuent de fonctionner). L'opération qui suit
    /// reprend la graine déjà ouverte ; l'appelant doit ensuite appeler `clear_spend`.
    pub fn prepare_spend(&self, code: &str) -> Result<(), String> {
        let snap = self.wallet.lock().unwrap().spend_snapshot();
        let seed = snap.open(code)?;
        self.wallet.lock().unwrap().set_pre_seed(seed);
        Ok(())
    }

    pub fn clear_spend(&self) {
        self.wallet.lock().unwrap().clear_pre_seed();
    }

    /// Change les mots de passe : le long calcul Argon2 se fait hors verrou, seule l'écriture du fichier est verrouillée.
    pub fn change_passwords(&self, old_spend: &str, new_open: &str, new_spend: &str) -> Result<(), String> {
        let snap = self.wallet.lock().unwrap().spend_snapshot();
        let plan = snap.prepare_change(old_spend, new_open, new_spend)?;
        self.wallet.lock().unwrap().apply_change(plan)
    }

    /// Les 3 morceaux de secours, sans verrou pendant l'Argon2.
    pub fn recovery_shares(&self, code: &str) -> Result<[String; 3], String> {
        let snap = self.wallet.lock().unwrap().spend_snapshot();
        let seed = snap.open(code)?;
        crate::vault::split_seed(&*seed)
    }

    pub fn submit_tx(&self, tx: Transaction) -> Result<(), String> {
        {
            let c = self.chain.lock().unwrap();
            self.mempool.lock().unwrap().accept(tx.clone(), &c)?;
        }
        self.wallet.lock().unwrap().mark_spent(&tx);
        self.tip_version.fetch_add(1, Ordering::SeqCst);
        self.broadcast(&Message::Tx(tx), None);
        Ok(())
    }

    pub fn data_dir(&self) -> PathBuf {
        self.opts.data_dir.clone()
    }

    pub fn peer_list(&self) -> Vec<(String, bool, u64)> {
        self.peers.lock().unwrap().values().map(|p| (p.addr.to_string(), p.outbound, p.height)).collect()
    }

    // ---------- Minage ----------

    fn build_template(&self) -> Block {
        let to = match self.opts.reward_to {
            Some(a) => a,
            None => self.wallet.lock().unwrap().mining_address(),
        };
        let c = self.chain.lock().unwrap();
        let tip = c.tip();
        let height = c.height() + 1;
        let (txs, fees) = self.mempool.lock().unwrap().select(MAX_BLOCK_SIZE - 64 * 1024);
        let reward = block_reward(height, total_before(height)) + fees;
        let mut extra = [0u8; 8];
        let _ = getrandom::getrandom(&mut extra);
        let outputs = if reward > 0 { vec![TxOut::new(reward, to)] } else { vec![] };
        let mut all = vec![Transaction::coinbase(height, &extra, outputs)];
        all.extend(txs);
        let ts = now().max(c.median_time_past(&tip) + 1);
        let mut b = Block { header: new_header(tip, [0; 64], ts, c.expected_target(&tip, height)), txs: all };
        b.header.merkle_root = b.compute_merkle_root();
        b
    }

    fn miner_loop(self: Arc<Self>) {
        loop {
            let threads = self.threads.load(Ordering::SeqCst).max(1) as u64;
            if !self.mining.load(Ordering::SeqCst) || !self.ready_to_mine() {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            let version = self.tip_version.load(Ordering::SeqCst);
            let template = self.build_template();
            let found = AtomicBool::new(false);
            let result = Mutex::new(None);
            let started = Instant::now();
            std::thread::scope(|s| {
                for t in 0..threads {
                    let (found, result, template, me) = (&found, &result, &template, &self);
                    s.spawn(move || {
                        let mut h = template.header.clone();
                        let mut nonce = t;
                        loop {
                            for i in 0..8 {
                                h.nonce = nonce;
                                if h.meets_target() {
                                    me.hashes.fetch_add(i + 1, Ordering::Relaxed);
                                    found.store(true, Ordering::SeqCst);
                                    *result.lock().unwrap() = Some(nonce);
                                    return;
                                }
                                nonce = nonce.wrapping_add(threads);
                            }
                            me.hashes.fetch_add(8, Ordering::Relaxed);
                            if found.load(Ordering::SeqCst)
                                || me.tip_version.load(Ordering::SeqCst) != version
                                || !me.mining.load(Ordering::SeqCst)
                                || started.elapsed() > Duration::from_secs(30)
                            {
                                return;
                            }
                        }
                    });
                }
            });
            if let Some(nonce) = result.into_inner().unwrap() {
                let mut b = template;
                b.header.nonce = nonce;
                self.on_block(b, None);
            }
        }
    }

    /// Le minage ne démarre qu'après la recherche initiale de pairs, et s'arrête pendant
    /// qu'on rattrape un pair en avance. Comme Bitcoin, on ne croit pas une simple annonce :
    /// le pair doit nous avoir livré récemment un bloc valide (preuve de travail vérifiée).
    pub fn ready_to_mine(&self) -> bool {
        if self.started.elapsed() < Duration::from_secs(STARTUP_SYNC_SECS) {
            return false;
        }
        !self.is_syncing()
    }

    pub fn is_syncing(&self) -> bool {
        let ours = self.chain.lock().unwrap().height();
        self.peers.lock().unwrap().values().any(|p| p.proven_ahead(ours))
    }

    // ---------- Découverte automatique (réseau local) ----------

    fn discovery_packet(&self) -> Vec<u8> {
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(b"NFRHELLO");
        p.extend_from_slice(&GENESIS_HASH_PREFIX);
        p.extend_from_slice(&self.opts.port.to_be_bytes());
        p.extend_from_slice(&self.nonce.to_be_bytes());
        p
    }

    fn discovery_announce(self: Arc<Self>, sock: Arc<std::net::UdpSocket>) {
        let packet = self.discovery_packet();
        loop {
            let _ = sock.send_to(&packet, ("255.255.255.255", DISCOVERY_PORT));
            let _ = sock.send_to(&packet, ("127.0.0.1", DISCOVERY_PORT));
            std::thread::sleep(Duration::from_secs(DISCOVERY_INTERVAL_SECS));
        }
    }

    fn discovery_listen(self: Arc<Self>, sock: Arc<std::net::UdpSocket>) {
        let mut buf = [0u8; 64];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf) else { continue };
            let p = &buf[..n];
            if n != 4 + 8 + 8 + 2 + 8 || p[0..4] != MAGIC || &p[4..12] != b"NFRHELLO" || p[12..20] != GENESIS_HASH_PREFIX {
                continue;
            }
            let port = u16::from_be_bytes([p[20], p[21]]);
            let nonce = u64::from_be_bytes(p[22..30].try_into().unwrap());
            if nonce == self.nonce || self.is_banned(&src.ip()) {
                continue;
            }
            let target = SocketAddr::new(src.ip(), port).to_string();
            let already = self.peers.lock().unwrap().values().any(|p| p.label == target || p.addr.ip() == src.ip());
            if !already {
                let recent = {
                    let mut a = self.attempts.lock().unwrap();
                    let r = a.get(&target).is_some_and(|t| t.elapsed() < Duration::from_secs(30));
                    if !r {
                        a.insert(target.clone(), Instant::now());
                    }
                    r
                };
                if !recent {
                    log(&crate::tf!("[ ] Nœud trouvé sur le réseau local : {target}", "[ ] Node found on the local network: {target}"));
                    let n = self.clone();
                    std::thread::spawn(move || n.connect_to(target));
                }
            }
        }
    }

    // ---------- Ouverture automatique du port sur la box (UPnP) ----------

    /// Demande à la box d'ouvrir le port réseau vers ce PC (UPnP, puis NAT-PMP), renouvelle la
    /// demande toutes les 10 minutes, et réessaie toutes les 5 minutes tant que ça échoue
    /// (box rallumée, UPnP activé entre-temps...). Chaque mineur devient ainsi joignable depuis
    /// Internet, sans réglage et sans PC central.
    fn upnp_loop(self: Arc<Self>) {
        let mut external: Option<u16> = None;
        loop {
            let box_ip = portmap::passerelle_par_defaut();
            let essai = open_port_upnp(self.opts.port, external, None)
                .or_else(|e| match (e, box_ip) {
                    (EchecPort::PasDeBox, Some(b)) => open_port_upnp(self.opts.port, external, Some(b)),
                    (e, _) => Err(e),
                })
                .map(|(ip, p)| (ip, p, "UPnP"))
                .or_else(|e1| {
                    // Si l'UPnP a répondu par un refus, c'est lui qui explique l'échec.
                    let refus1 = matches!(e1, EchecPort::Refus);
                    open_port_natpmp(self.opts.port, external)
                        .map(|(ip, p)| (ip, p, "NAT-PMP"))
                        .or_else(|_| open_port_pcp(self.opts.port, external).map(|(ip, p)| (ip, p, "PCP")))
                        .map_err(|e2| if refus1 { EchecPort::Refus } else { e2 })
                });
            let nouvel_etat = match essai {
                Ok((ext, port, via)) => {
                    external = Some(port);
                    self.public_port.store(port, Ordering::SeqCst);
                    *self.public_ip.lock().unwrap() = Some(ext);
                    let publique = match ext {
                        IpAddr::V4(v4) => portmap::est_publique(v4),
                        IpAddr::V6(_) => true,
                    };
                    self.mapped.store(publique, Ordering::SeqCst);
                    if publique { PortState::Open { port, via } } else { PortState::Shared { port } }
                }
                Err(EchecPort::PasDeBox) => {
                    self.mapped.store(false, Ordering::SeqCst);
                    PortState::NoRouter
                }
                Err(EchecPort::Refus) => {
                    self.mapped.store(false, Ordering::SeqCst);
                    PortState::Refused
                }
            };
            if nouvel_etat.guide_utile() {
                *self.aide.lock().unwrap() = Some(portmap::aide_box(self.opts.port));
            }
            let change = {
                let mut e = self.port_state.lock().unwrap();
                let c = *e != nouvel_etat;
                *e = nouvel_etat.clone();
                c
            };
            if change {
                let ligne = if nouvel_etat.joignable() { "[ ] " } else { "[i] " };
                log(&format!("{ligne}{}", nouvel_etat.titre()));
            }
            let pause = if nouvel_etat.niveau() == 1 { RENOUVELLEMENT_S } else { REESSAI_S };
            std::thread::sleep(Duration::from_secs(pause));
        }
    }

    /// Adresse « chez nous » : réseau local, ou notre propre adresse publique (connexion qui a fait
    /// le tour par la box). Une telle connexion ne prouve pas que le port est ouvert vers Internet.
    fn chez_nous(&self, ip: &IpAddr) -> bool {
        is_local_ip(ip) || *self.public_ip.lock().unwrap() == Some(*ip)
    }

    /// Peut-on être joint depuis Internet ? (box qui a ouvert le port, port ouvert à la main, ou preuve par connexion entrante.)
    fn is_reachable(&self) -> bool {
        self.mapped.load(Ordering::SeqCst) || self.manual_port.load(Ordering::SeqCst) || self.inbound_public.load(Ordering::SeqCst)
    }

    /// L'utilisateur dit avoir ouvert le port lui-même sur sa box (ou le retire).
    pub fn set_manual_port(&self, on: bool) {
        self.manual_port.store(on, Ordering::SeqCst);
    }

    /// Adresse de la box, de ce PC et port, pour le guide de réglage manuel (None tant que non calculée).
    pub fn aide_box(&self) -> Option<portmap::AideBox> {
        self.aide.lock().unwrap().clone()
    }

    /// État de l'ouverture du port (pour l'accueil et les Réglages).
    pub fn port_state(&self) -> PortState {
        let base = self.port_state.lock().unwrap().clone();
        let prouve = self.inbound_public.load(Ordering::SeqCst);
        let port = self.public_port.load(Ordering::SeqCst);
        match base {
            PortState::Open { port, .. } | PortState::Shared { port } if prouve => PortState::Confirmed { port },
            PortState::NoRouter | PortState::Refused if prouve => PortState::Confirmed { port },
            PortState::NoRouter | PortState::Refused if self.manual_port.load(Ordering::SeqCst) => PortState::ManualWaiting { port },
            b => b,
        }
    }

    // ---------- Découverte mondiale sans serveur (DHT BitTorrent) ----------

    /// Les nœuds NumFranc se retrouvent dans l'annuaire public et décentralisé de
    /// BitTorrent (des millions d'ordinateurs), sous un identifiant propre à NumFranc.
    /// Aucun serveur NumFranc, aucune adresse à publier soi-même.
    #[allow(deprecated)]
    fn dht_loop(self: Arc<Self>) {
        let dht = match mainline::Dht::client() {
            Ok(d) => d,
            Err(e) => {
                log(&crate::tf!("[i] Annuaire mondial indisponible ({e}) : seule la découverte locale fonctionne.", "[i] World directory unavailable ({e}): only local discovery works."));
                return;
            }
        };
        let mut seed = b"NumFranc-reseau-principal-v1".to_vec();
        seed.extend_from_slice(&GENESIS_HASH_PREFIX);
        let topic = match mainline::Id::from_bytes(&crate::hashing::sha3_512(&seed)[..20]) {
            Ok(t) => t,
            Err(_) => return,
        };
        let mut round = 0u32;
        loop {
            if self.is_reachable() {
                let _ = dht.announce_peer(topic, Some(self.public_port.load(Ordering::SeqCst)));
            }
            let mut found = 0usize;
            let me = self.public_ip.lock().unwrap().map(|ip| SocketAddr::new(ip, self.public_port.load(Ordering::SeqCst)));
            for batch in dht.get_peers(topic) {
                for addr in batch {
                    let addr = SocketAddr::V4(addr);
                    if Some(addr) == me {
                        continue; // notre propre inscription
                    }
                    // Comme les autres adresses, elles passent par l'annuaire (limites par quartier).
                    if self.addrman.lock().unwrap().add(addr, DHT_SOURCE) {
                        found += 1;
                    }
                }
            }
            if found > 0 {
                log(&crate::tf!("[ ] Annuaire mondial : {found} nœud(s) NumFranc trouvé(s).", "[ ] World directory: {found} NumFranc node(s) found."));
            } else if round == 0 {
                log(crate::i18n::t("[ ] Annuaire mondial : aucun autre nœud pour l'instant, nouvelle recherche régulièrement.", "[ ] World directory: no other node yet, searching again regularly."));
            }
            round += 1;
            // Recherche fréquente au début, puis toutes les 10 minutes.
            let wait = if round < 5 { 60 } else { 600 };
            std::thread::sleep(Duration::from_secs(wait));
        }
    }

    fn hashrate_loop(self: Arc<Self>) {
        loop {
            let a = self.hashes.load(Ordering::Relaxed);
            std::thread::sleep(Duration::from_secs(5));
            let b = self.hashes.load(Ordering::Relaxed);
            self.hashrate.store((b - a) / 5, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests_audit {
    use super::*;

    /// C1 : un menteur qui annonce une hauteur énorme sans livrer de bloc valide n'arrête pas le minage.
    #[test]
    fn annonce_sans_preuve_ignoree() {
        assert!(!proven_ahead(u64::MAX, None, 100));
        // Un vrai pair en avance, qui vient de nous livrer un bloc valide : on se synchronise d'abord.
        assert!(proven_ahead(150, Some(Instant::now()), 100));
        // Un pair qui ne livre plus rien depuis longtemps ne bloque plus le minage.
        let old = Instant::now().checked_sub(Duration::from_secs(PROVEN_PEER_SECS + 5));
        if let Some(old) = old {
            assert!(!proven_ahead(150, Some(old), 100));
        }
        // Pas en avance : rien à rattraper.
        assert!(!proven_ahead(100, Some(Instant::now()), 100));
    }
}

#[cfg(test)]
mod tests_genesis {
    #[test]
    fn prefixe_du_genesis_a_jour() {
        let hex: String = super::GENESIS_HASH_PREFIX.iter().map(|b| format!("{b:02x}")).collect();
        assert!(crate::config::GENESIS_HASH_HEX.starts_with(&hex));
    }
}
