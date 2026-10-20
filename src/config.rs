//! Constantes de consensus et de réseau de NumFranc (NFR).
//! Toute valeur monétaire est un entier (unités minimales). Aucun flottant.

/// 1 NFR = 10^8 unités minimales.
pub const MIN_UNIT: u64 = 100_000_000;
/// Plafond total : 69 100 000 NFR, en unités minimales.
pub const HARD_CAP: u64 = 69_100_000 * MIN_UNIT;
/// Nombre de blocs par palier d'émission.
pub const PALIER_BLOCKS: u64 = 100_000;
/// Récompense du palier 0 : 6,91 NFR.
pub const SLOW_START_REWARD: u64 = 691_000_000;
/// Récompense du palier 1 : 69,10 NFR.
pub const PEAK_REWARD: u64 = 6_910_000_000;

/// Temps cible entre deux blocs, en secondes.
pub const TARGET_BLOCK_TIME: u64 = 691;
/// Réajustement de la difficulté tous les 691 blocs.
pub const DIFFICULTY_WINDOW: u64 = 691;
/// Durée attendue mesurée entre le bloc H-691 et le bloc H-1 : 690 intervalles.
/// (Correction du décalage d'un intervalle relevé dans la spécification.)
pub const EXPECTED_TIMESPAN: u64 = (DIFFICULTY_WINDOW - 1) * TARGET_BLOCK_TIME;
/// Nombre de blocs utilisés pour le temps médian passé (MTP).
pub const MTP_BLOCKS: usize = 11;
/// Un bloc ne peut pas être daté de plus de 2 heures dans le futur.
pub const MAX_FUTURE_DRIFT: u64 = 7_200;

/// Taille fixe de l'en-tête de bloc, en octets.
pub const HEADER_SIZE: usize = 212;
/// Taille maximale d'un bloc : 8 Mio.
pub const MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;
/// Taille maximale d'une transaction.
pub const MAX_TX_SIZE: usize = MAX_BLOCK_SIZE - 4_096;
/// Version du protocole.
pub const PROTOCOL_VERSION: u32 = 4;
/// Taille maximale du message joint à un paiement, en octets.
pub const MAX_MEMO: usize = 140;
/// Frais minimaux : 1 000 unités minimales par kilo-octet entamé.
pub const MIN_FEE_PER_KB: u64 = 1_000;

/// --- Protections contre l'attaque des 51 % ---
/// Une récompense de minage ne peut être dépensée qu'après 100 confirmations.
pub const COINBASE_MATURITY: u64 = 100;
/// Un nœud refuse toute réorganisation plus profonde que 10 blocs (~1 h 55).
pub const MAX_REORG_DEPTH: u64 = 10;
/// Nombre de confirmations conseillé avant de considérer un paiement comme sûr.
pub const SAFE_CONFIRMATIONS: u64 = 6;

/// Cible maximale : 2^512 - 1.
pub const MAX_TARGET_BE: [u8; 64] = [0xFF; 64];
/// Cible du bloc genesis et des 690 blocs suivants : 2^492 - 1, soit environ un million
/// d'essais Argon2 par bloc (quelques minutes pour un PC de bureau).
pub const GENESIS_TARGET_BE: [u8; 64] = {
    let mut t = [0xFFu8; 64];
    t[0] = 0x00;
    t[1] = 0x00;
    t[2] = 0x0F;
    t
};
/// Date du bloc genesis : 17 octobre 2026, 00:00:00 UTC.
pub const GENESIS_TIMESTAMP: u64 = 1_792_195_200;
/// Message inscrit dans le bloc genesis.
pub const GENESIS_MESSAGE: &[u8] = b"NumFranc - 69,1 millions - 17/10/2026";
/// Nonce du bloc genesis (trouve une fois pour toutes, verifie par les tests).
pub const GENESIS_NONCE: u64 = 452_924;
/// Empreinte attendue du bloc genesis.
pub const GENESIS_HASH_HEX: &str = "7e0e17a3e283a0291917d8f8c04605bbd5ab00b8e0459baafc0dd0d698238c74fb5fbc288403453f5f3ad2aef5aed636b367f8b654e6bd5e7327360257cbf79e";

/// --- Preuve de travail gourmande en mémoire (Argon2d) ---
/// Mémoire utilisée par chaque essai de minage : 4 Mio.
pub const POW_MEMORY_KIB: u32 = 4_096;
/// Sel fixe de la preuve de travail (séparation de domaine, 16 octets).
pub const POW_SALT: &[u8] = b"NumFranc-PoW-v1!";

/// --- Verrous ---
/// Un verrou inférieur à cette valeur est une hauteur de bloc, sinon une date Unix (comme Bitcoin).
pub const LOCK_TIME_THRESHOLD: u32 = 500_000_000;

/// --- Multi-signature ---
/// Nombre maximal de signataires d'une adresse multi-signature.
pub const MAX_MULTISIG_MEMBERS: usize = 15;

/// --- Pseudos (« alice.nfr ») ---
/// Longueur d'un pseudo, sans le suffixe « .nfr ».
pub const NAME_MIN_LEN: usize = 3;
pub const NAME_MAX_LEN: usize = 32;
/// Frais supplémentaires pour enregistrer un pseudo (contre l'accaparement des noms courts), en unités.
pub const NAME_FEE_3: u64 = 100 * MIN_UNIT;
pub const NAME_FEE_4: u64 = 25 * MIN_UNIT;
pub const NAME_FEE_5_7: u64 = 5 * MIN_UNIT;
pub const NAME_FEE_8_PLUS: u64 = MIN_UNIT;

/// Contexte ML-DSA des signatures de transaction (séparation de domaine).
pub const SIG_CONTEXT: &[u8] = b"NFR-tx-v1";

/// --- Réseau ---
pub const P2P_PORT: u16 = 6910;
pub const MAGIC: [u8; 4] = [0x4E, 0x46, 0x52, 0x04]; // "NFR\x04"
pub const MAX_OUTBOUND: usize = 8;
/// Découverte automatique sur le réseau local : annonce UDP toutes les 10 s.
pub const DISCOVERY_PORT: u16 = 6910;
pub const DISCOVERY_INTERVAL_SECS: u64 = 10;
/// Au démarrage, le minage attend 20 s pour trouver les autres nœuds et se synchroniser.
pub const STARTUP_SYNC_SECS: u64 = 20;
pub const MAX_INBOUND: usize = 32;
/// Nombre maximal de blocs envoyés en réponse à une demande de synchronisation.
pub const MAX_BLOCKS_PER_REPLY: usize = 500;
/// Nœuds d'amorçage : noms fixes de nœuds toujours allumés. Les nouveaux s'y connectent d'abord, puis
/// le réseau s'organise tout seul (annuaire, échanges d'adresses). Sans port, les ports de SEED_PORTS sont
/// essayés dans l'ordre (ce sont ceux que NumFranc demande aux box, voir node.rs).
pub const DEFAULT_SEEDS: &[&str] = &["numfranc.duckdns.org"];
/// Ports essayés pour un nœud d'amorçage écrit sans port.
pub const SEED_PORTS: [u16; 6] = [6910, 16910, 26910, 36910, 46910, 56910];
/// RPC (pour une future passerelle d'échange) : uniquement en local.
pub const RPC_ADDR: &str = "127.0.0.1:6911";

/// --- Règles ajoutées en v1.0.0 (audit de sécurité) ---
/// Date d'activation des nouvelles règles de consensus (19 octobre 2026, 00:00 UTC), comparée au
/// temps médian (MTP) du bloc parent, comme les soft forks de Bitcoin. Les blocs plus anciens,
/// déjà acceptés par tout le monde, restent valides tels quels.
/// Règles concernées : anti « time warp » (BIP94) et `locktime` obligatoirement à 0.
pub const V1_RULES_MTP: u64 = 1_792_368_000;
/// Anti « time warp » (comme le BIP94 de Bitcoin) : le premier bloc d'une fenêtre de difficulté
/// ne peut pas être daté plus de 2 heures avant le bloc précédent.
pub const MAX_TIMEWARP: u64 = 7_200;
/// Taille maximale d'une transaction relayée par le réseau (comme la limite « standard » de Bitcoin,
/// adaptée aux signatures post-quantiques, environ 7 Ko par entrée : ~270 entrées).
/// Un mineur peut toujours inclure une transaction plus grande (jusqu'à MAX_TX_SIZE) dans son propre bloc.
pub const MAX_RELAY_TX_SIZE: usize = 2 * 1024 * 1024;
/// Volume maximal de blocs envoyés en réponse à une seule demande (comme Bitcoin, on envoie
/// les blocs un par un et on s'arrête à une limite) : 32 Mio.
pub const MAX_BYTES_PER_REPLY: usize = 32 * 1024 * 1024;
/// Un pair n'est « en avance » (et ne suspend notre minage) que s'il nous a livré un bloc valide
/// depuis moins de ce délai, en secondes. Une simple annonce de hauteur ne suffit plus.
pub const PROVEN_PEER_SECS: u64 = 120;
