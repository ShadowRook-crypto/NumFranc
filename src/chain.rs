//! État de la chaîne : validation complète des blocs, choix de la chaîne,
//! réorganisations limitées, ensemble des UTXO et stockage sur disque.
//!
//! Stockage : les blocs sont écrits dans blocks.dat et relus à la demande ;
//! seuls les en-têtes, l'ensemble UTXO et les données d'annulation des derniers
//! blocs restent en mémoire.
//!
//! Protections contre l'attaque des 51 % :
//! 1. Choix de la chaîne par TRAVAIL CUMULÉ (pas par longueur).
//! 2. Réorganisation refusée au-delà de MAX_REORG_DEPTH blocs (finalité).
//! 3. Points de contrôle (checkpoints) inscrits dans le logiciel.
//! 4. Maturité de 100 blocs pour les récompenses de minage.
//! 5. Règles d'horodatage (MTP + 2 h) contre la manipulation de la difficulté.

use crate::block::{new_header, Block};
use crate::config::*;
use crate::emission::{block_reward, total_before};
use crate::encoding::hex;
use crate::tx::{is_unlocked, min_fee, name_fee, Address, Hash, NameKind, OutPoint, Transaction, TxOut};
use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Données d'annulation conservées pour les derniers blocs actifs (au-delà, réorganisation refusée).
const UNDO_KEEP: u64 = MAX_REORG_DEPTH + 5;

/// Règle anti « time warp » (BIP94 de Bitcoin) : le premier bloc d'une fenêtre de difficulté ne peut pas
/// être daté plus de MAX_TIMEWARP secondes avant son parent. Sinon, un mineur majoritaire pourrait dater
/// ce bloc dans le passé et fausser la mesure de la fenêtre suivante pour faire baisser la difficulté.
pub fn is_time_warp(height: u64, timestamp: u64, parent_timestamp: u64) -> bool {
    height % DIFFICULTY_WINDOW == 0 && timestamp.saturating_add(MAX_TIMEWARP) < parent_timestamp
}

/// Points de contrôle : (hauteur, hash en hexadécimal). À compléter à chaque version publiée, avec la ligne
/// donnée par `numfranc --point-de-controle` sur un nœud à jour.
pub const CHECKPOINTS: &[(u64, &str)] = &[
    // v1.3.1 : bloc n°300, relevé sur le nœud HP le 23 octobre 2026.
    (300, "79e0447c3b13f1617aa0fa4df7f9208c04e8bad6ead84630d1e0ca933487fdf23c54b21785733839997d168b646a9bfd35c1e0b5ff88f97d3042754e6ff3a4ef"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub amount: u64,
    pub address: Address,
    pub lock_until: u32,
    /// Adresse qui peut reprendre la sortie avant `lock_until` (paiement retenu / annulable).
    pub cancel: Option<Address>,
    /// Paiement retenu : adresse de celui qui l'a envoyé (première entrée de la transaction). À partir des
    /// règles v1.3.0, une annulation ne peut renvoyer l'argent qu'à cette adresse.
    pub refund: Option<Address>,
    pub height: u64,
    pub coinbase: bool,
}

/// Un pseudo enregistré : son propriétaire actuel et la hauteur de son premier enregistrement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEntry {
    pub owner: Address,
    pub height: u64,
}

pub type Utxo = HashMap<OutPoint, UtxoEntry>;
pub type Names = HashMap<String, NameEntry>;

pub struct IndexEntry {
    pub header: crate::block::BlockHeader,
    pub height: u64,
    pub work: BigUint,
    pub invalid: bool,
    /// Heure locale de réception (0 = relu depuis notre fichier, ou genesis) : sert à repérer les chaînes cachées.
    pub vu: u64,
}

/// Message interne de `check_block` pour un horodatage trop loin dans le futur (voir `ChainError::FutureTime`).
const FUTURE_TIME_MSG: &str = "horodatage trop loin dans le futur";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    Invalid(String),
    /// Bloc daté de plus de 2 h dans le futur selon NOTRE horloge : il n'est pas forcément faux (horloge d'un des deux
    /// ordinateurs décalée), donc il est ignoré sans punir celui qui l'envoie (comme Bitcoin, BLOCK_TIME_FUTURE).
    FutureTime,
    /// Bloc déjà rejeté par nous, ou fils d'un bloc rejeté : le pair ne l'a peut-être pas encore appris.
    /// On coupe la connexion, sans l'exclure 24 h.
    KnownBad(String),
    ReorgTooDeep { depth: u64 },
    Orphan,
    AlreadyKnown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    Extended,
    Reorganized { depth: u64 },
    SideChain,
    /// Branche plus lourde, mais révélée en retard (chaîne cachée) : gardée de côté pour l'instant.
    Penalisee { retard: u64 },
}

/// Une modification de l'ensemble UTXO, pour pouvoir l'annuler dans l'ordre inverse.
#[derive(Clone, Debug)]
pub enum UndoOp {
    Spent(OutPoint, UtxoEntry),
    Created(OutPoint),
    /// Ancienne valeur d'un pseudo (None = il n'existait pas).
    Name(String, Option<NameEntry>),
}

fn undo_ops(utxo: &mut Utxo, names: &mut Names, ops: Vec<UndoOp>) {
    for op in ops.into_iter().rev() {
        match op {
            UndoOp::Spent(k, v) => {
                utxo.insert(k, v);
            }
            UndoOp::Created(k) => {
                utxo.remove(&k);
            }
            UndoOp::Name(n, Some(v)) => {
                names.insert(n, v);
            }
            UndoOp::Name(n, None) => {
                names.remove(&n);
            }
        }
    }
}

pub struct Chain {
    index: HashMap<Hash, IndexEntry>,
    /// Blocs gardés en mémoire : le genesis, ou tous les blocs quand il n'y a pas de fichier.
    mem: HashMap<Hash, Block>,
    /// Position (début, longueur) de chaque bloc dans blocks.dat.
    locs: HashMap<Hash, (u64, u32)>,
    active: Vec<Hash>,
    pub utxo: Utxo,
    /// Pseudos enregistrés (« alice » pour « alice.nfr »).
    pub names: Names,
    undo: HashMap<Hash, Vec<UndoOp>>,
    store: Option<File>,
    path: Option<PathBuf>,
    store_len: u64,
    /// Travail en dessous duquel la limite de réorganisation ne s'applique pas (synchronisation initiale).
    min_work_reorg: BigUint,
    /// Points de contrôle en vigueur (ceux du logiciel pour la vraie chaîne ; réglables dans les tests).
    pub(crate) points: Vec<(u64, String)>,
    /// Empreintes de blocs entiers déjà jugés invalides : renvoyés en boucle, ils sont refusés sans
    /// revérifier leurs signatures (le contenu exact est mémorisé, pas seulement l'en-tête).
    rejets: std::collections::HashSet<[u8; 64]>,
}

/// Bloc genesis, identique pour tous les nœuds. Sa récompense est envoyée à une
/// adresse nulle impossible à dépenser (comme le genesis de Bitcoin).
pub fn genesis_block() -> Block {
    let cb = Transaction::coinbase(
        0,
        GENESIS_MESSAGE,
        vec![TxOut::new(SLOW_START_REWARD, [0u8; 32])],
    );
    let mut b = Block {
        header: new_header([0u8; 64], [0u8; 64], GENESIS_TIMESTAMP, GENESIS_TARGET_BE),
        txs: vec![cb],
    };
    b.header.merkle_root = b.compute_merkle_root();
    b.header.nonce = GENESIS_NONCE;
    b
}

pub fn target_to_int(t: &[u8; 64]) -> BigUint {
    BigUint::from_bytes_be(t)
}

pub fn int_to_target(v: &BigUint) -> [u8; 64] {
    let b = v.to_bytes_be();
    let mut out = [0u8; 64];
    if b.len() > 64 {
        return MAX_TARGET_BE;
    }
    out[64 - b.len()..].copy_from_slice(&b);
    out
}

/// Travail d'un bloc : 2^512 / (cible + 1).
pub fn block_work(target: &[u8; 64]) -> BigUint {
    (BigUint::from(1u8) << 512usize) / (target_to_int(target) + 1u8)
}

/// Nouvelle cible après une fenêtre, en arithmétique entière stricte.
pub fn retarget(old: &[u8; 64], actual_timespan: u64) -> [u8; 64] {
    let actual = actual_timespan.clamp(EXPECTED_TIMESPAN / 4, EXPECTED_TIMESPAN * 4);
    let new = target_to_int(old) * actual / EXPECTED_TIMESPAN;
    let max = target_to_int(&MAX_TARGET_BE);
    let new = if new > max { max } else if new < BigUint::from(1u8) { BigUint::from(1u8) } else { new };
    int_to_target(&new)
}

/// Vérifie les entrées d'une transaction contre l'ensemble UTXO. Renvoie les frais.
/// `height` = hauteur du bloc qui contiendra la transaction, `mtp` = temps médian de son parent.
pub fn check_tx_inputs(utxo: &Utxo, tx: &Transaction, height: u64, mtp: u64) -> Result<u64, String> {
    let v2 = mtp >= V2_RULES_MTP;
    let mut in_sum = 0u64;
    for i in &tx.inputs {
        let u = utxo.get(&i.prev).ok_or("entrée inexistante ou déjà dépensée")?;
        if u.coinbase && height < u.height + COINBASE_MATURITY {
            return Err("récompense de minage pas encore mûre (100 confirmations)".into());
        }
        // Qui a le droit de dépenser ? Le destinataire une fois la date passée ; avant,
        // personne... sauf l'adresse d'annulation d'un paiement retenu.
        let expected = if is_unlocked(u.lock_until, height, mtp) {
            u.address
        } else if let Some(c) = u.cancel {
            // Règles v1.3.0 : l'argent d'un paiement annulé repart uniquement chez celui qui l'avait envoyé.
            if v2 {
                let r = u.refund.ok_or("paiement retenu sans expéditeur connu")?;
                if tx.outputs.iter().any(|o| o.address != r || o.lock_until != 0 || o.cancel.is_some()) {
                    return Err("un paiement annulé doit revenir à celui qui l'a envoyé".into());
                }
            }
            c
        } else {
            return Err(if u.lock_until < LOCK_TIME_THRESHOLD {
                format!("sortie verrouillée jusqu'au bloc #{}", u.lock_until)
            } else {
                format!("sortie verrouillée jusqu'à la date Unix {}", u.lock_until)
            });
        };
        if i.spender() != expected {
            return Err(if expected == u.address {
                "la clé publique ne correspond pas à l'adresse".into()
            } else {
                "avant la date de déblocage, seule l'adresse d'annulation peut reprendre cette sortie".to_string()
            });
        }
        in_sum = in_sum.checked_add(u.amount).ok_or("dépassement")?;
    }
    let out = tx.output_sum().ok_or("dépassement")?;
    if in_sum <= out {
        return Err("entrées insuffisantes ou frais nuls".into());
    }
    let fee = in_sum - out;
    if fee < min_fee(tx.size()) {
        return Err("frais trop faibles".into());
    }
    Ok(fee)
}

/// Contrôle l'enregistrement ou le transfert d'un pseudo. À appeler APRÈS `check_tx_inputs`
/// (les signatures et les adresses des entrées sont alors déjà vérifiées). `fee` = frais payés.
pub fn check_name_op(names: &Names, tx: &Transaction, fee: u64) -> Result<(), String> {
    let Some(op) = &tx.name_op else { return Ok(()) };
    match op.kind {
        NameKind::Register => {
            if names.contains_key(&op.name) {
                return Err(format!("le pseudo « {} » est déjà pris", op.name));
            }
            let need = min_fee(tx.size()).saturating_add(name_fee(op.name.len()));
            if fee < need {
                return Err(format!("frais insuffisants pour ce pseudo : {need} unités au minimum"));
            }
        }
        NameKind::Update => {
            let cur = names.get(&op.name).ok_or("pseudo inconnu")?;
            if !tx.inputs.iter().any(|i| i.spender() == cur.owner) {
                return Err("seul le propriétaire d'un pseudo peut le modifier".into());
            }
        }
    }
    Ok(())
}

/// Frais détruits (règles v1.3.0) : le prix de chaque pseudo enregistré. `mtp` = temps médian du parent.
pub fn burned_fees(txs: &[Transaction], mtp: u64) -> u64 {
    if mtp < V2_RULES_MTP {
        return 0;
    }
    txs.iter()
        .filter_map(|t| t.name_op.as_ref())
        .filter(|n| n.kind == NameKind::Register)
        .map(|n| name_fee(n.name.len()))
        .fold(0u64, |a, b| a.saturating_add(b))
}

fn apply_name(names: &mut Names, tx: &Transaction, height: u64, log: &mut Vec<UndoOp>) {
    if let Some(op) = &tx.name_op {
        let prev = names.get(&op.name).cloned();
        let first = prev.as_ref().map(|p| p.height).unwrap_or(height);
        log.push(UndoOp::Name(op.name.clone(), prev));
        names.insert(op.name.clone(), NameEntry { owner: op.owner, height: first });
    }
}

fn apply_tx(utxo: &mut Utxo, names: &mut Names, tx: &Transaction, height: u64, log: &mut Vec<UndoOp>) {
    let coinbase = tx.is_coinbase();
    if !coinbase {
        for i in &tx.inputs {
            if let Some(u) = utxo.remove(&i.prev) {
                log.push(UndoOp::Spent(i.prev, u));
            }
        }
    }
    let txid = tx.txid();
    let sender = if coinbase { None } else { tx.inputs.first().map(|i| i.spender()) };
    for (n, o) in tx.outputs.iter().enumerate() {
        let op = OutPoint { txid, vout: n as u32 };
        let refund = o.cancel.and(sender);
        utxo.insert(op, UtxoEntry { amount: o.amount, address: o.address, lock_until: o.lock_until, cancel: o.cancel, refund, height, coinbase });
        log.push(UndoOp::Created(op));
    }
    apply_name(names, tx, height, log);
}

fn connect_inner(
    utxo: &mut Utxo,
    names: &mut Names,
    block: &Block,
    height: u64,
    mtp: u64,
    log: &mut Vec<UndoOp>,
) -> Result<(), String> {
    let mut fees = 0u64;
    for tx in &block.txs[1..] {
        let fee = check_tx_inputs(utxo, tx, height, mtp)?;
        check_name_op(names, tx, fee)?;
        fees = fees.checked_add(fee).ok_or("dépassement des frais")?;
        apply_tx(utxo, names, tx, height, log);
    }
    // Règles v1.3.0 : la part « pseudo » des frais est détruite, le mineur ne la reçoit pas.
    fees = fees.checked_sub(burned_fees(&block.txs[1..], mtp)).ok_or("frais de pseudo incohérents")?;
    let cb = &block.txs[0];
    let allowed = block_reward(height, total_before(height))
        .checked_add(fees)
        .ok_or("dépassement")?;
    if cb.output_sum().ok_or("dépassement")? > allowed {
        return Err("récompense de minage trop élevée".into());
    }
    apply_tx(utxo, names, cb, height, log);
    Ok(())
}

/// Applique un bloc à l'ensemble UTXO et renvoie de quoi l'annuler.
/// En cas d'erreur, l'ensemble est remis exactement dans son état initial.
pub fn connect_block(utxo: &mut Utxo, names: &mut Names, block: &Block, height: u64, mtp: u64) -> Result<Vec<UndoOp>, String> {
    let mut log = Vec::new();
    match connect_inner(utxo, names, block, height, mtp, &mut log) {
        Ok(()) => Ok(log),
        Err(e) => {
            undo_ops(utxo, names, log);
            Err(e)
        }
    }
}

/// Ligne de point de contrôle à copier dans CHECKPOINTS, lue dans la chaîne la plus longue parmi ces
/// dossiers de données. Travaille sur une copie de blocks.dat : le nœud peut continuer de tourner.
/// Le bloc choisi est enterré sous au moins 100 blocs (multiple de 100), donc définitif.
pub fn point_de_controle(dossiers: &[PathBuf]) -> Result<String, String> {
    let source = dossiers
        .iter()
        .map(|d| d.join("blocks.dat"))
        .filter_map(|p| std::fs::metadata(&p).ok().map(|m| (m.len(), p)))
        .max_by_key(|(n, _)| *n)
        .map(|(_, p)| p)
        .ok_or("aucune chaîne trouvée (blocks.dat) : lance NumFranc au moins une fois, ou indique le dossier : numfranc --point-de-controle DOSSIER")?;
    let mut r = [0u8; 8];
    let _ = getrandom::getrandom(&mut r);
    let tmp = std::env::temp_dir().join(format!("numfranc-point-{}", hex(&r)));
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let copie = tmp.join("blocks.dat");
    let res = (|| {
        std::fs::copy(&source, &copie).map_err(|e| format!("{} : {e}", source.display()))?;
        let c = Chain::open(&copie).map_err(|e| e.to_string())?;
        let haut = c.height();
        if haut < 200 {
            return Err(format!("chaîne trop courte ({haut} blocs) : il en faut au moins 200"));
        }
        let h = (haut - 100) / 100 * 100;
        let hash = c.hash_at(h).ok_or("bloc introuvable")?;
        Ok(format!(
            "Chaîne lue : {} ({haut} blocs)\nPoint de contrôle proposé : bloc n°{h}\n\n    ({h}, \"{}\"),\n",
            source.display(),
            hex(&hash)
        ))
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

const LECTURE_DISQUE: &str = "bloc introuvable sur le disque";

impl Chain {
    pub fn new() -> Self {
        Self::with_genesis(genesis_block())
    }

    /// Chaîne partant d'un genesis donné (utilisé par les tests avec une difficulté réduite).
    pub fn with_genesis(g: Block) -> Self {
        let h = g.hash();
        let mut index = HashMap::new();
        index.insert(
            h,
            IndexEntry { header: g.header.clone(), height: 0, work: block_work(&g.header.target), invalid: false, vu: 0 },
        );
        let vraie = h == genesis_block().hash();
        let min_work_reorg = if vraie {
            block_work(&GENESIS_TARGET_BE) * BigUint::from(MIN_CHAIN_BLOCKS + 1)
        } else {
            BigUint::from(0u8)
        };
        let points = if vraie { CHECKPOINTS.iter().map(|(n, s)| (*n, s.to_string())).collect() } else { Vec::new() };
        let mut mem = HashMap::new();
        mem.insert(h, g);
        Self {
            min_work_reorg,
            points,
            rejets: std::collections::HashSet::new(),
            index,
            mem,
            locs: HashMap::new(),
            active: vec![h],
            utxo: HashMap::new(),
            names: HashMap::new(),
            undo: HashMap::new(),
            store: None,
            path: None,
            store_len: 0,
        }
    }

    /// Ouvre (ou crée) la chaîne stockée dans `path`.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with_genesis(path, genesis_block())
    }

    /// Relit blocks.dat bloc par bloc (sans tout charger en mémoire). Ces blocs ont déjà été
    /// entièrement vérifiés par ce nœud avant d'être écrits : au rechargement, on refait toutes
    /// les vérifications sauf les plus coûteuses (preuve de travail Argon2 et signatures ML-DSA).
    /// Une fin de fichier tronquée (coupure de courant) est réparée.
    pub fn open_with_genesis(path: &Path, genesis: Block) -> std::io::Result<Self> {
        let mut chain = Self::with_genesis(genesis);
        chain.path = Some(path.to_path_buf()); // nécessaire dès le chargement (réorganisations)
        let mut good_end = 0u64;
        if let Ok(f) = File::open(path) {
            let total = f.metadata()?.len();
            let mut r = BufReader::with_capacity(1 << 20, f);
            let mut pos = 0u64;
            loop {
                let mut len_buf = [0u8; 4];
                if r.read_exact(&mut len_buf).is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf);
                if len as usize > MAX_BLOCK_SIZE || pos + 4 + len as u64 > total {
                    break;
                }
                let mut data = vec![0u8; len as usize];
                if r.read_exact(&mut data).is_err() {
                    break;
                }
                if let Ok(b) = Block::from_bytes(&data) {
                    let _ = chain.add_block_inner(b, u64::MAX / 4, Some((pos + 4, len)));
                }
                pos += 4 + len as u64;
                good_end = pos;
            }
        }
        // Fichier non vide mais aucun bloc utilisable : chaîne d'une ancienne version (autres règles).
        // On la met de côté au lieu de l'écraser, et on repart d'une chaîne neuve.
        if chain.height() == 0 && good_end > 0 {
            let mut n = 0u32;
            let dest = loop {
                let d = path.with_extension(if n == 0 { "ancien".to_string() } else { format!("ancien{n}") });
                if !d.exists() {
                    break d;
                }
                n += 1;
            };
            std::fs::rename(path, &dest)?;
            crate::events::log(&crate::tf!(
                "Ancienne chaîne (autres règles) mise de côté dans {} : nouvelle chaîne NumFranc v0.6.",
                "Old chain (different rules) moved aside to {}: new NumFranc v0.6 chain.",
                dest.display()
            ));
            good_end = 0;
        }
        let f = OpenOptions::new().create(true).read(true).write(true).truncate(false).open(path)?;
        f.set_len(good_end)?;
        chain.store = Some(f);
        chain.store_len = good_end;
        Ok(chain)
    }

    pub fn tip(&self) -> Hash {
        *self.active.last().unwrap()
    }
    pub fn height(&self) -> u64 {
        (self.active.len() - 1) as u64
    }
    pub fn header(&self, hash: &Hash) -> Option<&crate::block::BlockHeader> {
        self.index.get(hash).map(|e| &e.header)
    }

    /// Lit un bloc (en mémoire ou dans blocks.dat).
    pub fn get_block(&self, hash: &Hash) -> Option<Block> {
        if let Some(b) = self.mem.get(hash) {
            return Some(b.clone());
        }
        let (start, len) = *self.locs.get(hash)?;
        let mut f = File::open(self.path.as_ref()?).ok()?;
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut data = vec![0u8; len as usize];
        f.read_exact(&mut data).ok()?;
        Block::from_bytes(&data).ok()
    }

    /// Hash du bloc actif à la hauteur `height`.
    pub fn hash_at(&self, height: u64) -> Option<Hash> {
        self.active.get(height as usize).copied()
    }

    pub fn block_at(&self, height: u64) -> Option<Block> {
        self.get_block(self.active.get(height as usize)?)
    }
    pub fn contains(&self, hash: &Hash) -> bool {
        self.index.contains_key(hash)
    }
    pub fn is_active(&self, hash: &Hash) -> bool {
        match self.index.get(hash) {
            Some(e) => self.active.get(e.height as usize) == Some(hash),
            None => false,
        }
    }
    pub fn tip_work(&self) -> &BigUint {
        &self.index[&self.tip()].work
    }

    fn ancestor(&self, hash: &Hash, height: u64) -> Hash {
        let mut h = *hash;
        loop {
            let e = &self.index[&h];
            if e.height == height {
                return h;
            }
            if self.is_active(&h) {
                return self.active[height as usize];
            }
            h = e.header.previous_block_hash;
        }
    }

    /// Temps médian des 11 blocs se terminant par `parent`.
    pub fn median_time_past(&self, parent: &Hash) -> u64 {
        let mut ts = Vec::with_capacity(MTP_BLOCKS);
        let mut h = *parent;
        for _ in 0..MTP_BLOCKS {
            let e = &self.index[&h];
            ts.push(e.header.timestamp);
            if e.height == 0 {
                break;
            }
            h = e.header.previous_block_hash;
        }
        ts.sort_unstable();
        ts[ts.len() / 2]
    }

    /// Temps médian qui s'appliquera au prochain bloc (sert aux verrous par date).
    pub fn next_mtp(&self) -> u64 {
        self.median_time_past(&self.tip())
    }

    /// Cible exigée pour le bloc de hauteur `height` dont le parent est `parent`.
    pub fn expected_target(&self, parent: &Hash, height: u64) -> [u8; 64] {
        let p = &self.index[parent];
        if height % DIFFICULTY_WINDOW != 0 {
            return p.header.target;
        }
        let first = self.ancestor(parent, height - DIFFICULTY_WINDOW);
        let actual = p.header.timestamp.saturating_sub(self.index[&first].header.timestamp);
        retarget(&p.header.target, actual)
    }

    /// `trusted` : bloc relu depuis notre propre fichier, déjà entièrement vérifié avant d'être écrit.
    fn check_block(&self, block: &Block, parent: &Hash, height: u64, now: u64, trusted: bool) -> Result<(), String> {
        let hdr = &block.header;
        let hash = hdr.hash();
        if hdr.version != PROTOCOL_VERSION {
            return Err("version de bloc inconnue".into());
        }
        for (h, expected) in &self.points {
            if *h == height && hex(&hash) != *expected {
                return Err(format!("bloc contraire au point de contrôle {h}"));
            }
        }
        if hdr.target != self.expected_target(parent, height) {
            return Err("cible de difficulté incorrecte".into());
        }
        let mtp = self.median_time_past(parent);
        if hdr.timestamp <= mtp {
            return Err("horodatage trop ancien (MTP)".into());
        }
        // Règles v1.0.0, actives à partir de V1_RULES_MTP (les blocs plus anciens restent valides).
        let v1 = mtp >= V1_RULES_MTP;
        if v1 && is_time_warp(height, hdr.timestamp, self.index[parent].header.timestamp) {
            return Err("début de fenêtre de difficulté daté trop tôt (time warp)".into());
        }
        if hdr.timestamp > now.saturating_add(MAX_FUTURE_DRIFT) {
            return Err(FUTURE_TIME_MSG.into());
        }
        // Vérifications bon marché d'abord, preuve de travail (Argon2, ~2 ms) ensuite.
        if !trusted && !hdr.meets_target() {
            return Err("preuve de travail insuffisante".into());
        }
        if block.serialize().len() > MAX_BLOCK_SIZE {
            return Err("bloc trop grand".into());
        }
        if block.txs.is_empty() || !block.txs[0].is_coinbase() {
            return Err("la première transaction doit être la coinbase".into());
        }
        if block.txs[0].coinbase_height() != Some(height) {
            return Err("hauteur incorrecte dans la coinbase".into());
        }
        if block.txs[1..].iter().any(|t| t.is_coinbase()) {
            return Err("coinbase en double".into());
        }
        if block.compute_merkle_root() != hdr.merkle_root {
            return Err("racine de Merkle incorrecte".into());
        }
        if v1 && block.txs.iter().any(|t| t.locktime != 0) {
            return Err("champ locktime non nul (réservé)".into());
        }
        // Règles v1.3.0 : plus de pièces minuscules (hors récompense de minage).
        if mtp >= V2_RULES_MTP && block.txs[1..].iter().any(|t| t.outputs.iter().any(|o| o.amount < DUST)) {
            return Err("pièce de moins de 0,0001 NFR dans un bloc".into());
        }
        let mut ids = HashSet::new();
        for t in &block.txs {
            if !ids.insert(t.txid()) {
                return Err("transaction en double dans le bloc".into());
            }
            if trusted { t.check_structure() } else { t.check_stateless() }.map_err(|e| e.0)?;
        }
        Ok(())
    }

    /// Enregistre un bloc : dans blocks.dat s'il y a un fichier, sinon en mémoire.
    fn store_block(&mut self, hash: Hash, block: &Block) {
        if let Some(f) = self.store.as_mut() {
            let bytes = block.serialize();
            let mut rec = (bytes.len() as u32).to_be_bytes().to_vec();
            rec.extend_from_slice(&bytes);
            if f.seek(SeekFrom::Start(self.store_len)).is_ok() && f.write_all(&rec).is_ok() && f.flush().is_ok() {
                self.locs.insert(hash, (self.store_len + 4, bytes.len() as u32));
                self.store_len += rec.len() as u64;
                return;
            }
        }
        self.mem.insert(hash, block.clone());
    }

    /// Ajoute un bloc reçu ou miné. `now` = heure UNIX actuelle.
    pub fn add_block(&mut self, block: Block, now: u64) -> Result<Added, ChainError> {
        self.add_block_inner(block, now, None)
    }

    /// `loc` = position dans blocks.dat quand le bloc est relu au démarrage.
    fn add_block_inner(&mut self, block: Block, now: u64, loc: Option<(u64, u32)>) -> Result<Added, ChainError> {
        let hash = block.hash();
        if let Some(e) = self.index.get(&hash) {
            return Err(if e.invalid { ChainError::KnownBad("bloc déjà rejeté".into()) } else { ChainError::AlreadyKnown });
        }
        // (Pas au rechargement de notre propre fichier : inutile, et ce serait lent au démarrage.)
        let empreinte = if loc.is_none() { crate::hashing::sha3_512(&block.serialize()) } else { [0; 64] };
        if loc.is_none() && self.rejets.contains(&empreinte) {
            return Err(ChainError::KnownBad("bloc déjà rejeté".into()));
        }
        let parent_hash = block.header.previous_block_hash;
        let (parent_height, parent_work) = match self.index.get(&parent_hash) {
            None => return Err(ChainError::Orphan),
            Some(p) if p.invalid => return Err(ChainError::KnownBad("parent invalide".into())),
            Some(p) => (p.height, p.work.clone()),
        };
        let height = parent_height + 1;
        // Points de contrôle : une fois notre chaîne au-delà du dernier, plus aucun embranchement avant lui
        // (personne ne peut réécrire cette partie de l'histoire, même avec énormément de puissance de calcul).
        if let Some(dernier) = self.points.iter().map(|p| p.0).max() {
            if height <= dernier && self.height() >= dernier {
                return Err(ChainError::KnownBad("embranchement avant le dernier point de contrôle".into()));
            }
        }
        // Comme Bitcoin, on n'enregistre pas un bloc d'une branche qui ne pourra jamais gagner :
        // si elle part de plus de MAX_REORG_DEPTH blocs en arrière, elle serait de toute façon refusée.
        // (Pas au rechargement de notre propre fichier : ces blocs y sont déjà.)
        if loc.is_none() && parent_hash != self.tip() {
            let limite = self.limite_reorg();
            let mut h = parent_hash;
            let mut steps = 0u64;
            while !self.is_active(&h) {
                // Un ancêtre déjà jugé invalide : toute la branche l'est.
                if self.index[&h].invalid {
                    return Err(ChainError::KnownBad("ancêtre invalide".into()));
                }
                steps += 1;
                if limite && steps > MAX_REORG_DEPTH + 1 {
                    return Err(ChainError::ReorgTooDeep { depth: steps });
                }
                h = self.index[&h].header.previous_block_hash;
            }
            let depth = self.height().saturating_sub(self.index[&h].height);
            if limite && depth > MAX_REORG_DEPTH {
                return Err(ChainError::ReorgTooDeep { depth });
            }
        }
        if let Err(e) = self.check_block(&block, &parent_hash, height, now, loc.is_some()) {
            if e == FUTURE_TIME_MSG {
                return Err(ChainError::FutureTime);
            }
            self.rejeter(empreinte);
            return Err(ChainError::Invalid(e));
        }

        let work = parent_work + block_work(&block.header.target);
        let vu = if loc.is_none() { now } else { 0 };
        self.index.insert(hash, IndexEntry { header: block.header.clone(), height, work: work.clone(), invalid: false, vu });
        match loc {
            Some(l) => {
                self.locs.insert(hash, l);
            }
            None => self.store_block(hash, &block),
        }

        if parent_hash == self.tip() {
            let mtp = self.median_time_past(&parent_hash);
            match connect_block(&mut self.utxo, &mut self.names, &block, height, mtp) {
                Ok(log) => {
                    self.active.push(hash);
                    self.remember_undo(hash, log);
                    Ok(Added::Extended)
                }
                Err(e) => {
                    self.index.get_mut(&hash).unwrap().invalid = true;
                    self.rejeter(empreinte);
                    Err(ChainError::Invalid(e))
                }
            }
        } else if &work > self.tip_work() {
            // Chaîne cachée (minée en secret puis révélée d'un coup) : il lui faut davantage de travail.
            if loc.is_none() && self.limite_reorg() {
                if let Some(retard) = self.retard_branche(hash, now) {
                    let cible = self.index[&self.tip()].header.target;
                    let besoin = self.tip_work().clone() + block_work(&cible) * BigUint::from(retard);
                    if work <= besoin {
                        return Ok(Added::Penalisee { retard });
                    }
                }
            }
            self.try_reorg(hash)
        } else {
            Ok(Added::SideChain)
        }
    }

    /// Retard d'une branche concurrente : nombre de blocs de notre chaîne (après la fourche) qui étaient déjà
    /// arrivés quand le premier bloc de la branche est apparu. None si pas de pénalité à appliquer.
    fn retard_branche(&self, bout: Hash, now: u64) -> Option<u64> {
        let mut h = bout;
        let mut premier = u64::MAX;
        while !self.is_active(&h) {
            let e = &self.index[&h];
            if e.vu == 0 {
                return None;
            }
            premier = premier.min(e.vu);
            h = e.header.previous_block_hash;
        }
        if premier == u64::MAX || now >= premier.saturating_add(PENALITE_DUREE) {
            return None;
        }
        let fourche = self.index[&h].height as usize;
        let retard = self.active[fourche + 1..].iter().filter(|b| self.index[*b].vu != 0 && self.index[*b].vu < premier).count() as u64;
        (retard >= PENALITE_MIN).then_some(retard)
    }

    /// Hauteur du dernier point de contrôle (inscrit ou signé), s'il y en a un.
    pub fn dernier_point(&self) -> Option<u64> {
        self.points.iter().map(|p| p.0).max()
    }

    /// La limite de réorganisation s'applique-t-elle ? (Non pendant la synchronisation initiale.)
    fn limite_reorg(&self) -> bool {
        self.tip_work() >= &self.min_work_reorg
    }

    fn rejeter(&mut self, empreinte: [u8; 64]) {
        if self.rejets.len() >= 10_000 {
            self.rejets.clear();
        }
        self.rejets.insert(empreinte);
    }

    fn remember_undo(&mut self, hash: Hash, log: Vec<UndoOp>) {
        self.undo.insert(hash, log);
        let h = self.height();
        if h >= UNDO_KEEP {
            if let Some(old) = self.active.get((h - UNDO_KEEP) as usize) {
                let old = *old;
                self.undo.remove(&old);
            }
        }
    }

    /// Reconstruit l'ensemble UTXO depuis le genesis jusqu'à `height` (secours, lent).
    fn rebuild_utxo(&mut self, height: u64) {
        let mut utxo = HashMap::new();
        let mut names = HashMap::new();
        self.undo.clear();
        for h in 1..=height {
            let bh = self.active[h as usize];
            let b = self.get_block(&bh).expect("bloc actif lisible");
            let mtp = self.median_time_past(&b.header.previous_block_hash);
            let log = connect_block(&mut utxo, &mut names, &b, h, mtp).expect("la chaîne active est valide");
            if h + UNDO_KEEP > height {
                self.undo.insert(bh, log);
            }
        }
        self.utxo = utxo;
        self.names = names;
    }

    /// Bascule vers une chaîne concurrente ayant plus de travail (au plus MAX_REORG_DEPTH blocs annulés).
    fn try_reorg(&mut self, new_tip: Hash) -> Result<Added, ChainError> {
        let mut path = Vec::new();
        let mut h = new_tip;
        while !self.is_active(&h) {
            if self.index[&h].invalid {
                return Err(ChainError::Invalid("chaîne contenant un bloc invalide".into()));
            }
            path.push(h);
            h = self.index[&h].header.previous_block_hash;
        }
        let fork_height = self.index[&h].height;
        // Jamais de retour en arrière avant le dernier point de contrôle.
        if self.dernier_point().is_some_and(|d| fork_height < d && self.height() >= d) {
            return Err(ChainError::KnownBad("embranchement avant le dernier point de contrôle".into()));
        }
        let depth = self.height() - fork_height;
        if self.limite_reorg() && depth > MAX_REORG_DEPTH {
            return Err(ChainError::ReorgTooDeep { depth });
        }
        path.reverse();

        // 1. Annuler les blocs actifs au-dessus du point de fourche.
        let old: Vec<Hash> = self.active[(fork_height as usize + 1)..].to_vec();
        if old.iter().all(|b| self.undo.contains_key(b)) {
            for b in old.iter().rev() {
                let log = self.undo.remove(b).unwrap();
                undo_ops(&mut self.utxo, &mut self.names, log);
            }
        } else {
            self.rebuild_utxo(fork_height);
        }
        self.active.truncate(fork_height as usize + 1);

        // 2. Appliquer la nouvelle branche ; en cas d'échec, revenir à l'ancienne.
        for (i, bh) in path.iter().enumerate() {
            let height = fork_height + 1 + i as u64;
            let res = match self.get_block(bh) {
                Some(b) => {
                    let mtp = self.median_time_past(&b.header.previous_block_hash);
                    connect_block(&mut self.utxo, &mut self.names, &b, height, mtp)
                }
                None => Err(LECTURE_DISQUE.into()),
            };
            match res {
                Ok(log) => {
                    self.active.push(*bh);
                    self.remember_undo(*bh, log);
                }
                Err(e) => {
                    // Une erreur de lecture du disque ne rend pas le bloc invalide (il pourra être relu).
                    if e != LECTURE_DISQUE {
                        self.index.get_mut(bh).unwrap().invalid = true;
                    }
                    // Retour à l'ancienne branche.
                    while self.height() > fork_height {
                        let b = self.active.pop().unwrap();
                        if let Some(log) = self.undo.remove(&b) {
                            undo_ops(&mut self.utxo, &mut self.names, log);
                        }
                    }
                    for (j, ob) in old.iter().enumerate() {
                        let height = fork_height + 1 + j as u64;
                        let b = self.get_block(ob).expect("ancien bloc lisible");
                        let mtp = self.median_time_past(&b.header.previous_block_hash);
                        let log = connect_block(&mut self.utxo, &mut self.names, &b, height, mtp).expect("l'ancienne branche était valide");
                        self.active.push(*ob);
                        self.remember_undo(*ob, log);
                    }
                    if e == LECTURE_DISQUE {
                        // Pas la faute de celui qui a envoyé le bloc : on ne l'exclut pas.
                        return Err(ChainError::AlreadyKnown);
                    }
                    return Err(ChainError::Invalid(e));
                }
            }
        }
        Ok(Added::Reorganized { depth })
    }

    /// Liste de hashes permettant à un pair de trouver notre point commun.
    pub fn locator(&self) -> Vec<Hash> {
        let mut v = Vec::new();
        let mut step = 1i64;
        let mut h = self.height() as i64;
        while h > 0 {
            v.push(self.active[h as usize]);
            if v.len() >= 10 {
                step *= 2;
            }
            h -= step;
        }
        v.push(self.active[0]);
        v
    }

    /// Hashes des blocs de la chaîne active qui suivent le premier hash connu du localisateur.
    /// (Comme l'inventaire de Bitcoin : une liste légère ; les blocs sont ensuite lus un par un.)
    pub fn hashes_after(&self, locator: &[Hash], max: usize) -> Vec<Hash> {
        let start = locator
            .iter()
            .find_map(|h| if self.is_active(h) { Some(self.index[h].height) } else { None })
            .unwrap_or(0);
        ((start + 1)..=self.height()).take(max).filter_map(|h| self.hash_at(h)).collect()
    }

    /// Blocs de la chaîne active qui suivent le premier hash connu du localisateur (tests et outils).
    pub fn blocks_after(&self, locator: &[Hash], max: usize) -> Vec<Block> {
        self.hashes_after(locator, max).iter().filter_map(|h| self.get_block(h)).collect()
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::block::mine;
    use crate::signature::KeyPair;
    use crate::tx::{address_of_pubkey, multisig_address, normalize_members, NameOp, PartialSig, TxIn};

    pub fn addr(kp: &KeyPair) -> Address {
        address_of_pubkey(&kp.public_key_bytes())
    }

    /// Construit et mine un bloc au-dessus de `parent`.
    pub fn make_block(chain: &Chain, parent: Hash, txs: Vec<Transaction>, to: Address, ts_offset: u64, extra: &[u8]) -> Block {
        let p = chain.header(&parent).unwrap().clone();
        let height = chain.index[&parent].height + 1;
        let fees: u64 = 0;
        let reward = block_reward(height, total_before(height)) + fees;
        let mut all = vec![Transaction::coinbase(height, extra, vec![TxOut::new(reward, to)])];
        all.extend(txs);
        let mut b = Block {
            header: new_header(parent, [0; 64], p.timestamp + ts_offset, chain.expected_target(&parent, height)),
            txs: all,
        };
        b.header.merkle_root = b.compute_merkle_root();
        assert!(mine(&mut b.header, u64::MAX));
        b
    }

    fn now() -> u64 {
        GENESIS_TIMESTAMP + 10_000_000
    }

    /// Genesis à difficulté réduite (environ 1 essai sur 16) pour des tests rapides.
    pub fn test_genesis() -> Block {
        let mut g = genesis_block();
        let mut t = [0xFFu8; 64];
        t[0] = 0x0F;
        g.header.target = t;
        assert!(mine(&mut g.header, u64::MAX));
        g
    }

    fn test_chain() -> Chain {
        Chain::with_genesis(test_genesis())
    }

    #[test]
    fn ancienne_chaine_incompatible_mise_de_cote() {
        let dir = std::env::temp_dir().join(format!("nfr-old-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("blocks.dat");
        // Un enregistrement bien formé (longueur + octets) mais qui n'est pas un bloc v0.6.
        let mut junk = 20u32.to_be_bytes().to_vec();
        junk.extend_from_slice(&[7u8; 20]);
        std::fs::write(&p, &junk).unwrap();
        let c = Chain::open_with_genesis(&p, test_genesis()).unwrap();
        assert_eq!(c.height(), 0);
        assert_eq!(std::fs::read(dir.join("blocks.ancien")).unwrap(), junk);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn genesis_est_valide() {
        let g = genesis_block();
        assert!(g.header.meets_target(), "GENESIS_NONCE incorrect");
        assert_eq!(hex(&g.hash()), GENESIS_HASH_HEX);
        assert_eq!(g.compute_merkle_root(), g.header.merkle_root);
        assert_eq!(Chain::new().height(), 0);
    }

    #[test]
    fn chaine_qui_avance() {
        let mut c = test_chain();
        let kp = KeyPair::from_seed(&[1; 32]);
        for _ in 0..3 {
            let b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"");
            assert_eq!(c.add_block(b, now()), Ok(Added::Extended));
        }
        assert_eq!(c.height(), 3);
        assert_eq!(c.utxo.len(), 3);
    }

    #[test]
    fn recompense_trop_elevee_refusee() {
        let mut c = test_chain();
        let mut b = make_block(&c, c.tip(), vec![], [5; 32], 691, b"");
        b.txs[0].outputs[0].amount += 1;
        b.header.merkle_root = b.compute_merkle_root();
        assert!(mine(&mut b.header, u64::MAX));
        assert!(matches!(c.add_block(b, now()), Err(ChainError::Invalid(_))));
    }

    #[test]
    fn preuve_de_travail_falsifiee_refusee() {
        let mut c = test_chain();
        let mut b = make_block(&c, c.tip(), vec![], [5; 32], 691, b"");
        while b.header.meets_target() {
            b.header.nonce += 1;
        }
        assert!(matches!(c.add_block(b, now()), Err(ChainError::Invalid(_))));
    }

    #[test]
    fn cible_trop_facile_refusee() {
        let mut c = test_chain();
        let mut b = make_block(&c, c.tip(), vec![], [5; 32], 691, b"");
        b.header.target = MAX_TARGET_BE;
        assert!(mine(&mut b.header, u64::MAX));
        assert!(matches!(c.add_block(b, now()), Err(ChainError::Invalid(_))));
    }

    #[test]
    fn horodatage_futur_refuse() {
        let mut c = test_chain();
        let b = make_block(&c, c.tip(), vec![], [5; 32], 10_000, b"");
        assert_eq!(c.add_block(b, GENESIS_TIMESTAMP), Err(ChainError::FutureTime));
    }

    #[test]
    fn bloc_orphelin_signale() {
        let mut c = test_chain();
        let b = make_block(&c, c.tip(), vec![], [5; 32], 691, b"");
        let mut b2 = b.clone();
        b2.header.previous_block_hash = [7; 64];
        assert_eq!(c.add_block(b2, now()), Err(ChainError::Orphan));
    }

    /// Construit une chaîne de `n` blocs de base, puis renvoie (chaîne, clé du mineur).
    fn chain_with(n: usize, kp: &KeyPair) -> Chain {
        let mut c = test_chain();
        for _ in 0..n {
            let b = make_block(&c, c.tip(), vec![], addr(kp), 691, b"");
            c.add_block(b, now()).unwrap();
        }
        c
    }

    fn spend(c: &Chain, kp: &KeyPair, height: u64, to: Address, amount: u64, fee: u64) -> Transaction {
        let cb = &c.block_at(height).unwrap().txs[0];
        let total = cb.outputs[0].amount;
        let mut tx = Transaction::new(
            vec![TxIn::single(OutPoint { txid: cb.txid(), vout: 0 }, kp.public_key_bytes().to_vec(), vec![0; crate::signature::SIGNATURE_SIZE])],
            vec![TxOut::new(amount, to), TxOut::new(total - amount - fee, addr(kp))],
            Vec::new(),
        );
        tx.inputs[0].signature = kp.sign(&tx.sighash()).unwrap().to_vec();
        tx
    }

    #[test]
    fn depense_immature_refusee_puis_acceptee() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut c = chain_with(1, &kp);
        let tx = spend(&c, &kp, 1, [9; 32], 1_000_000, 8_000);
        let b = make_block(&c, c.tip(), vec![tx.clone()], addr(&kp), 691, b"");
        assert!(matches!(c.add_block(b, now()), Err(ChainError::Invalid(_))));

        while c.height() < 1 + COINBASE_MATURITY - 1 {
            let b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"");
            c.add_block(b, now()).unwrap();
        }
        let b = make_block(&c, c.tip(), vec![tx], addr(&kp), 691, b"");
        assert_eq!(c.add_block(b, now()), Ok(Added::Extended));
    }

    #[test]
    fn double_depense_refusee_et_vol_refuse() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let thief = KeyPair::from_seed(&[2; 32]);
        let mut c = chain_with(COINBASE_MATURITY as usize + 1, &kp);
        let tx1 = spend(&c, &kp, 1, [9; 32], 1_000_000, 8_000);
        let tx2 = spend(&c, &kp, 1, [8; 32], 2_000_000, 8_000);
        let b = make_block(&c, c.tip(), vec![tx1.clone(), tx2], addr(&kp), 691, b"");
        assert!(matches!(c.add_block(b, now()), Err(ChainError::Invalid(_))));

        // Un voleur signe avec sa propre clé : l'adresse ne correspond pas.
        let stolen = spend(&c, &thief, 1, addr(&thief), 1_000_000, 8_000);
        let b = make_block(&c, c.tip(), vec![stolen], addr(&kp), 691, b"");
        assert!(matches!(c.add_block(b, now()), Err(ChainError::Invalid(_))));

        let b = make_block(&c, c.tip(), vec![tx1], addr(&kp), 691, b"");
        assert_eq!(c.add_block(b, now()), Ok(Added::Extended));
    }

    #[test]
    fn reorganisation_courte_acceptee() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut c = chain_with(5, &kp);
        let fork = c.active[3];
        let mut parent = fork;
        let mut c2 = test_chain();
        for h in 1..=3 {
            c2.add_block(c.block_at(h).unwrap().clone(), now()).unwrap();
        }
        for i in 0..3 {
            let b = make_block(&c2, parent, vec![], [3; 32], 691, b"attaquant");
            parent = b.hash();
            c2.add_block(b.clone(), now()).unwrap();
            let r = c.add_block(b, now());
            if i < 2 {
                assert_eq!(r, Ok(Added::SideChain));
            } else {
                assert_eq!(r, Ok(Added::Reorganized { depth: 2 }));
            }
        }
        assert_eq!(c.height(), 6);
    }

    #[test]
    fn reorganisation_profonde_refusee() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let depth = MAX_REORG_DEPTH as usize + 1;
        let mut c = chain_with(depth, &kp);
        let honest_tip = c.tip();
        // L'attaquant prépare en secret une chaîne plus longue depuis le genesis.
        let mut attacker = test_chain();
        let mut results = Vec::new();
        for _ in 0..depth + 2 {
            let b = make_block(&attacker, attacker.tip(), vec![], [3; 32], 691, b"attaquant");
            attacker.add_block(b.clone(), now()).unwrap();
            results.push(c.add_block(b, now()));
        }
        // Le premier bloc de l'attaquant part de trop loin : refusé d'emblée (v1.0.0), donc les suivants
        // n'ont plus de parent connu. Aucune réorganisation n'a lieu.
        assert!(matches!(results[0], Err(ChainError::ReorgTooDeep { .. })));
        assert!(results.iter().all(|r| matches!(r, Err(ChainError::ReorgTooDeep { .. }) | Err(ChainError::Orphan))));
        assert_eq!(c.tip(), honest_tip);
    }

    #[test]
    fn ajustement_de_difficulte() {
        let t = GENESIS_TARGET_BE;
        assert_eq!(retarget(&t, EXPECTED_TIMESPAN), t);
        assert!(target_to_int(&retarget(&t, EXPECTED_TIMESPAN / 2)) < target_to_int(&t));
        assert!(target_to_int(&retarget(&t, EXPECTED_TIMESPAN * 2)) > target_to_int(&t));
        // Bornes : au plus x4 ou /4 par fenêtre.
        assert_eq!(retarget(&t, 1), retarget(&t, EXPECTED_TIMESPAN / 4));
        assert_eq!(retarget(&MAX_TARGET_BE, u64::MAX), MAX_TARGET_BE);
    }

    #[test]
    fn rechargement_depuis_le_disque() {
        let dir = std::env::temp_dir().join(format!("nfr-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocks.dat");
        let _ = std::fs::remove_file(&path);
        let kp = KeyPair::from_seed(&[1; 32]);
        let tip;
        {
            let mut c = Chain::open_with_genesis(&path, test_genesis()).unwrap();
            for _ in 0..4 {
                let b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"");
                c.add_block(b, now()).unwrap();
            }
            tip = c.tip();
        }
        let c = Chain::open_with_genesis(&path, test_genesis()).unwrap();
        assert_eq!(c.tip(), tip);
        assert_eq!(c.utxo.len(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Remplace l'ensemble UTXO par une reconstruction complète depuis le genesis et compare.
    fn utxo_rejoue(c: &mut Chain) -> HashMap<OutPoint, UtxoEntry> {
        let before = c.utxo.clone();
        c.rebuild_utxo(c.height());
        let rebuilt = c.utxo.clone();
        c.utxo = before;
        rebuilt
    }

    #[test]
    fn annulation_exacte_meme_avec_depense_dans_le_meme_bloc() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let c = chain_with(COINBASE_MATURITY as usize + 1, &kp);
        // tx1 dépense la récompense du bloc 1 ; tx2 dépense une sortie de tx1 dans le même bloc.
        let tx1 = spend(&c, &kp, 1, addr(&kp), 300_000_000, 8_000);
        let mut tx2 = Transaction::new(
            vec![TxIn::single(OutPoint { txid: tx1.txid(), vout: 0 }, kp.public_key_bytes().to_vec(), vec![0; crate::signature::SIGNATURE_SIZE])],
            vec![TxOut::new(300_000_000 - 8_000, [3; 32])],
            Vec::new(),
        );
        tx2.inputs[0].signature = kp.sign(&tx2.sighash()).unwrap().to_vec();
        let b = make_block(&c, c.tip(), vec![tx1, tx2], addr(&kp), 691, b"");
        let mut utxo = c.utxo.clone();
        let mut names = c.names.clone();
        let mtp = c.next_mtp();
        let log = connect_block(&mut utxo, &mut names, &b, c.height() + 1, mtp).unwrap();
        assert_ne!(utxo, c.utxo);
        undo_ops(&mut utxo, &mut names, log);
        assert_eq!(utxo, c.utxo);
        assert_eq!(names, c.names);
    }

    #[test]
    fn stockage_disque_reorganisation_et_fin_tronquee() {
        let dir = std::env::temp_dir().join(format!("nfr-disque-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocks.dat");
        let _ = std::fs::remove_file(&path);
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut c = Chain::open_with_genesis(&path, test_genesis()).unwrap();
        for _ in 0..6 {
            let b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"");
            c.add_block(b, now()).unwrap();
        }
        // Les blocs ne sont plus gardés en mémoire, mais relus depuis le disque.
        assert_eq!(c.mem.len(), 1);
        assert_eq!(c.block_at(4).unwrap().hash(), c.active[4]);

        // Branche concurrente plus longue partant du bloc 3 : réorganisation de 3 blocs.
        let mut parent = c.active[3];
        for i in 0..4u8 {
            let b = make_block(&c, parent, vec![], [3; 32], 691, &[b'b', i]);
            parent = b.hash();
            let _ = c.add_block(b, now());
        }
        assert_eq!(c.tip(), parent);
        assert_eq!(c.height(), 7);
        let rejoue = utxo_rejoue(&mut c);
        assert_eq!(c.utxo, rejoue);
        let tip = c.tip();
        let utxo = c.utxo.clone();
        drop(c);

        // Rechargement : même sommet, même ensemble UTXO.
        let c = Chain::open_with_genesis(&path, test_genesis()).unwrap();
        assert_eq!(c.tip(), tip);
        assert_eq!(c.utxo, utxo);
        drop(c);

        // Coupure de courant au milieu d'une écriture : la fin abîmée est retirée.
        let len = std::fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 10).unwrap();
        drop(f);
        let mut c = Chain::open_with_genesis(&path, test_genesis()).unwrap();
        assert_eq!(c.height(), 6);
        let b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"apres");
        c.add_block(b, now()).unwrap();
        let tip = c.tip();
        drop(c);
        let c = Chain::open_with_genesis(&path, test_genesis()).unwrap();
        assert_eq!(c.tip(), tip);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verrou_par_date_et_par_hauteur() {
        use crate::tx::is_unlocked;
        assert!(is_unlocked(0, 1, 0));
        assert!(!is_unlocked(10, 9, u64::MAX));
        assert!(is_unlocked(10, 10, 0));
        let date = 1_800_000_000u32;
        assert!(!is_unlocked(date, u64::MAX, date as u64 - 1));
        assert!(is_unlocked(date, 0, date as u64));
    }

    // ---------- Nouvelles règles : paiement retenu, multi-signature, pseudos ----------

    /// Chaîne dont les récompenses du mineur `kp` sont mûres, et la position de la 1re.
    fn mature(kp: &KeyPair) -> Chain {
        chain_with(COINBASE_MATURITY as usize + 3, kp)
    }

    /// Transaction signée par `kp` qui dépense la récompense du bloc `height` vers `outputs`.
    fn spend_to(c: &Chain, kp: &KeyPair, height: u64, outputs: Vec<TxOut>) -> Transaction {
        let cb = &c.block_at(height).unwrap().txs[0];
        let mut tx = Transaction::new(
            vec![TxIn::single(OutPoint { txid: cb.txid(), vout: 0 }, kp.public_key_bytes().to_vec(), vec![0; crate::signature::SIGNATURE_SIZE])],
            outputs,
            Vec::new(),
        );
        tx.inputs[0].signature = kp.sign(&tx.sighash()).unwrap().to_vec();
        tx
    }

    fn mine_with(c: &mut Chain, txs: Vec<Transaction>, to: Address) -> Result<Added, ChainError> {
        let b = make_block_fees(c, txs, to);
        c.add_block(b, now())
    }

    /// Comme make_block, mais la coinbase réclame aussi les frais des transactions.
    fn make_block_fees(c: &Chain, txs: Vec<Transaction>, to: Address) -> Block {
        let height = c.height() + 1;
        let mut fees = 0u64;
        for t in &txs {
            fees += check_tx_inputs(&c.utxo, t, height, c.next_mtp()).unwrap();
        }
        let reward = block_reward(height, total_before(height)) + fees;
        let mut all = vec![Transaction::coinbase(height, b"", vec![TxOut::new(reward, to)])];
        all.extend(txs);
        let parent = c.tip();
        let p = c.header(&parent).unwrap().clone();
        let mut b = Block { header: new_header(parent, [0; 64], p.timestamp + 691, c.expected_target(&parent, height)), txs: all };
        b.header.merkle_root = b.compute_merkle_root();
        assert!(mine(&mut b.header, u64::MAX));
        b
    }

    /// v1.4.0 : une chaîne cachée révélée d'un coup est mise de côté, puis acceptée après PENALITE_DUREE.
    #[test]
    fn chaine_cachee_penalisee_puis_acceptee() {
        let honnete = KeyPair::from_seed(&[11; 32]);
        let pirate = KeyPair::from_seed(&[12; 32]);
        let mut c = test_chain();
        c.min_work_reorg = BigUint::from(0u8); // chaîne « synchronisée » dès le départ
        let base = c.tip();
        // Le pirate mine 5 blocs en secret à partir de `base` (gardés hors de la chaîne).
        let mut cachee = Chain::with_genesis(test_genesis());
        let mut secrets = Vec::new();
        for _ in 0..5 {
            let b = make_block(&cachee, cachee.tip(), vec![], addr(&pirate), 691, b"p");
            cachee.add_block(b.clone(), now()).unwrap();
            secrets.push(b);
        }
        // Pendant ce temps, le réseau honnête reçoit 4 blocs, un toutes les 691 s.
        let t0 = now();
        for i in 0..4u64 {
            let b = make_block(&c, c.tip(), vec![], addr(&honnete), 691, b"h");
            c.add_block(b, t0 + i * 691).unwrap();
        }
        let tip_honnete = c.tip();
        assert_eq!(base, c.hash_at(0).unwrap());
        // Révélation : 5 blocs d'un coup. Plus de travail (5 > 4), mais 4 blocs de retard : mis de côté.
        let t1 = t0 + 4 * 691;
        let mut dernier = None;
        for b in &secrets {
            dernier = Some(c.add_block(b.clone(), t1));
        }
        assert_eq!(dernier.unwrap(), Ok(Added::Penalisee { retard: 4 }));
        assert_eq!(c.tip(), tip_honnete);
        // Deux heures plus tard, la branche (toujours plus lourde) qui continue est acceptée normalement.
        let b = make_block(&cachee, cachee.tip(), vec![], addr(&pirate), 691, b"p");
        cachee.add_block(b.clone(), now()).unwrap();
        assert!(matches!(c.add_block(b, t1 + PENALITE_DUREE + 1), Ok(Added::Reorganized { .. })));
    }

    /// v1.4.0 : un bloc honnête concurrent arrivé une minute après n'est pas pénalisé (moins de PENALITE_MIN blocs).
    #[test]
    fn concurrence_honnete_non_penalisee() {
        let a = KeyPair::from_seed(&[13; 32]);
        let b_ = KeyPair::from_seed(&[14; 32]);
        let mut c = test_chain();
        c.min_work_reorg = BigUint::from(0u8);
        let parent = c.tip();
        let x = make_block(&c, parent, vec![], addr(&a), 691, b"x");
        let y = make_block(&c, parent, vec![], addr(&b_), 691, b"y");
        c.add_block(x, now()).unwrap();
        assert_eq!(c.add_block(y.clone(), now() + 60), Ok(Added::SideChain));
        let z = make_block(&c, y.hash(), vec![], addr(&b_), 691, b"z");
        assert!(matches!(c.add_block(z, now() + 120), Ok(Added::Reorganized { .. })));
    }

    /// Règles v1.3.0 : l'annulation revient à l'expéditeur, frais de pseudo détruits.
    #[test]
    fn regles_v130_gardien_et_pseudos() {
        let sender = KeyPair::from_seed(&[1; 32]);
        let friend = KeyPair::from_seed(&[2; 32]);
        let guardian = KeyPair::from_seed(&[4; 32]);
        let mut c = mature(&sender);
        let unlock = (V2_RULES_MTP + 1_000_000) as u32;
        let total = c.block_at(1).unwrap().txs[0].outputs[0].amount;
        let tx = spend_to(&c, &sender, 1, vec![TxOut::retained(total - 8_000, addr(&friend), unlock, addr(&guardian))]);
        assert_eq!(mine_with(&mut c, vec![tx.clone()], addr(&sender)), Ok(Added::Extended));
        let op = OutPoint { txid: tx.txid(), vout: 0 };
        assert_eq!(c.utxo[&op].refund, Some(addr(&sender)));
        let reclaim = |to: Address| {
            let mut t = Transaction::new(
                vec![TxIn::single(op, guardian.public_key_bytes().to_vec(), vec![0; crate::signature::SIGNATURE_SIZE])],
                vec![TxOut::new(total - 20_000, to)],
                Vec::new(),
            );
            t.inputs[0].signature = guardian.sign(&t.sighash()).unwrap().to_vec();
            t
        };
        let h = c.height() + 1;
        // Avant l'activation : le gardien peut encore envoyer ailleurs.
        assert!(check_tx_inputs(&c.utxo, &reclaim(addr(&guardian)), h, c.next_mtp()).is_ok());
        // Après : seulement vers l'expéditeur.
        assert!(check_tx_inputs(&c.utxo, &reclaim(addr(&guardian)), h, V2_RULES_MTP).unwrap_err().contains("revenir"));
        assert!(check_tx_inputs(&c.utxo, &reclaim(addr(&sender)), h, V2_RULES_MTP).is_ok());
        // Frais de pseudo détruits seulement après l'activation.
        let mut t = reclaim(addr(&sender));
        t.name_op = Some(crate::tx::NameOp { kind: NameKind::Register, name: "abc".into(), owner: addr(&sender) });
        assert_eq!(burned_fees(std::slice::from_ref(&t), V2_RULES_MTP - 1), 0);
        assert_eq!(burned_fees(std::slice::from_ref(&t), V2_RULES_MTP), name_fee(3));
    }

    /// Points de contrôle : bloc contraire refusé, et plus d'embranchement avant le dernier.
    #[test]
    fn points_de_controle() {
        let kp = KeyPair::from_seed(&[5; 32]);
        let mut c = chain_with(5, &kp);
        let h3 = c.hash_at(3).unwrap();
        c.points = vec![(3, hex(&h3))];
        // Embranchement à la hauteur 2 (avant le point de contrôle) : refusé sans même être vérifié.
        let b = make_block(&c, c.hash_at(1).unwrap(), vec![], addr(&kp), 999, b"fourche");
        assert!(matches!(c.add_block(b, now()), Err(ChainError::KnownBad(e)) if e.contains("point de contrôle")));
        // Une chaîne neuve avec un autre bloc n°3 que celui du point de contrôle : refusé.
        let mut d = chain_with(2, &kp);
        d.points = vec![(3, hex(&h3))];
        let b = make_block(&d, d.tip(), vec![], addr(&kp), 999, b"autre");
        assert!(matches!(d.add_block(b, now()), Err(ChainError::Invalid(e)) if e.contains("point de contrôle")));
    }

    #[test]
    fn paiement_retenu_annulable_puis_definitif() {
        let sender = KeyPair::from_seed(&[1; 32]);
        let friend = KeyPair::from_seed(&[2; 32]);
        let mut c = mature(&sender);
        let unlock = (c.next_mtp() + 4 * 691) as u32; // quelques blocs plus tard
        let total = c.block_at(1).unwrap().txs[0].outputs[0].amount;
        let retained = TxOut::retained(total - 8_000, addr(&friend), unlock, addr(&sender));
        let tx = spend_to(&c, &sender, 1, vec![retained]);
        assert_eq!(mine_with(&mut c, vec![tx.clone()], addr(&sender)), Ok(Added::Extended));
        let op = OutPoint { txid: tx.txid(), vout: 0 };
        assert_eq!(c.utxo[&op].cancel, Some(addr(&sender)));

        let reclaim = |signer: &KeyPair, to: Address| {
            let mut t = Transaction::new(
                vec![TxIn::single(op, signer.public_key_bytes().to_vec(), vec![0; crate::signature::SIGNATURE_SIZE])],
                vec![TxOut::new(total - 20_000, to)],
                Vec::new(),
            );
            t.inputs[0].signature = signer.sign(&t.sighash()).unwrap().to_vec();
            t
        };
        let mtp = c.next_mtp();
        // Avant la date : le destinataire ne peut PAS dépenser, l'expéditeur peut reprendre.
        assert!(check_tx_inputs(&c.utxo, &reclaim(&friend, addr(&friend)), c.height() + 1, mtp).is_err());
        assert!(check_tx_inputs(&c.utxo, &reclaim(&sender, addr(&sender)), c.height() + 1, mtp).is_ok());
        // Un tiers ne peut ni dépenser ni annuler.
        let thief = KeyPair::from_seed(&[3; 32]);
        assert!(check_tx_inputs(&c.utxo, &reclaim(&thief, addr(&thief)), c.height() + 1, mtp).is_err());
        // Après la date : seul le destinataire peut dépenser ; l'annulation n'est plus possible.
        let later = unlock as u64;
        assert!(check_tx_inputs(&c.utxo, &reclaim(&friend, addr(&friend)), c.height() + 1, later).is_ok());
        assert!(check_tx_inputs(&c.utxo, &reclaim(&sender, addr(&sender)), c.height() + 1, later).is_err());

        // L'annulation passe bien dans un bloc, et annuler le bloc remet la sortie en place.
        let cancel = reclaim(&sender, addr(&sender));
        let before = c.utxo.clone();
        assert_eq!(mine_with(&mut c, vec![cancel], addr(&sender)), Ok(Added::Extended));
        assert!(!c.utxo.contains_key(&op));
        let mut u2 = c.utxo.clone();
        let mut n2 = c.names.clone();
        let log = c.undo.get(&c.tip()).unwrap().clone();
        undo_ops(&mut u2, &mut n2, log);
        assert_eq!(u2, before);
    }

    #[test]
    fn multisignature_depense_2_sur_3_dans_un_bloc() {
        let miner = KeyPair::from_seed(&[1; 32]);
        let a = KeyPair::from_seed(&[11; 32]);
        let b = KeyPair::from_seed(&[12; 32]);
        let d = KeyPair::from_seed(&[13; 32]);
        let members = normalize_members(2, &[addr(&a), addr(&b), addr(&d)]).unwrap();
        let group = multisig_address(2, &members);
        let mut c = mature(&miner);
        let total = c.block_at(1).unwrap().txs[0].outputs[0].amount;
        let fund = spend_to(&c, &miner, 1, vec![TxOut::new(total - 8_000, group)]);
        assert_eq!(mine_with(&mut c, vec![fund.clone()], addr(&miner)), Ok(Added::Extended));
        let op = OutPoint { txid: fund.txid(), vout: 0 };

        let build = |signers: &[&KeyPair]| {
            let mut t = Transaction::new(vec![TxIn::multisig(op, 2, members.clone())], vec![TxOut::new(total - 8_000 - 20_000, [5; 32])], Vec::new());
            let sh = t.sighash();
            let mut sigs: Vec<PartialSig> = signers
                .iter()
                .map(|k| PartialSig {
                    index: members.iter().position(|m| *m == addr(k)).unwrap() as u8,
                    pubkey: k.public_key_bytes().to_vec(),
                    signature: k.sign(&sh).unwrap().to_vec(),
                })
                .collect();
            sigs.sort_by_key(|s| s.index);
            t.inputs[0].multi.as_mut().unwrap().sigs = sigs;
            t
        };
        // Deux membres sur trois : accepté, y compris par le consensus.
        let ok = build(&[&a, &d]);
        ok.check_stateless().unwrap();
        assert!(check_tx_inputs(&c.utxo, &ok, c.height() + 1, c.next_mtp()).is_ok());
        // Un seul membre : refusé. Un groupe différent : l'adresse ne correspond pas.
        assert!(build(&[&a]).check_stateless().is_err());
        let mut wrong = build(&[&a, &b]);
        let other = normalize_members(2, &[addr(&a), addr(&b), [7; 32]]).unwrap();
        wrong.inputs[0].multi.as_mut().unwrap().members = other;
        assert!(check_tx_inputs(&c.utxo, &wrong, c.height() + 1, c.next_mtp()).is_err());
        // Un compte simple ne peut pas dépenser les fonds du groupe.
        let thief = spend_like(&c, &a, op, total - 8_000);
        assert!(check_tx_inputs(&c.utxo, &thief, c.height() + 1, c.next_mtp()).is_err());
        assert_eq!(mine_with(&mut c, vec![ok], addr(&miner)), Ok(Added::Extended));
        assert!(!c.utxo.contains_key(&op));
    }

    fn spend_like(_c: &Chain, kp: &KeyPair, op: OutPoint, amount: u64) -> Transaction {
        let mut t = Transaction::new(
            vec![TxIn::single(op, kp.public_key_bytes().to_vec(), vec![0; crate::signature::SIGNATURE_SIZE])],
            vec![TxOut::new(amount - 20_000, [5; 32])],
            Vec::new(),
        );
        t.inputs[0].signature = kp.sign(&t.sighash()).unwrap().to_vec();
        t
    }

    /// Transaction signée par `kp` qui dépense la sortie `op` (valeur `total`) en y joignant une opération de pseudo.
    fn name_tx(kp: &KeyPair, op: OutPoint, total: u64, nop: NameOp, fee: u64) -> Transaction {
        let mut t = Transaction::new(
            vec![TxIn::single(op, kp.public_key_bytes().to_vec(), vec![0; crate::signature::SIGNATURE_SIZE])],
            vec![TxOut::new(total - fee, addr(kp))],
            Vec::new(),
        );
        t.name_op = Some(nop);
        t.inputs[0].signature = kp.sign(&t.sighash()).unwrap().to_vec();
        t
    }

    #[test]
    fn pseudos_enregistrement_transfert_et_annulation() {
        use crate::tx::NameKind;
        let kp = KeyPair::from_seed(&[1; 32]);
        let other = KeyPair::from_seed(&[2; 32]);
        let mut c = mature(&kp);
        let cb_total = |c: &Chain, h: u64| c.block_at(h).unwrap().txs[0].outputs[0].amount;
        let cb_op = |c: &Chain, h: u64| OutPoint { txid: c.block_at(h).unwrap().txs[0].txid(), vout: 0 };
        let fee_ok = min_fee(7_500) + name_fee(7) + 5_000;
        let reg_op = |owner: Address| NameOp { kind: NameKind::Register, name: "alice".into(), owner };

        // `other` reçoit des fonds ordinaires (utilisables tout de suite).
        let fund = spend_to(&c, &kp, 3, vec![TxOut::new(cb_total(&c, 3) - 8_000, addr(&other))]);
        let other_op = OutPoint { txid: fund.txid(), vout: 0 };
        let other_total = cb_total(&c, 3) - 8_000;
        assert_eq!(mine_with(&mut c, vec![fund], addr(&kp)), Ok(Added::Extended));

        // Frais trop faibles pour un pseudo de 7 lettres : refusé.
        let cheap = name_tx(&kp, cb_op(&c, 1), cb_total(&c, 1), reg_op(addr(&kp)), 10_000);
        assert!(mine_with_result(&mut c, cheap).is_err());
        // Avec les frais : enregistré.
        let reg = name_tx(&kp, cb_op(&c, 1), cb_total(&c, 1), reg_op(addr(&kp)), fee_ok);
        assert_eq!(mine_with(&mut c, vec![reg], addr(&kp)), Ok(Added::Extended));
        assert_eq!(c.names["alice"].owner, addr(&kp));
        let first_height = c.names["alice"].height;

        // Le même pseudo ne peut pas être pris une seconde fois.
        let dup = name_tx(&kp, cb_op(&c, 2), cb_total(&c, 2), reg_op(addr(&other)), fee_ok);
        assert!(mine_with_result(&mut c, dup).is_err());

        // Un autre compte (avec ses propres fonds) ne peut pas transférer le pseudo ; le propriétaire le peut.
        let steal = name_tx(&other, other_op, other_total, NameOp { kind: NameKind::Update, name: "alice".into(), owner: addr(&other) }, 8_000);
        assert!(mine_with_result(&mut c, steal).is_err());
        assert_eq!(c.names["alice"].owner, addr(&kp));
        let give = name_tx(&kp, cb_op(&c, 2), cb_total(&c, 2), NameOp { kind: NameKind::Update, name: "alice".into(), owner: addr(&other) }, 8_000);
        assert_eq!(mine_with(&mut c, vec![give], addr(&kp)), Ok(Added::Extended));
        assert_eq!(c.names["alice"].owner, addr(&other));
        assert_eq!(c.names["alice"].height, first_height);

        // Annuler le dernier bloc restaure l'ancien propriétaire ; une reconstruction complète retrouve l'état actuel.
        let mut u = c.utxo.clone();
        let mut n = c.names.clone();
        let log = c.undo.get(&c.tip()).unwrap().clone();
        undo_ops(&mut u, &mut n, log);
        assert_eq!(n["alice"].owner, addr(&kp));
        let live = c.names.clone();
        c.rebuild_utxo(c.height());
        assert_eq!(c.names, live);
    }

    fn mine_with_result(c: &mut Chain, tx: Transaction) -> Result<Added, ChainError> {
        // Bloc fabriqué sans contrôle de frais préalable, pour tester le refus du consensus.
        let height = c.height() + 1;
        let fee = check_tx_inputs(&c.utxo, &tx, height, c.next_mtp()).unwrap_or(0);
        let reward = block_reward(height, total_before(height)) + fee;
        let parent = c.tip();
        let p = c.header(&parent).unwrap().clone();
        let mut b = Block {
            header: new_header(parent, [0; 64], p.timestamp + 691, c.expected_target(&parent, height)),
            txs: vec![Transaction::coinbase(height, b"", vec![TxOut::new(reward, [0; 32])]), tx],
        };
        b.header.merkle_root = b.compute_merkle_root();
        assert!(mine(&mut b.header, u64::MAX));
        c.add_block(b, now())
    }
}

/// Tests des corrections de l'audit de sécurité (v1.0.0).
#[cfg(test)]
mod tests_audit {
    use super::tests::*;
    use super::*;
    use crate::signature::KeyPair;
    use crate::tx::{OutPoint, TxIn};

    const NOW: u64 = GENESIS_TIMESTAMP + 10_000_000;

    /// E3 : une branche qui ne pourra jamais gagner (trop ancienne) n'est plus enregistrée.
    #[test]
    fn branche_morte_refusee_avant_enregistrement() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut c = Chain::with_genesis(test_genesis());
        for _ in 0..(MAX_REORG_DEPTH + 3) {
            let b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"");
            c.add_block(b, NOW).unwrap();
        }
        let g = c.hash_at(0).unwrap();
        let before = c.mem.len();
        for i in 0..20u8 {
            let b = make_block(&c, g, vec![], [3; 32], 691, &[b'x', i]);
            assert!(matches!(c.add_block(b, NOW), Err(ChainError::ReorgTooDeep { .. })));
        }
        assert_eq!(c.mem.len(), before, "aucun bloc mort ne doit être stocké");
        // Une fourche récente (qui peut encore gagner) reste acceptée, comme dans Bitcoin.
        let recent = c.hash_at(c.height() - 2).unwrap();
        let b = make_block(&c, recent, vec![], [4; 32], 691, b"r");
        assert_eq!(c.add_block(b, NOW), Ok(Added::SideChain));
    }

    /// E2 : une transaction qui dépense des pièces inexistantes est refusée AVANT la vérification
    /// (coûteuse) des signatures.
    #[test]
    fn fausse_transaction_refusee_sans_verifier_les_signatures() {
        let kp = KeyPair::from_seed(&[9; 32]);
        // 300 entrées inexistantes, avec des signatures bidon (qui échoueraient si elles étaient vérifiées).
        let tx = Transaction::new(
            (0..300u32)
                .map(|i| TxIn::single(OutPoint { txid: [7; 64], vout: i }, kp.public_key_bytes().to_vec(), vec![1; crate::signature::SIGNATURE_SIZE]))
                .collect(),
            vec![TxOut::new(1, [1; 32])],
            Vec::new(),
        );
        let c = Chain::with_genesis(test_genesis());
        let mut mp = crate::mempool::Mempool::default();
        let t = std::time::Instant::now();
        assert_eq!(mp.accept(tx, &c), Err("entrée inexistante".to_string()));
        assert!(t.elapsed() < std::time::Duration::from_millis(100), "refus trop lent : {:?}", t.elapsed());
    }

    /// M1 : la règle anti time warp.
    #[test]
    fn regle_anti_time_warp() {
        let w = DIFFICULTY_WINDOW;
        // Premier bloc d'une fenêtre daté 3 h avant son parent : refusé.
        assert!(is_time_warp(w, 1_000_000, 1_000_000 + 3 * 3_600));
        // Daté 1 h avant : toléré (horloges imparfaites), comme dans Bitcoin (2 h).
        assert!(!is_time_warp(w, 1_000_000, 1_000_000 + 3_600));
        // Au milieu d'une fenêtre, seule la règle du temps médian s'applique.
        assert!(!is_time_warp(w + 1, 1_000_000, 1_000_000 + 3 * 3_600));
    }

    /// F4 : le champ locktime doit valoir 0 (file d'attente toujours, blocs après l'activation).
    #[test]
    fn locktime_reserve() {
        let kp = KeyPair::from_seed(&[2; 32]);
        // Avant l'activation : un bloc dont la coinbase a un locktime non nul reste valide (passé inchangé).
        let mut c = Chain::with_genesis(test_genesis());
        let mut b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"");
        b.txs[0].locktime = 5;
        b.header.merkle_root = b.compute_merkle_root();
        assert!(crate::block::mine(&mut b.header, u64::MAX));
        assert_eq!(c.add_block(b, NOW), Ok(Added::Extended));
        // On avance l'horloge de la chaîne au-delà de la date d'activation.
        for _ in 0..8 {
            let b = make_block(&c, c.tip(), vec![], addr(&kp), 200_000, b"");
            c.add_block(b, NOW).unwrap();
        }
        assert!(c.next_mtp() >= V1_RULES_MTP);
        let mut b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"l");
        b.txs[0].locktime = 5;
        b.header.merkle_root = b.compute_merkle_root();
        assert!(crate::block::mine(&mut b.header, u64::MAX));
        assert!(matches!(c.add_block(b, NOW), Err(ChainError::Invalid(e)) if e.contains("locktime")));
        // La file d'attente refuse toujours un locktime non nul.
        let mut tx = Transaction::new(
            vec![TxIn::single(OutPoint { txid: [7; 64], vout: 0 }, kp.public_key_bytes().to_vec(), vec![1; crate::signature::SIGNATURE_SIZE])],
            vec![TxOut::new(1, [1; 32])],
            Vec::new(),
        );
        tx.locktime = 1;
        let mut mp = crate::mempool::Mempool::default();
        assert!(mp.accept(tx, &c).unwrap_err().contains("locktime"));
    }

    /// Règles v1.3.0 : pas de pièce minuscule dans un bloc après l'activation.
    #[test]
    fn poussiere_refusee_dans_les_blocs() {
        let kp = KeyPair::from_seed(&[6; 32]);
        let mut c = Chain::with_genesis(test_genesis());
        while c.next_mtp() < V2_RULES_MTP {
            let b = make_block(&c, c.tip(), vec![], addr(&kp), 300_000, b"");
            c.add_block(b, u64::MAX / 4).unwrap();
        }
        let mut tx = Transaction::new(
            vec![TxIn::single(OutPoint { txid: [7; 64], vout: 0 }, kp.public_key_bytes().to_vec(), vec![1; crate::signature::SIGNATURE_SIZE])],
            vec![TxOut::new(DUST - 1, [1; 32])],
            Vec::new(),
        );
        tx.inputs[0].signature = kp.sign(&tx.sighash()).unwrap().to_vec();
        let mut b = make_block(&c, c.tip(), vec![tx], addr(&kp), 691, b"p");
        b.header.merkle_root = b.compute_merkle_root();
        assert!(crate::block::mine(&mut b.header, u64::MAX));
        assert!(matches!(c.add_block(b, u64::MAX / 4), Err(ChainError::Invalid(e)) if e.contains("0,0001")));
    }

    /// E1 : la réponse à une demande de blocs est une liste légère de hashes, limitée en nombre.
    #[test]
    fn inventaire_limite() {
        let kp = KeyPair::from_seed(&[3; 32]);
        let mut c = Chain::with_genesis(test_genesis());
        for _ in 0..12 {
            let b = make_block(&c, c.tip(), vec![], addr(&kp), 691, b"");
            c.add_block(b, NOW).unwrap();
        }
        let loc = vec![c.hash_at(0).unwrap()];
        assert_eq!(c.hashes_after(&loc, 5).len(), 5);
        assert_eq!(c.hashes_after(&loc, 500).len(), 12);
        assert_eq!(c.hashes_after(&loc, 500)[0], c.hash_at(1).unwrap());
    }
}
