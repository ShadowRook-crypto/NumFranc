//! Portefeuille déterministe : toutes les clés ML-DSA-87 sont dérivées d'une
//! seule graine secrète de 32 octets.
//!
//! Fichier wallet.dat (format NFRWAL03), deux sections chiffrées deux fois (voir vault.rs) :
//! - la « vue » (adresses, carnet), ouverte par le MOT DE PASSE D'OUVERTURE : voir le solde, miner, recevoir ;
//! - le « coffre » (la graine), ouvert par le CODE DE DÉPENSE : uniquement le temps de signer un envoi.
//! Une réserve de 1 000 adresses est calculée à l'avance : miner et recevoir ne demandent jamais la graine.
//! Le code de secours est remis en 3 morceaux (2 suffisent).
//!
//! Règles :
//! - une adresse principale permanente sert à tout recevoir (ML-DSA est sans état :
//!   réutiliser une clé après une signature ne l'affaiblit pas) ;
//! - chaque récompense de minage arrive sur une adresse neuve ;
//! - la monnaie rendue part vers une adresse neuve.

use crate::chain::Chain;
use crate::config::{COINBASE_MATURITY, MAX_MEMO, MIN_UNIT};
use crate::encoding::{from_hex, Reader};
use crate::hashing::{hash512, sha3_512};
use crate::vault::{self, KdfParams, Sealed};
use zeroize::Zeroizing;
use crate::mempool::Mempool;
use crate::signature::KeyPair;
use crate::tx::{address_of_pubkey, is_unlocked, Address, Transaction, TxOut};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Format actuel : la section « coffre » est facultative (portefeuille gelé).
pub(crate) const FILE_MAGIC: &[u8; 8] = b"NFRWAL04";
/// Format de la v0.4 / v0.5 : toujours lisible.
const FILE_MAGIC_V3: &[u8; 8] = b"NFRWAL03";
const LEGACY_MAGIC: &[u8; 8] = b"NFRWAL02";
/// Nombre d'adresses calculées à l'avance (réutilisées en boucle au-delà).
pub const POOL_SIZE: usize = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub name: String,
    pub address: Address,
}

/// État du fichier portefeuille sur le disque.
#[derive(Debug, PartialEq, Eq)]
pub enum WalletFile {
    Missing,
    Encrypted,
    /// Ancien portefeuille non chiffré (v0.2 / v0.3) : à protéger par des mots de passe.
    Legacy,
    Unknown,
}

pub fn file_status(path: &Path) -> WalletFile {
    match std::fs::read(path) {
        Err(_) => WalletFile::Missing,
        Ok(d) if d.starts_with(FILE_MAGIC) || d.starts_with(FILE_MAGIC_V3) => WalletFile::Encrypted,
        Ok(d) if d.starts_with(LEGACY_MAGIC) => WalletFile::Legacy,
        Ok(_) => WalletFile::Unknown,
    }
}

/// Protection des gros paiements : au-dessus de `threshold`, le paiement est retenu `delay_secs`
/// secondes pendant lesquelles on peut l'annuler. `guardian` : adresse d'un autre portefeuille
/// (ou d'un groupe) qui peut aussi annuler ; sans gardien, l'adresse principale de ce portefeuille.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protection {
    pub threshold: u64,
    pub delay_secs: u64,
    pub guardian: Option<Address>,
}

/// Groupe multi-signature mémorisé dans le portefeuille (M signatures parmi les membres).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub m: u8,
    /// Adresses des membres, triées.
    pub members: Vec<Address>,
}

impl Group {
    pub fn address(&self) -> Address {
        crate::tx::multisig_address(self.m, &self.members)
    }
}

pub struct Wallet {
    /// Graine en clair : seulement pour les portefeuilles de test et pendant une migration.
    pub(crate) seed: Option<Zeroizing<[u8; 32]>>,
    pub(crate) keys: Vec<(Address, bool)>, // (adresse, clé publique révélée)
    pub(crate) by_addr: HashMap<Address, usize>,
    /// Prochaine adresse de la réserve à distribuer (la n° 0 est l'adresse principale).
    pub(crate) next: usize,
    pub(crate) mining: Option<usize>,
    pub(crate) contacts: Vec<Contact>,
    pub(crate) path: Option<PathBuf>,
    /// Clé de la section « vue » (gardée en mémoire pour pouvoir enregistrer), réglages et sel.
    pub(crate) view: Option<(Zeroizing<[u8; 64]>, KdfParams, [u8; 32])>,
    /// Graine chiffrée par le code de dépense (absente quand le portefeuille est gelé).
    pub(crate) vault: Option<Sealed>,
    /// Portefeuille gelé : empreinte de la graine, qui n'existe plus sur cet ordinateur.
    pub(crate) frozen: Option<[u8; 32]>,
    pub(crate) protection: Option<Protection>,
    pub(crate) groups: Vec<Group>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Balance {
    pub available: u64,
    pub immature: u64,
    pub pending: u64,
    /// Fonds reçus mais verrouillés jusqu'à une date (hauteur de bloc).
    pub locked: u64,
}

pub(crate) fn derive(seed: &[u8; 32], index: u32) -> KeyPair {
    let mut data = b"NFR-wallet-key".to_vec();
    data.extend_from_slice(seed);
    data.extend_from_slice(&index.to_be_bytes());
    let h = sha3_512(&data);
    KeyPair::from_seed(h[..32].try_into().unwrap())
}

pub(crate) fn address_of(kp: &KeyPair) -> Address {
    address_of_pubkey(&kp.public_key_bytes())
}

/// Alphabet de Crockford : sans I, L, O, U (pas de confusion avec 1 et 0).
const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(crate) fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub(crate) fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out = Vec::new();
    for c in s.chars() {
        let c = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        let v = B32.iter().position(|&x| x as char == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 255) as u8);
        }
    }
    Some(out)
}

/// Adresse lisible : « NFR1-XXXX-XXXX-… » (256 bits en base 32 + somme de contrôle de 4 octets).
pub fn address_to_string(a: &Address) -> String {
    let mut raw = a.to_vec();
    raw.extend_from_slice(&hash512(a)[..4]);
    let body = b32_encode(&raw);
    let groups: Vec<&str> = body.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("NFR1-{}", groups.join("-"))
}

pub fn parse_address(s: &str) -> Result<Address, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    let body = clean
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("NFR1"))
        .map(|_| &clean[4..])
        .ok_or(crate::i18n::t("une adresse commence par NFR1", "an address starts with NFR1"))?;
    let raw = b32_decode(body).ok_or(crate::i18n::t("caractères invalides dans l'adresse", "invalid characters in the address"))?;
    if body.len() != 58 || raw.len() != 36 {
        return Err(crate::i18n::t("longueur d'adresse incorrecte (adresse coupée ?)", "wrong address length (address cut off?)").into());
    }
    let addr: Address = raw[..32].try_into().unwrap();
    if hash512(&addr)[..4] != raw[32..] {
        return Err(crate::i18n::t("somme de contrôle incorrecte (faute de frappe ?)", "wrong checksum (typo?)").into());
    }
    Ok(addr)
}

/// Lit une durée « 30min », « 12h », « 3j », « 2sem », « 1mois », « 1an » et la convertit en secondes.
pub fn parse_lock_duration(s: &str) -> Result<u64, String> {
    let s = s.trim().to_lowercase();
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    let unit = &s[digits.len()..];
    let n: u64 = digits.parse().map_err(|_| crate::i18n::t("durée invalide (exemples : 30min, 12h, 3j, 2sem, 1mois, 1an)", "invalid duration (examples: 30min, 12h, 3j, 2sem, 1mois, 1an)"))?;
    let secs_per_unit = match unit {
        "min" => 60,
        "h" => 3_600,
        "j" => 86_400,
        "sem" => 7 * 86_400,
        "mois" => 30 * 86_400,
        "an" | "ans" => 365 * 86_400,
        _ => return Err(crate::i18n::t("unité inconnue : utilisez min, h, j, sem, mois ou an", "unknown unit: use min, h, j (days), sem (weeks), mois (months) or an (years)").into()),
    };
    let secs = n.checked_mul(secs_per_unit).ok_or(crate::i18n::t("durée trop grande", "duration too large"))?;
    if n == 0 {
        return Err(crate::i18n::t("la durée doit être positive", "the duration must be positive").into());
    }
    if secs > 10 * 365 * 86_400 {
        return Err(crate::i18n::t("le verrou est limité à 10 ans", "the lock is limited to 10 years").into());
    }
    Ok(secs)
}

/// Options d'un paiement : message public joint et verrou (durée en secondes).
/// `now` = heure actuelle de l'ordinateur ; le verrou part du plus tard entre elle
/// et le temps médian de la chaîne, pour ne jamais être plus court que demandé.
#[derive(Default, Clone, Debug)]
pub struct PaymentOptions {
    pub memo: String,
    pub lock_secs: u64,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryKind {
    Received,
    Sent,
    /// Envoi vers soi-même avec verrou (« coffre-fort »).
    Vault,
}

#[derive(Debug, Clone)]
pub struct HistoryItem {
    pub height: u64,
    pub kind: HistoryKind,
    pub amount: u64,
    pub memo: String,
    pub lock_until: u32,
}

/// Affiche un montant : 12,5 NFR.
pub fn format_amount(units: u64) -> String {
    let whole = units / MIN_UNIT;
    let frac = units % MIN_UNIT;
    if frac == 0 {
        format!("{whole} NFR")
    } else {
        let f = format!("{frac:08}");
        let sep = if crate::i18n::en() { '.' } else { ',' };
        format!("{whole}{sep}{} NFR", f.trim_end_matches('0'))
    }
}

/// Lit un montant écrit « 12,5 » ou « 12.5 » (8 décimales au maximum), sans flottant.
pub fn parse_amount(s: &str) -> Result<u64, String> {
    let s = s.trim().replace(',', ".");
    let (w, f) = match s.split_once('.') {
        Some((w, f)) => (w.to_string(), f.to_string()),
        None => (s.clone(), String::new()),
    };
    if w.is_empty() && f.is_empty() || f.len() > 8 {
        return Err(crate::i18n::t("montant invalide (8 décimales au maximum)", "invalid amount (8 decimals maximum)").into());
    }
    if !w.chars().all(|c| c.is_ascii_digit()) || !f.chars().all(|c| c.is_ascii_digit()) {
        return Err(crate::i18n::t("montant invalide", "invalid amount").into());
    }
    let whole: u64 = if w.is_empty() { 0 } else { w.parse().map_err(|_| crate::i18n::t("montant trop grand", "amount too large"))? };
    let frac: u64 = if f.is_empty() { 0 } else { format!("{f:0<8}").parse().unwrap() };
    let v = whole.checked_mul(MIN_UNIT).and_then(|x| x.checked_add(frac)).ok_or(crate::i18n::t("montant trop grand", "amount too large"))?;
    if v == 0 {
        return Err(crate::i18n::t("le montant doit être positif", "the amount must be positive").into());
    }
    if v > crate::config::HARD_CAP {
        return Err(crate::i18n::t("montant trop grand (plus que tous les NFR qui existeront)", "amount too large (more than all the NFR that will ever exist)").into());
    }
    Ok(v)
}

impl Wallet {
    /// Portefeuille en clair à partir d'une graine (tests ; ou étape avant chiffrement).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut w = Self {
            seed: Some(Zeroizing::new(seed)),
            keys: Vec::with_capacity(POOL_SIZE),
            by_addr: HashMap::new(),
            next: 1,
            mining: None,
            contacts: Vec::new(),
            path: None,
            view: None,
            vault: None,
            frozen: None,
            protection: None,
            groups: Vec::new(),
        };
        w.fill_pool(&seed, POOL_SIZE);
        w
    }

    fn fill_pool(&mut self, seed: &[u8; 32], size: usize) {
        for i in self.keys.len()..size {
            let a = address_of(&derive(seed, i as u32));
            self.keys.push((a, false));
            self.by_addr.insert(a, i);
        }
    }

    /// Lit un code de secours complet à l'ancienne (64 caractères hexadécimaux).
    pub fn parse_full_code(code: &str) -> Result<Zeroizing<[u8; 32]>, String> {
        let raw = Zeroizing::new(from_hex(code.trim()).ok_or(crate::i18n::t("code de secours invalide", "invalid recovery code"))?);
        let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| "le code de secours complet fait 64 caractères")?;
        Ok(Zeroizing::new(seed))
    }

    /// Portefeuille neuf en clair (graine aléatoire), à chiffrer ensuite avec `protect`.
    pub fn create_encrypted_plain() -> Result<Self, String> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(vault::random()?);
        Ok(Self::from_seed(*seed))
    }

    /// Crée un portefeuille neuf, chiffré. Renvoie aussi les 3 morceaux du code de secours.
    pub fn create_encrypted(path: &Path, open_pw: &str, spend_code: &str, p: KdfParams) -> Result<(Self, [String; 3]), String> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(vault::random()?);
        Self::from_seed(*seed).protect(path, open_pw, spend_code, p)
    }

    /// Chiffre un portefeuille en clair (neuf, restauré ou ancien) avec ses deux mots de passe,
    /// l'enregistre, et renvoie les 3 morceaux du code de secours.
    pub fn protect(mut self, path: &Path, open_pw: &str, spend_code: &str, p: KdfParams) -> Result<(Self, [String; 3]), String> {
        vault::check_password(open_pw, vault::MIN_OPEN_PASSWORD, "Mot de passe d'ouverture")?;
        vault::check_password(spend_code, vault::MIN_SPEND_CODE, "Code de dépense")?;
        if open_pw == spend_code {
            return Err(crate::i18n::t("le code de dépense doit être différent du mot de passe d'ouverture", "the spending code must differ from the opening password").into());
        }
        let seed = self.seed.take().ok_or("graine absente")?;
        let vp = vault::vault_params(p);
        let vault_salt: [u8; 32] = vault::random()?;
        let vault_key = vault::derive_key(spend_code, &vault_salt, vp)?;
        self.vault = Some(vault::seal(&vault_key, vp, vault_salt, b"coffre", seed.as_slice())?);
        let view_salt: [u8; 32] = vault::random()?;
        let view_key = vault::derive_key(open_pw, &view_salt, p)?;
        self.view = Some((view_key, p, view_salt));
        self.path = Some(path.to_path_buf());
        let shares = vault::split_seed(&seed)?;
        self.save()?;
        Ok((self, shares))
    }

    /// Ouvre un portefeuille chiffré avec le mot de passe d'ouverture (la graine reste chiffrée).
    pub fn unlock(path: &Path, open_pw: &str) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        let mut r = Reader::new(&data);
        let e = |_| "fichier portefeuille corrompu".to_string();
        let magic = r.bytes(8).map_err(e)?;
        let v4 = magic == FILE_MAGIC;
        if !v4 && magic != FILE_MAGIC_V3 {
            return Err(crate::i18n::t("ce fichier n'est pas un portefeuille NumFranc chiffré", "this file is not an encrypted NumFranc wallet").into());
        }
        let view_s = Sealed::decode(&mut r)?;
        // v0.4 / v0.5 : le coffre est toujours là. v0.6 : un octet dit s'il est absent (portefeuille gelé).
        let has_vault = if v4 { r.u8().map_err(e)? == 0 } else { true };
        let vault_s = if has_vault { Some(Sealed::decode(&mut r)?) } else { None };
        let key = vault::derive_key(open_pw, &view_s.salt, view_s.params)?;
        let plain = vault::open(&key, b"vue", &view_s)?;
        let mut w = Self::decode_view(&plain)?;
        if vault_s.is_none() && w.frozen.is_none() {
            return Err("portefeuille incohérent (coffre absent sans gel)".into());
        }
        w.view = Some((key, view_s.params, view_s.salt));
        w.vault = vault_s;
        w.path = Some(path.to_path_buf());
        Ok(w)
    }

    /// Lit un ancien portefeuille non chiffré (v0.2 / v0.3), pour le chiffrer ensuite avec `protect`.
    pub fn load_legacy(path: &Path) -> Result<Self, String> {
        let data = Zeroizing::new(std::fs::read(path).map_err(|e| e.to_string())?);
        let mut r = Reader::new(&data);
        let e = |_| "fichier portefeuille corrompu".to_string();
        if r.bytes(8).map_err(e)? != LEGACY_MAGIC {
            return Err("ce fichier n'est pas un ancien portefeuille NumFranc".into());
        }
        let seed: [u8; 32] = r.array().map_err(e)?;
        let mining = r.u32().map_err(e)?;
        let n = r.u32().map_err(e)? as usize;
        let mut w = Self::from_seed(seed);
        let mut old = Vec::new();
        for _ in 0..n {
            let revealed = r.u8().map_err(e)? == 1;
            let addr: Address = r.array().map_err(e)?;
            old.push((addr, revealed));
        }
        // On garde au moins toutes les adresses déjà utilisées, puis la réserve habituelle.
        if n > POOL_SIZE {
            w.fill_pool(&seed, n);
        }
        for (i, (a, rev)) in old.iter().enumerate() {
            if w.keys[i].0 == *a {
                w.keys[i].1 = *rev;
            }
        }
        w.next = n.max(1);
        w.mining = if mining == u32::MAX || mining as usize >= w.keys.len() { None } else { Some(mining as usize) };
        Ok(w)
    }

    fn decode_view(data: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(data);
        let e = |_| crate::i18n::t("portefeuille illisible", "unreadable wallet").to_string();
        let next = r.u32().map_err(e)? as usize;
        let mining = r.u32().map_err(e)?;
        let n = r.u32().map_err(e)? as usize;
        if n == 0 || n > 10_000_000 {
            return Err(crate::i18n::t("portefeuille illisible", "unreadable wallet").into());
        }
        let mut w = Self {
            seed: None,
            keys: Vec::with_capacity(n),
            by_addr: HashMap::new(),
            next: next.clamp(1, n),
            mining: None,
            contacts: Vec::new(),
            path: None,
            view: None,
            vault: None,
            frozen: None,
            protection: None,
            groups: Vec::new(),
        };
        for i in 0..n {
            let revealed = r.u8().map_err(e)? == 1;
            let addr: Address = r.array().map_err(e)?;
            w.keys.push((addr, revealed));
            w.by_addr.insert(addr, i);
        }
        w.mining = if mining == u32::MAX || mining as usize >= n { None } else { Some(mining as usize) };
        let nc = r.u32().map_err(e)? as usize;
        for _ in 0..nc {
            let len = r.u8().map_err(e)? as usize;
            let name = String::from_utf8(r.bytes(len).map_err(e)?.to_vec()).map_err(|_| crate::i18n::t("portefeuille illisible", "unreadable wallet").to_string())?;
            let address: Address = r.array().map_err(e)?;
            w.contacts.push(Contact { name, address });
        }
        // Section ajoutée en v0.6 (gel, protection, groupes) : absente des anciens fichiers.
        if r.remaining() > 0 {
            w.decode_extras(&mut r).map_err(e)?;
        }
        r.finish().map_err(e)?;
        Ok(w)
    }

    fn decode_extras(&mut self, r: &mut Reader) -> Result<(), crate::encoding::DecodeError> {
        use crate::encoding::DecodeError;
        if r.u8()? != 1 {
            return Err(DecodeError("version de section inconnue"));
        }
        self.frozen = match r.u8()? {
            0 => None,
            _ => Some(r.array()?),
        };
        self.protection = match r.u8()? {
            0 => None,
            _ => {
                let threshold = r.u64()?;
                let delay_secs = r.u64()?;
                let guardian = match r.u8()? {
                    0 => None,
                    _ => Some(r.array()?),
                };
                Some(Protection { threshold, delay_secs, guardian })
            }
        };
        let n = r.u32()? as usize;
        if n > 1_000 {
            return Err(DecodeError("trop de groupes"));
        }
        for _ in 0..n {
            let len = r.u8()? as usize;
            let name = String::from_utf8(r.bytes(len)?.to_vec()).map_err(|_| DecodeError("nom illisible"))?;
            let m = r.u8()?;
            let k = r.u8()? as usize;
            let mut members = Vec::with_capacity(k);
            for _ in 0..k {
                members.push(r.array()?);
            }
            self.groups.push(Group { name, m, members });
        }
        Ok(())
    }

    fn encode_extras(&self, out: &mut Vec<u8>) {
        out.push(1);
        match &self.frozen {
            Some(t) => {
                out.push(1);
                out.extend_from_slice(t);
            }
            None => out.push(0),
        }
        match &self.protection {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.threshold.to_be_bytes());
                out.extend_from_slice(&p.delay_secs.to_be_bytes());
                match &p.guardian {
                    Some(g) => {
                        out.push(1);
                        out.extend_from_slice(g);
                    }
                    None => out.push(0),
                }
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(self.groups.len() as u32).to_be_bytes());
        for g in &self.groups {
            out.push(g.name.len() as u8);
            out.extend_from_slice(g.name.as_bytes());
            out.push(g.m);
            out.push(g.members.len() as u8);
            for a in &g.members {
                out.extend_from_slice(a);
            }
        }
    }

    fn encode_view(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(16 + self.keys.len() * 33));
        out.extend_from_slice(&(self.next as u32).to_be_bytes());
        out.extend_from_slice(&self.mining.map(|m| m as u32).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
        for (a, r) in &self.keys {
            out.push(*r as u8);
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&(self.contacts.len() as u32).to_be_bytes());
        for c in &self.contacts {
            out.push(c.name.len() as u8);
            out.extend_from_slice(c.name.as_bytes());
            out.extend_from_slice(&c.address);
        }
        self.encode_extras(&mut out);
        out
    }

    /// Enregistre le portefeuille chiffré (écriture atomique, lisible uniquement par l'utilisateur).
    /// Un portefeuille en clair (tests) n'est jamais écrit sur le disque.
    pub fn save(&self) -> Result<(), String> {
        let (Some(path), Some((key, p, salt))) = (&self.path, &self.view) else {
            return Ok(());
        };
        if self.vault.is_none() && self.frozen.is_none() {
            return Ok(());
        }
        let view_s = vault::seal(key, *p, *salt, b"vue", &self.encode_view())?;
        let mut out = FILE_MAGIC.to_vec();
        view_s.encode(&mut out);
        match &self.vault {
            Some(v) => {
                out.push(0);
                v.encode(&mut out);
            }
            None => out.push(1),
        }
        let tmp = path.with_extension("tmp");
        write_private(&tmp, &out).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    pub fn is_encrypted(&self) -> bool {
        self.vault.is_some() || self.frozen.is_some()
    }

    /// Graine en clair, le temps d'une opération : déchiffrée avec le code de dépense.
    pub(crate) fn seed_with(&self, spend_code: Option<&str>) -> Result<Zeroizing<[u8; 32]>, String> {
        if let Some(s) = &self.seed {
            return Ok(s.clone());
        }
        if self.frozen.is_some() {
            return Err(crate::i18n::t(
                "portefeuille gelé : la graine n'est plus sur cet ordinateur. Dégelez-le avec vos trois codes (onglet Sécurité).",
                "wallet frozen: the seed is no longer on this computer. Unfreeze it with your three codes (Security tab).",
            )
            .into());
        }
        let v = self.vault.as_ref().ok_or("portefeuille sans coffre")?;
        let code = spend_code.ok_or(crate::i18n::t("code de dépense requis", "spending code required"))?;
        let key = vault::derive_key(code, &v.salt, v.params)?;
        let plain = vault::open(&key, b"coffre", v).map_err(|_| crate::i18n::t("code de dépense incorrect", "wrong spending code").to_string())?;
        let seed: [u8; 32] = plain.as_slice().try_into().map_err(|_| "coffre illisible".to_string())?;
        let seed = Zeroizing::new(seed);
        // Vérification : la graine redonne bien l'adresse principale.
        if address_of(&derive(&seed, 0)) != self.keys[0].0 {
            return Err("coffre incohérent avec ce portefeuille".into());
        }
        Ok(seed)
    }

    /// Vérifie le code de dépense (sans rien faire d'autre).
    pub fn check_spend_code(&self, code: &str) -> Result<(), String> {
        self.seed_with(Some(code)).map(|_| ())
    }

    /// Les 3 morceaux du code de secours (toujours les mêmes pour un portefeuille donné).
    pub fn recovery_shares(&self, spend_code: &str) -> Result<[String; 3], String> {
        vault::split_seed(&*self.seed_with(Some(spend_code))?)
    }

    /// Change le mot de passe d'ouverture et/ou le code de dépense (il faut l'ancien code de dépense).
    pub fn change_passwords(&mut self, old_spend: &str, new_open: &str, new_spend: &str) -> Result<(), String> {
        let seed = self.seed_with(Some(old_spend))?;
        vault::check_password(new_open, vault::MIN_OPEN_PASSWORD, "Mot de passe d'ouverture")?;
        vault::check_password(new_spend, vault::MIN_SPEND_CODE, "Code de dépense")?;
        if new_open == new_spend {
            return Err(crate::i18n::t("le code de dépense doit être différent du mot de passe d'ouverture", "the spending code must differ from the opening password").into());
        }
        let p = self.view.as_ref().map(|v| v.1).unwrap_or(vault::STRONG);
        let vp = vault::vault_params(p);
        let vault_salt: [u8; 32] = vault::random()?;
        let vk = vault::derive_key(new_spend, &vault_salt, vp)?;
        let new_vault = vault::seal(&vk, vp, vault_salt, b"coffre", seed.as_slice())?;
        let view_salt: [u8; 32] = vault::random()?;
        let view_key = vault::derive_key(new_open, &view_salt, p)?;
        self.vault = Some(new_vault);
        self.view = Some((view_key, p, view_salt));
        self.save()
    }

    pub(crate) fn new_key(&mut self) -> Address {
        let i = self.next;
        self.next = if self.next + 1 >= self.keys.len() { 1 } else { self.next + 1 };
        self.keys[i].0
    }

    /// Adresse principale permanente : la même pour toujours, à donner à tout le monde.
    pub fn main_address(&mut self) -> Result<Address, String> {
        Ok(self.keys[0].0)
    }

    /// Nouvelle adresse de réception à usage unique (plus de discrétion).
    pub fn new_address(&mut self) -> Result<Address, String> {
        let a = self.new_key();
        self.save()?;
        Ok(a)
    }

    /// Adresse qui reçoit la prochaine récompense de minage.
    pub fn mining_address(&mut self) -> Address {
        match self.mining {
            Some(i) => self.keys[i].0,
            None => {
                let i = self.next;
                let a = self.new_key();
                self.mining = Some(i);
                let _ = self.save();
                a
            }
        }
    }

    /// Après un bloc trouvé : la récompense suivante ira sur une adresse neuve.
    pub fn rotate_mining_address(&mut self) {
        self.mining = None;
        let _ = self.save();
    }

    // ---------- Carnet d'adresses ----------

    pub fn contacts(&self) -> &[Contact] {
        &self.contacts
    }

    pub fn add_contact(&mut self, name: &str, address: Address) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() || name.len() > 40 {
            return Err(crate::i18n::t("le nom doit faire entre 1 et 40 caractères", "the name must be 1 to 40 characters long").into());
        }
        if name.starts_with("NFR1") || name.starts_with("nfr1") {
            return Err(crate::i18n::t("un nom ne peut pas commencer par NFR1", "a name cannot start with NFR1").into());
        }
        if name.contains(char::is_whitespace) {
            return Err(crate::i18n::t("pas d'espace dans un nom (ex. : Maman, HP_bureau)", "no spaces in a name (e.g. Mom, HP_office)").into());
        }
        if self.contacts.iter().any(|c| c.name.eq_ignore_ascii_case(name)) {
            return Err(crate::tf!("« {name} » existe déjà dans le carnet", "“{name}” is already in the address book"));
        }
        self.contacts.push(Contact { name: name.to_string(), address });
        self.contacts.sort_by_key(|c| c.name.to_lowercase());
        self.save()
    }

    pub fn remove_contact(&mut self, name: &str) -> Result<(), String> {
        let before = self.contacts.len();
        self.contacts.retain(|c| !c.name.eq_ignore_ascii_case(name.trim()));
        if self.contacts.len() == before {
            return Err(crate::tf!("« {name} » n'est pas dans le carnet", "“{name}” is not in the address book"));
        }
        self.save()
    }

    pub fn contact_address(&self, name: &str) -> Option<Address> {
        self.contacts.iter().find(|c| c.name.eq_ignore_ascii_case(name.trim())).map(|c| c.address)
    }

    pub fn contact_name(&self, a: &Address) -> Option<&str> {
        self.contacts.iter().find(|c| c.address == *a).map(|c| c.name.as_str())
    }

    /// Destinataire écrit soit comme un nom du carnet, soit comme une adresse NFR1-….
    pub fn resolve_recipient(&self, s: &str) -> Result<Address, String> {
        match self.contact_address(s) {
            Some(a) => Ok(a),
            None => parse_address(s).map_err(|e| {
                if s.trim().to_uppercase().starts_with("NFR1") { e } else { crate::tf!("« {} » n'est ni dans le carnet, ni une adresse NFR1", "“{}” is neither in the address book nor an NFR1 address", s.trim()) }
            }),
        }
    }

    pub fn is_mine(&self, a: &Address) -> bool {
        self.by_addr.contains_key(a)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub fn balance(&self, chain: &Chain, mempool: &Mempool) -> Balance {
        let next = chain.height() + 1;
        let mtp = chain.next_mtp();
        let mut b = Balance::default();
        for (op, u) in &chain.utxo {
            if !self.is_mine(&u.address) {
                continue;
            }
            if u.coinbase && next < u.height + COINBASE_MATURITY {
                b.immature += u.amount;
            } else if !is_unlocked(u.lock_until, next, mtp) {
                b.locked += u.amount;
            } else if mempool.spends(op) {
                b.pending += u.amount;
            } else {
                b.available += u.amount;
            }
        }
        b
    }

    /// Prépare et signe un paiement (avec message joint et verrou éventuels).
    /// Seules les sorties disponibles sont dépensées ; la monnaie rendue part vers une adresse neuve.
    pub fn create_payment(
        &mut self,
        chain: &Chain,
        mempool: &Mempool,
        to: Address,
        amount: u64,
        opts: &PaymentOptions,
        spend_code: Option<&str>,
    ) -> Result<Transaction, String> {
        let memo = opts.memo.as_bytes().to_vec();
        if memo.len() > MAX_MEMO {
            return Err(crate::tf!("message trop long : {} octets sur {MAX_MEMO} (les accents comptent double)", "message too long: {} bytes out of {MAX_MEMO} (accented letters count double)", memo.len()));
        }
        let mtp = chain.next_mtp();
        let mut lock_until = if opts.lock_secs == 0 {
            0
        } else {
            let t = mtp.max(opts.now) + opts.lock_secs;
            u32::try_from(t).map_err(|_| "verrou trop lointain".to_string())?
        };
        // Protection des gros paiements : retenue annulable jusqu'à la fin du délai.
        let mut cancel = None;
        if let Some(p) = self.protection.clone() {
            if amount >= p.threshold {
                let until = u32::try_from(mtp.max(opts.now) + p.delay_secs).map_err(|_| "délai trop lointain".to_string())?;
                lock_until = lock_until.max(until);
                cancel = Some(p.guardian.unwrap_or(self.keys[0].0));
            }
        }
        let out = TxOut { amount, address: to, lock_until, cancel };
        self.build_tx(
            chain,
            mempool,
            crate::wallet_plus::BuildSpec { outputs: vec![out], extra_fee: 0, memo, name_op: None, prefer: None },
            spend_code,
        )
    }

    /// Historique des paiements reçus et envoyés (hors récompenses de minage).
    pub fn history(&self, chain: &Chain) -> Vec<HistoryItem> {
        let mut items = Vec::new();
        for h in 1..=chain.height() {
            let Some(block) = chain.block_at(h) else { continue };
            for tx in block.txs.iter().filter(|t| !t.is_coinbase()) {
                let spent_by_me = tx.inputs.iter().any(|i| self.is_mine(&i.spender()));
                let memo = tx.memo_text();
                let mine: u64 = tx.outputs.iter().filter(|o| self.is_mine(&o.address)).map(|o| o.amount).sum();
                let others: Vec<&TxOut> = tx.outputs.iter().filter(|o| !self.is_mine(&o.address)).collect();
                if spent_by_me && !others.is_empty() {
                    items.push(HistoryItem {
                        height: h,
                        kind: HistoryKind::Sent,
                        amount: others.iter().map(|o| o.amount).sum(),
                        memo,
                        lock_until: others.iter().map(|o| o.lock_until).max().unwrap_or(0),
                    });
                } else if spent_by_me {
                    // Tout revient chez nous : seul un envoi verrouillé est intéressant.
                    if let Some(o) = tx.outputs.iter().filter(|o| o.lock_until > 0).max_by_key(|o| o.lock_until) {
                        items.push(HistoryItem { height: h, kind: HistoryKind::Vault, amount: o.amount, memo, lock_until: o.lock_until });
                    }
                } else if mine > 0 {
                    let unlock = tx.outputs.iter().filter(|o| self.is_mine(&o.address)).map(|o| o.lock_until).max().unwrap_or(0);
                    items.push(HistoryItem { height: h, kind: HistoryKind::Received, amount: mine, memo, lock_until: unlock });
                }
            }
        }
        items
    }

    /// Marque comme révélées les clés publiques utilisées par une transaction envoyée.
    pub fn mark_spent(&mut self, tx: &Transaction) {
        for i in &tx.inputs {
            let a = i.spender();
            if let Some(&k) = self.by_addr.get(&a) {
                self.keys[k].1 = true;
            }
        }
        let _ = self.save();
    }
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    // Fichier neuf créé directement en 0600 (lecture par le seul propriétaire), même si un ancien
    // fichier temporaire traînait avec d'autres droits ; droits réappliqués par sécurité.
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SIGNATURE_SIZE;
    use crate::tx::{OutPoint, TxIn};
    use crate::chain::tests::{make_block, test_genesis};
    use crate::chain::Chain;

    #[test]
    fn adresse_aller_retour_et_faute_de_frappe() {
        let a = [7u8; 32];
        let s = address_to_string(&a);
        assert!(s.starts_with("NFR1-"));
        assert_eq!(s.len(), 5 + 58 + 14); // « NFR1- » + 58 caractères + 14 tirets intérieurs
        assert_eq!(parse_address(&s).unwrap(), a);
        // Insensible à la casse, aux tirets et aux espaces ; O = 0, I = L = 1.
        assert_eq!(parse_address(&s.to_lowercase().replace('-', " ")).unwrap(), a);
        let mut bad = s.clone();
        bad.replace_range(10..11, if &s[10..11] == "2" { "3" } else { "2" });
        assert!(parse_address(&bad).is_err());
        assert!(parse_address(&s[..s.len() - 2]).is_err());
        assert!(parse_address("NFR1-0000").is_err());
        let b = [0xA5u8; 32];
        assert_eq!(parse_address(&address_to_string(&b)).unwrap(), b);
    }

    #[test]
    fn durees_de_verrou() {
        assert_eq!(parse_lock_duration("30min").unwrap(), 1_800);
        assert_eq!(parse_lock_duration("1h").unwrap(), 3_600);
        assert_eq!(parse_lock_duration("1j").unwrap(), 86_400);
        assert!(parse_lock_duration("0j").is_err());
        assert!(parse_lock_duration("3").is_err());
        assert!(parse_lock_duration("3x").is_err());
        assert!(parse_lock_duration("11an").is_err());
        assert!(parse_lock_duration("10an").is_ok());
    }

    #[test]
    fn adresse_principale_permanente() {
        let mut w = Wallet::from_seed([8; 32]);
        let a = w.main_address().unwrap();
        assert_eq!(w.main_address().unwrap(), a);
        assert_ne!(w.new_address().unwrap(), a);
        assert_eq!(w.main_address().unwrap(), a);
        // Même graine, même adresse principale.
        assert_eq!(Wallet::from_seed([8; 32]).main_address().unwrap(), a);
    }

    #[test]
    fn montants() {
        assert_eq!(parse_amount("1").unwrap(), 100_000_000);
        assert_eq!(parse_amount("6,91").unwrap(), 691_000_000);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
        assert!(parse_amount("0.000000001").is_err());
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount("0").is_err());
        assert_eq!(format_amount(691_000_000), "6,91 NFR");
        assert_eq!(format_amount(100_000_000), "1 NFR");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nfr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const OUV: &str = "Ouverture-Test-2026";
    const DEP: &str = "Depense#Code42-Plage";

    #[test]
    fn coffre_chiffre_de_bout_en_bout() {
        let dir = temp_dir("coffre");
        let p = dir.join("wallet.dat");
        let (mut w, shares) = Wallet::create_encrypted(&p, OUV, DEP, vault::TEST).unwrap();
        assert!(w.is_encrypted());
        assert_eq!(file_status(&p), WalletFile::Encrypted);
        let main = w.main_address().unwrap();
        let fresh = w.new_address().unwrap();
        let c = mined_chain(&mut w, COINBASE_MATURITY + 2);

        // Le fichier ne contient ni la graine ni les adresses en clair.
        let seed = vault::join_shares(&shares[0], &shares[2]).unwrap();
        let file = std::fs::read(&p).unwrap();
        assert!(!file.windows(32).any(|x| x == seed.as_slice()));
        assert!(!file.windows(32).any(|x| x == main.as_slice()));
        assert_eq!(Wallet::from_seed(*seed).keys[0].0, main);

        // Mauvais mot de passe : refusé. Bon mot de passe : tout est là.
        assert!(Wallet::unlock(&p, "Mauvais-Mot-2026").is_err());
        let mut w2 = Wallet::unlock(&p, OUV).unwrap();
        assert!(w2.is_mine(&fresh));
        assert_eq!(w2.main_address().unwrap(), main);
        assert_eq!(w2.balance(&c, &Mempool::default()), w.balance(&c, &Mempool::default()));

        // Carnet d'adresses chiffré et conservé.
        w2.add_contact("HP", [9; 32]).unwrap();
        assert!(w2.add_contact("hp", [8; 32]).is_err());
        assert!(w2.add_contact("deux mots", [8; 32]).is_err());
        let w3 = Wallet::unlock(&p, OUV).unwrap();
        assert_eq!(w3.contact_address("hp"), Some([9; 32]));
        assert_eq!(w3.resolve_recipient("HP").unwrap(), [9; 32]);
        assert!(w3.resolve_recipient("Inconnu").is_err());

        // Envoyer exige le bon code de dépense.
        let mp = Mempool::default();
        let e = w2.create_payment(&c, &mp, [9; 32], 100_000_000, &PaymentOptions::default(), None).unwrap_err();
        assert!(e.contains("code de dépense"));
        assert!(w2.create_payment(&c, &mp, [9; 32], 100_000_000, &PaymentOptions::default(), Some(OUV)).is_err());
        let tx = w2.create_payment(&c, &mp, [9; 32], 100_000_000, &PaymentOptions::default(), Some(DEP)).unwrap();
        tx.check_stateless().unwrap();

        // Changement des mots de passe.
        w2.change_passwords(DEP, "Nouvelle-Ouverture-7", "Nouveau#Code99-Tambour").unwrap();
        assert!(Wallet::unlock(&p, OUV).is_err());
        let w4 = Wallet::unlock(&p, "Nouvelle-Ouverture-7").unwrap();
        assert!(w4.check_spend_code(DEP).is_err());
        w4.check_spend_code("Nouveau#Code99-Tambour").unwrap();
        let again = w4.recovery_shares("Nouveau#Code99-Tambour").unwrap();
        assert_eq!(*vault::join_shares(&again[1], &shares[0]).unwrap(), *seed);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn regles_de_creation() {
        let dir = temp_dir("regles");
        let p = dir.join("wallet.dat");
        assert!(Wallet::create_encrypted(&p, "court", DEP, vault::TEST).is_err());
        assert!(Wallet::create_encrypted(&p, OUV, OUV, vault::TEST).is_err());
        assert!(Wallet::create_encrypted(&p, OUV, "petit", vault::TEST).is_err());
        assert_eq!(file_status(&p), WalletFile::Missing);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn migration_d_un_ancien_portefeuille() {
        let dir = temp_dir("migration");
        let p = dir.join("wallet.dat");
        // Ancien format NFRWAL02 : graine en clair + 3 adresses.
        let old = Wallet::from_seed([5; 32]);
        let mut data = LEGACY_MAGIC.to_vec();
        data.extend_from_slice(&[5; 32]);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&3u32.to_be_bytes());
        for i in 0..3 {
            data.push((i == 1) as u8);
            data.extend_from_slice(&old.keys[i].0);
        }
        std::fs::write(&p, &data).unwrap();
        assert_eq!(file_status(&p), WalletFile::Legacy);
        let w = Wallet::load_legacy(&p).unwrap();
        assert_eq!(w.next, 3);
        assert!(w.keys[1].1);
        let (_, shares) = w.protect(&p, OUV, DEP, vault::TEST).unwrap();
        assert_eq!(file_status(&p), WalletFile::Encrypted);
        let w = Wallet::unlock(&p, OUV).unwrap();
        assert_eq!(w.keys[0].0, old.keys[0].0);
        assert_eq!(*vault::join_shares(&shares[1], &shares[2]).unwrap(), [5; 32]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn minage_paiement_et_restauration() {
        let now = crate::config::GENESIS_TIMESTAMP + 10_000_000;
        let mut c = Chain::with_genesis(test_genesis());
        let mut w = Wallet::from_seed([42; 32]);
        for _ in 0..(COINBASE_MATURITY + 2) {
            let to = w.mining_address();
            let b = make_block(&c, c.tip(), vec![], to, 691, b"");
            c.add_block(b, now).unwrap();
            w.rotate_mining_address();
        }
        let mp = Mempool::default();
        let bal = w.balance(&c, &mp);
        // 102 blocs minés (hauteurs 1 à 102) : au bloc 103, ceux des hauteurs 1 à 3 sont mûrs.
        assert_eq!(bal.available, 3 * 691_000_000);
        assert_eq!(bal.immature, 99 * 691_000_000);

        let dest = Wallet::from_seed([1; 32]).mining_address();
        let tx = w.create_payment(&c, &mp, dest, 1_000_000_000, &PaymentOptions::default(), None).unwrap();
        let mut mp = Mempool::default();
        mp.accept(tx.clone(), &c).unwrap();
        w.mark_spent(&tx);
        let b = make_block(&c, c.tip(), vec![tx], [0; 32], 691, b"");
        c.add_block(b, now).unwrap();
        mp.revalidate(&c);
        assert!(mp.is_empty());

        // Le destinataire a reçu 10 NFR, la monnaie est revenue sur une adresse neuve.
        let received: u64 = c.utxo.values().filter(|u| u.address == dest).map(|u| u.amount).sum();
        assert_eq!(received, 1_000_000_000);

        // Restauration depuis la graine : la réserve d'adresses retrouve tout le solde.
        let r = Wallet::from_seed([42; 32]);
        assert_eq!(r.balance(&c, &mp), w.balance(&c, &mp));
    }

    /// Mine `n` blocs vers le portefeuille et renvoie la chaîne.
    fn mined_chain(w: &mut Wallet, n: u64) -> Chain {
        let now = crate::config::GENESIS_TIMESTAMP + 10_000_000;
        let mut c = Chain::with_genesis(test_genesis());
        for _ in 0..n {
            let to = w.mining_address();
            let b = make_block(&c, c.tip(), vec![], to, 691, b"");
            c.add_block(b, now).unwrap();
            w.rotate_mining_address();
        }
        c
    }

    #[test]
    fn message_joint_et_verrou_de_bout_en_bout() {
        let now = crate::config::GENESIS_TIMESTAMP + 10_000_000;
        let mut w = Wallet::from_seed([42; 32]);
        let mut c = mined_chain(&mut w, COINBASE_MATURITY + 2);
        let mut friend = Wallet::from_seed([1; 32]);
        let dest = friend.main_address().unwrap();
        let mp = Mempool::default();

        // Paiement avec message et verrou d'une heure (date réelle).
        let opts = PaymentOptions { memo: "Merci pour le déjeuner !".into(), lock_secs: 3_600, now: 0 };
        let tx = w.create_payment(&c, &mp, dest, 1_000_000_000, &opts, None).unwrap();
        assert_eq!(tx.memo, "Merci pour le déjeuner !".as_bytes());
        let unlock = tx.outputs[0].lock_until as u64;
        assert_eq!(unlock, c.next_mtp() + 3_600);
        assert!(unlock >= crate::config::LOCK_TIME_THRESHOLD as u64);
        let mut mp = Mempool::default();
        mp.accept(tx.clone(), &c).unwrap();
        w.mark_spent(&tx);
        let b = make_block(&c, c.tip(), vec![tx], [0; 32], 691, b"");
        c.add_block(b, now).unwrap();

        // Le destinataire voit les fonds verrouillés, et le message dans son historique.
        let mp0 = Mempool::default();
        let bal = friend.balance(&c, &mp0);
        assert_eq!((bal.available, bal.locked), (0, 1_000_000_000));
        let h = friend.history(&c);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].kind, HistoryKind::Received);
        assert_eq!(h[0].memo, "Merci pour le déjeuner !");
        assert_eq!(h[0].lock_until as u64, unlock);
        // Il ne peut pas les dépenser avant la date.
        assert!(friend.create_payment(&c, &mp0, dest, 1, &PaymentOptions::default(), None).is_err());

        // Le verrou tient aussi côté consensus, même avec une transaction forgée à la main.
        let u = c.utxo.iter().find(|(_, u)| u.address == dest).map(|(o, u)| (*o, u.clone())).unwrap();
        let forged = fake_spend(&friend, u.0, &u.1);
        assert!(crate::chain::check_tx_inputs(&c.utxo, &forged, c.height() + 1, unlock - 1).is_err());
        assert!(crate::chain::check_tx_inputs(&c.utxo, &forged, c.height() + 1, unlock).is_ok());

        // Quand le temps médian de la chaîne atteint la date, il peut dépenser.
        while c.next_mtp() < unlock {
            let b = make_block(&c, c.tip(), vec![], [0; 32], 691, b"");
            c.add_block(b, now).unwrap();
        }
        assert_eq!(friend.balance(&c, &mp0).locked, 0);
        assert!(friend.balance(&c, &mp0).available > 0);
        friend.create_payment(&c, &mp0, [9; 32], 500_000_000, &PaymentOptions::default(), None).unwrap();
    }

    /// Transaction forgée qui dépense directement une sortie du portefeuille `w`.
    fn fake_spend(w: &Wallet, op: OutPoint, u: &crate::chain::UtxoEntry) -> Transaction {
        let idx = w.by_addr[&u.address];
        let kp = derive(w.seed.as_ref().unwrap(), idx as u32);
        let mut tx = Transaction::new(
            vec![TxIn::single(op, kp.public_key_bytes().to_vec(), vec![0; SIGNATURE_SIZE])],
            vec![TxOut::new(u.amount - 100_000, [5; 32])],
            Vec::new(),
        );
        tx.inputs[0].signature = kp.sign(&tx.sighash()).unwrap().to_vec();
        tx
    }

    #[test]
    fn message_trop_long_refuse() {
        let mut w = Wallet::from_seed([42; 32]);
        let c = mined_chain(&mut w, COINBASE_MATURITY + 2);
        let opts = PaymentOptions { memo: "é".repeat(71), ..Default::default() }; // 142 octets
        let e = w.create_payment(&c, &Mempool::default(), [9; 32], 1_000, &opts, None).unwrap_err();
        assert!(e.contains("trop long"));
    }

    #[test]
    fn fonds_insuffisants() {
        let c = Chain::with_genesis(test_genesis());
        let mut w = Wallet::from_seed([3; 32]);
        assert!(w.create_payment(&c, &Mempool::default(), [1; 32], 1, &PaymentOptions::default(), None).is_err());
    }
}
