//! Fonctions avancées du portefeuille (v0.6) :
//! gel, protection des gros paiements (retenue annulable), multi-signature,
//! pseudos, demandes de paiement et preuve de réserve.

use crate::chain::Chain;
use crate::config::{COINBASE_MATURITY, MAX_MEMO, MIN_UNIT};
use crate::encoding::{from_hex, hex, put_varint, Reader};
use crate::hashing::sha3_512;
use crate::mempool::Mempool;
use crate::signature::{verify, KeyPair, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use crate::tx::{
    address_of_pubkey, check_name, is_unlocked, min_fee, multisig_address, name_fee, normalize_members, Address, NameKind, NameOp,
    OutPoint, PartialSig, Transaction, TxIn, TxOut,
};
use crate::vault;
use crate::wallet::{address_to_string, derive, parse_amount, Group, Protection, Wallet};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Ce que le portefeuille doit construire : des sorties explicites (la monnaie rendue est ajoutée
/// automatiquement), des frais supplémentaires, un message et éventuellement une opération de pseudo.
pub(crate) struct BuildSpec {
    pub outputs: Vec<TxOut>,
    pub extra_fee: u64,
    pub memo: Vec<u8>,
    pub name_op: Option<NameOp>,
    /// Dépenser en priorité depuis cette adresse (obligatoire pour prouver la propriété d'un pseudo).
    pub prefer: Option<Address>,
}

/// Une sortie que j'ai envoyée et que je peux encore annuler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retained {
    pub op: OutPoint,
    pub amount: u64,
    pub to: Address,
    pub unlock: u32,
    pub cancel: Address,
    pub height: u64,
}

fn freeze_tag(seed: &[u8; 32]) -> [u8; 32] {
    let mut d = b"NFR-gel".to_vec();
    d.extend_from_slice(seed);
    sha3_512(&d)[..32].try_into().unwrap()
}

// ---------- Demande de paiement (lien nfr:) ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    /// Adresse NFR1-… ou pseudo (« alice.nfr »), tel qu'écrit dans le lien.
    pub recipient: String,
    pub amount: Option<u64>,
    pub message: String,
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3).ok_or("lien mal formé")?;
            out.push(u8::from_str_radix(h, 16).map_err(|_| "lien mal formé")?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "texte du lien illisible".to_string())
}

/// Montant écrit pour un lien : toujours avec un point, quelle que soit la langue.
fn amount_for_uri(units: u64) -> String {
    let (w, f) = (units / MIN_UNIT, units % MIN_UNIT);
    if f == 0 { format!("{w}") } else { format!("{w}.{}", format!("{f:08}").trim_end_matches('0')) }
}

/// Lien de demande de paiement : nfr:NFR1-…?amount=12.5&message=Merci
pub fn payment_uri(recipient: &str, amount: Option<u64>, message: &str) -> String {
    let mut s = format!("nfr:{}", recipient.trim());
    let mut sep = '?';
    if let Some(a) = amount {
        s.push_str(&format!("{sep}amount={}", amount_for_uri(a)));
        sep = '&';
    }
    if !message.is_empty() {
        s.push_str(&format!("{sep}message={}", pct_encode(message)));
    }
    s
}

pub fn parse_payment_uri(s: &str) -> Result<PaymentRequest, String> {
    let s = s.trim();
    let rest = s.get(..4).filter(|p| p.eq_ignore_ascii_case("nfr:")).map(|_| &s[4..]).ok_or("un lien de paiement commence par nfr:")?;
    let (recipient, query) = match rest.split_once('?') {
        Some((r, q)) => (r, q),
        None => (rest, ""),
    };
    if recipient.is_empty() || recipient.len() > 200 || recipient.contains(char::is_whitespace) {
        return Err("destinataire absent ou invalide dans le lien".into());
    }
    let (mut amount, mut message) = (None, String::new());
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "amount" => amount = Some(parse_amount(v)?),
            "message" => {
                message = pct_decode(v)?;
                if message.len() > MAX_MEMO {
                    return Err(format!("message trop long ({} octets sur {MAX_MEMO})", message.len()));
                }
            }
            _ => {}
        }
    }
    Ok(PaymentRequest { recipient: recipient.to_string(), amount, message })
}

// ---------- Preuve de réserve ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveInfo {
    pub claimed: u64,
    pub proven: u64,
    pub height: u64,
    pub age_blocks: u64,
    pub challenge: String,
    pub addresses: Vec<Address>,
}

const PROOF_PREFIX: &str = "NFRPROOF1-";
const MAX_PROOF_ADDRESSES: usize = 64;

fn reserve_message(height: u64, hash: &[u8; 64], claimed: u64, challenge: &str) -> Vec<u8> {
    let mut m = b"NFR-RESERVE".to_vec();
    m.extend_from_slice(&height.to_be_bytes());
    m.extend_from_slice(hash);
    m.extend_from_slice(&claimed.to_be_bytes());
    put_varint(&mut m, challenge.len() as u64);
    m.extend_from_slice(challenge.as_bytes());
    m
}

/// Vérifie une preuve de réserve contre ma propre chaîne. `expected_challenge` : le mot que j'ai
/// demandé à la personne d'inclure (protège contre une preuve réutilisée).
pub fn verify_reserve(text: &str, chain: &Chain, expected_challenge: Option<&str>) -> Result<ReserveInfo, String> {
    let body = text.trim().strip_prefix(PROOF_PREFIX).ok_or("ce n'est pas une preuve de réserve NumFranc")?;
    let raw = from_hex(body).ok_or("preuve illisible")?;
    let mut r = Reader::new(&raw);
    let bad = |_| "preuve illisible".to_string();
    let height = r.u64().map_err(bad)?;
    let hash: [u8; 64] = r.array().map_err(bad)?;
    let claimed = r.u64().map_err(bad)?;
    let clen = r.u8().map_err(bad)? as usize;
    let challenge = String::from_utf8(r.bytes(clen).map_err(bad)?.to_vec()).map_err(|_| "preuve illisible".to_string())?;
    let n = r.u8().map_err(bad)? as usize;
    if n == 0 || n > MAX_PROOF_ADDRESSES {
        return Err("nombre d'adresses invalide dans la preuve".into());
    }
    let msg = reserve_message(height, &hash, claimed, &challenge);
    let mut addresses = Vec::new();
    for _ in 0..n {
        let pk = r.bytes(PUBLIC_KEY_SIZE).map_err(bad)?;
        let sig = r.bytes(SIGNATURE_SIZE).map_err(bad)?;
        if !verify(pk, &msg, sig) {
            return Err("une signature de la preuve est fausse".into());
        }
        let a = address_of_pubkey(pk);
        if addresses.contains(&a) {
            return Err("adresse répétée dans la preuve".into());
        }
        addresses.push(a);
    }
    r.finish().map_err(bad)?;
    if chain.hash_at(height) != Some(hash) {
        return Err("le bloc cité par la preuve n'est pas dans votre chaîne (pas encore à jour, ou autre chaîne)".into());
    }
    if let Some(c) = expected_challenge {
        if c != challenge {
            return Err(format!("le mot de la preuve (« {challenge} ») n'est pas celui attendu (« {c} »)"));
        }
    }
    let proven: u64 = chain.utxo.values().filter(|u| addresses.contains(&u.address)).map(|u| u.amount).sum();
    if proven < claimed {
        return Err("les fonds ne sont plus tous sur ces adresses".into());
    }
    Ok(ReserveInfo { claimed, proven, height, age_blocks: chain.height().saturating_sub(height), challenge, addresses })
}

// ---------- Multi-signature : propositions ----------

const PROPOSAL_PREFIX: &str = "NFRMS1-";

/// Ce que contient une proposition de paiement multi-signature, pour la relire avant de signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalInfo {
    pub outputs: Vec<(Address, u64)>,
    /// None si une entrée est inconnue de ma chaîne.
    pub fee: Option<u64>,
    pub memo: String,
    /// (signatures présentes, signatures requises) pour chaque entrée.
    pub signatures: Vec<(usize, u8)>,
    pub ready: bool,
    pub i_am_member: bool,
    pub i_signed: bool,
}

pub fn proposal_to_tx(text: &str) -> Result<Transaction, String> {
    let body = text.trim().strip_prefix(PROPOSAL_PREFIX).ok_or("ce n'est pas une proposition NumFranc (NFRMS1-…)")?;
    let raw = from_hex(body).ok_or("proposition illisible")?;
    let tx = Transaction::from_bytes(&raw).map_err(|e| format!("proposition illisible : {}", e.0))?;
    if tx.inputs.is_empty() || tx.inputs.iter().any(|i| i.multi.is_none()) {
        return Err("cette proposition ne contient pas que des entrées multi-signature".into());
    }
    Ok(tx)
}

fn tx_to_proposal(tx: &Transaction) -> String {
    format!("{PROPOSAL_PREFIX}{}", hex(&tx.serialize()))
}

/// Transaction multi-signature complète (le seuil de signatures est atteint pour chaque entrée), prête à être envoyée.
pub fn finalize_proposal(text: &str) -> Result<Transaction, String> {
    let tx = proposal_to_tx(text)?;
    tx.check_stateless().map_err(|e| format!("proposition incomplète ou invalide : {}", e.0))?;
    Ok(tx)
}

/// Taille d'une entrée multi-signature complète (seuil m, n membres).
fn multi_input_size(m: usize, n: usize) -> usize {
    64 + 4 + 1 + 1 + 1 + 32 * n + 1 + m * (1 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
}

impl Wallet {
    // ---------- Construction générale d'une transaction ----------

    /// Choisit les fonds, calcule les frais, rend la monnaie vers une adresse neuve et signe.
    pub(crate) fn build_tx(&mut self, chain: &Chain, mempool: &Mempool, spec: BuildSpec, spend_code: Option<&str>) -> Result<Transaction, String> {
        let next = chain.height() + 1;
        let mtp = chain.next_mtp();
        let amount = spec.outputs.iter().try_fold(0u64, |a, o| a.checked_add(o.amount)).ok_or("montant trop grand")?;
        let mut usable: Vec<(Address, OutPoint, u64)> = chain
            .utxo
            .iter()
            .filter(|(op, u)| {
                self.is_mine(&u.address)
                    && !(u.coinbase && next < u.height + COINBASE_MATURITY)
                    && is_unlocked(u.lock_until, next, mtp)
                    && !mempool.spends(op)
            })
            .map(|(op, u)| (u.address, *op, u.amount))
            .collect();
        let prefer = spec.prefer;
        usable.sort_by(|a, b| {
            let pa = prefer.is_some_and(|p| a.0 == p);
            let pb = prefer.is_some_and(|p| b.0 == p);
            pb.cmp(&pa).then(b.2.cmp(&a.2)).then(a.1.txid.cmp(&b.1.txid)).then(a.1.vout.cmp(&b.1.vout))
        });

        let memo_len = spec.memo.len();
        let name_bytes = spec.name_op.as_ref().map(|n| 3 + n.name.len() + 32).unwrap_or(0);
        let outs_size = (spec.outputs.len() + 1) * 77;
        let size_for = move |n_in: usize| 10 + n_in * 7_288 + outs_size + 1 + memo_len + 1 + name_bytes + 8;
        let need_change = u64::from(spec.outputs.is_empty());
        let mut chosen: Vec<(Address, OutPoint, u64)> = Vec::new();
        let mut total = 0u64;
        let mut fee = min_fee(size_for(1)) + spec.extra_fee;
        for u in usable {
            total += u.2;
            chosen.push(u);
            fee = min_fee(size_for(chosen.len())) + spec.extra_fee;
            if total >= amount + fee + need_change {
                break;
            }
        }
        if total < amount + fee + need_change {
            let bal = self.balance(chain, mempool);
            return Err(crate::tf!(
                "fonds insuffisants : disponible {}, en maturation {}, verrouillé {} (frais {})",
                "insufficient funds: available {}, maturing {}, locked {} (fee {})",
                crate::wallet::format_amount(bal.available),
                crate::wallet::format_amount(bal.immature),
                crate::wallet::format_amount(bal.locked),
                crate::wallet::format_amount(fee)
            ));
        }
        if let Some(p) = prefer {
            if !chosen.iter().any(|c| c.0 == p) {
                return Err(crate::i18n::t(
                    "il faut des fonds disponibles sur l'adresse propriétaire du pseudo pour prouver que c'est vous",
                    "funds are needed on the name owner's address to prove it is you",
                )
                .into());
            }
        }

        // Déchiffre la graine (et vérifie le code de dépense) AVANT de toucher à quoi que ce soit.
        let seed = self.seed_with(spend_code)?;
        let change = total - amount - fee;
        let mut outputs = spec.outputs;
        if change > 0 {
            let c = self.new_key();
            outputs.push(TxOut::new(change, c));
        }
        let mut tx = Transaction::new(Vec::new(), outputs, spec.memo);
        tx.name_op = spec.name_op;
        let mut keypairs = Vec::new();
        for (a, op, _) in &chosen {
            let kp = derive(&seed, self.by_addr[a] as u32);
            tx.inputs.push(TxIn::single(*op, kp.public_key_bytes().to_vec(), vec![0; SIGNATURE_SIZE]));
            keypairs.push(kp);
        }
        let sighash = tx.sighash();
        for (i, kp) in keypairs.iter().enumerate() {
            tx.inputs[i].signature = kp.sign(&sighash).map_err(|e| e.to_string())?.to_vec();
        }
        if tx.size() > size_for(chosen.len()) {
            return Err("erreur interne d'estimation de taille".into());
        }
        self.save()?;
        Ok(tx)
    }

    /// Adresse principale (permanente).
    pub fn keys_main(&self) -> Address {
        self.keys[0].0
    }

    // ---------- Gel ----------

    pub fn is_frozen(&self) -> bool {
        self.frozen.is_some()
    }

    /// Vérifie le mot de passe d'ouverture (sans rien changer).
    pub fn check_open_password(&self, pw: &str) -> Result<(), String> {
        let (key, p, salt) = self.view.as_ref().ok_or("portefeuille non chiffré")?;
        let k2 = vault::derive_key(pw, salt, *p)?;
        let diff = key.iter().zip(k2.iter()).fold(0u8, |a, (x, y)| a | (x ^ y));
        if diff == 0 { Ok(()) } else { Err(crate::i18n::t("mot de passe d'ouverture incorrect", "wrong opening password").into()) }
    }

    /// Gèle le portefeuille : la graine est RETIRÉE de cet ordinateur (il n'en reste qu'une empreinte).
    /// Même avec les deux mots de passe, plus rien ne peut être envoyé d'ici ; seuls deux morceaux
    /// du code de secours permettent de dégeler. Recevoir et miner continuent de fonctionner.
    pub fn freeze(&mut self, spend_code: &str) -> Result<(), String> {
        if self.frozen.is_some() {
            return Err(crate::i18n::t("le portefeuille est déjà gelé", "the wallet is already frozen").into());
        }
        if self.vault.is_none() {
            return Err("protégez d'abord le portefeuille par des mots de passe".into());
        }
        let seed = self.seed_with(Some(spend_code))?;
        self.frozen = Some(freeze_tag(&seed));
        self.vault = None;
        self.save()
    }

    /// Dégel : mot de passe d'ouverture, code de dépense (qui re-scelle la graine) et deux morceaux du code de secours.
    pub fn unfreeze(&mut self, open_pw: &str, spend_code: &str, share_a: &str, share_b: &str) -> Result<(), String> {
        let tag = self.frozen.ok_or(crate::i18n::t("le portefeuille n'est pas gelé", "the wallet is not frozen"))?;
        self.check_open_password(open_pw)?;
        vault::check_password(spend_code, vault::MIN_SPEND_CODE, "Code de dépense")?;
        if spend_code == open_pw {
            return Err(crate::i18n::t("le code de dépense doit être différent du mot de passe d'ouverture", "the spending code must differ from the opening password").into());
        }
        let seed = vault::join_shares(share_a, share_b)?;
        if freeze_tag(&seed) != tag || address_of_pubkey(&derive(&seed, 0).public_key_bytes()) != self.keys[0].0 {
            return Err(crate::i18n::t("ces morceaux de secours ne correspondent pas à ce portefeuille", "these recovery pieces do not match this wallet").into());
        }
        let p = self.view.as_ref().map(|v| v.1).unwrap_or(vault::STRONG);
        let vp = vault::vault_params(p);
        let salt: [u8; 32] = vault::random()?;
        let key = vault::derive_key(spend_code, &salt, vp)?;
        self.vault = Some(vault::seal(&key, vp, salt, b"coffre", seed.as_slice())?);
        self.frozen = None;
        self.save()
    }

    // ---------- Protection des gros paiements ----------

    pub fn protection(&self) -> Option<&Protection> {
        self.protection.as_ref()
    }

    pub fn set_protection(&mut self, p: Option<Protection>) -> Result<(), String> {
        if let Some(p) = &p {
            if p.threshold == 0 {
                return Err(crate::i18n::t("le seuil doit être positif", "the threshold must be positive").into());
            }
            if p.delay_secs == 0 || p.delay_secs > 30 * 86_400 {
                return Err(crate::i18n::t("le délai doit être compris entre 1 seconde et 30 jours", "the delay must be between 1 second and 30 days").into());
            }
        }
        self.protection = p;
        self.save()
    }

    /// Paiements que j'ai envoyés et que je peux encore reprendre (avant leur date de déblocage).
    pub fn retained_by_me(&self, chain: &Chain) -> Vec<Retained> {
        let next = chain.height() + 1;
        let mtp = chain.next_mtp();
        let mut v: Vec<Retained> = chain
            .utxo
            .iter()
            .filter_map(|(op, u)| {
                let c = u.cancel?;
                (self.is_mine(&c) && !is_unlocked(u.lock_until, next, mtp))
                    .then(|| Retained { op: *op, amount: u.amount, to: u.address, unlock: u.lock_until, cancel: c, height: u.height })
            })
            .collect();
        v.sort_by_key(|r| (r.unlock, r.height));
        v
    }

    /// Reprend un paiement retenu : les fonds reviennent sur une adresse neuve de ce portefeuille.
    pub fn cancel_retained(&mut self, chain: &Chain, mempool: &Mempool, op: OutPoint, spend_code: Option<&str>) -> Result<Transaction, String> {
        let u = chain.utxo.get(&op).ok_or(crate::i18n::t("ce paiement n'existe plus (déjà reçu ou annulé ?)", "this payment no longer exists (already claimed or cancelled?)"))?;
        let cancel = u.cancel.ok_or(crate::i18n::t("ce paiement n'est pas annulable", "this payment cannot be cancelled"))?;
        if !self.is_mine(&cancel) {
            return Err(crate::i18n::t("ce paiement n'est pas annulable depuis ce portefeuille", "this payment cannot be cancelled from this wallet").into());
        }
        if is_unlocked(u.lock_until, chain.height() + 1, chain.next_mtp()) {
            return Err(crate::i18n::t("la date de déblocage est passée : le destinataire peut le dépenser, trop tard pour annuler", "the unlock date has passed: the recipient can spend it, too late to cancel").into());
        }
        if mempool.spends(&op) {
            return Err(crate::i18n::t("une annulation est déjà en attente", "a cancellation is already pending").into());
        }
        let fee = min_fee(10 + 7_288 + 77 + 1 + 1 + 8);
        if u.amount <= fee {
            return Err("montant trop petit pour couvrir les frais".into());
        }
        let amount = u.amount;
        let seed = self.seed_with(spend_code)?;
        let kp = derive(&seed, self.by_addr[&cancel] as u32);
        let dest = self.new_key();
        let mut tx = Transaction::new(
            vec![TxIn::single(op, kp.public_key_bytes().to_vec(), vec![0; SIGNATURE_SIZE])],
            vec![TxOut::new(amount - fee, dest)],
            Vec::new(),
        );
        tx.inputs[0].signature = kp.sign(&tx.sighash()).map_err(|e| e.to_string())?.to_vec();
        self.save()?;
        Ok(tx)
    }

    // ---------- Pseudos ----------

    /// Pseudo écrit par l'utilisateur : minuscules, sans le suffixe « .nfr ».
    pub fn normalize_name(s: &str) -> String {
        let s = s.trim().to_lowercase();
        s.strip_suffix(".nfr").unwrap_or(&s).to_string()
    }

    /// Destinataire : nom du carnet, adresse NFR1-… ou pseudo « alice.nfr » (lu dans la chaîne).
    pub fn resolve_recipient_with(&self, s: &str, chain: &Chain) -> Result<Address, String> {
        if let Some(a) = self.contact_address(s) {
            return Ok(a);
        }
        let t = s.trim().to_lowercase();
        if t.ends_with(".nfr") {
            let name = Self::normalize_name(&t);
            check_name(&name).map_err(|e| e.to_string())?;
            return chain
                .names
                .get(&name)
                .map(|e| e.owner)
                .ok_or_else(|| crate::tf!("le pseudo « {}.nfr » n'existe pas (encore)", "the name “{}.nfr” does not exist (yet)", name));
        }
        self.resolve_recipient(s)
    }

    /// Frais supplémentaires demandés pour enregistrer ce pseudo.
    pub fn name_cost(name: &str) -> u64 {
        name_fee(Self::normalize_name(name).len())
    }

    /// Enregistre un pseudo qui désignera mon adresse principale.
    pub fn register_name(&mut self, chain: &Chain, mempool: &Mempool, name: &str, spend_code: Option<&str>) -> Result<Transaction, String> {
        let name = Self::normalize_name(name);
        check_name(&name).map_err(|e| e.to_string())?;
        if chain.names.contains_key(&name) {
            return Err(crate::tf!("« {}.nfr » est déjà pris", "“{}.nfr” is already taken", name));
        }
        // Le pseudo désigne une adresse neuve qui reçoit 0,01 NFR : c'est elle qui prouvera plus tard
        // que le pseudo est bien à vous (transfert).
        let owner = self.new_key();
        self.build_tx(
            chain,
            mempool,
            BuildSpec { outputs: vec![TxOut::new(MIN_UNIT / 100, owner)], extra_fee: name_fee(name.len()), memo: Vec::new(), name_op: Some(NameOp { kind: NameKind::Register, name, owner }), prefer: None },
            spend_code,
        )
    }

    /// Fait pointer un pseudo que je possède vers une autre adresse (transfert).
    pub fn transfer_name(&mut self, chain: &Chain, mempool: &Mempool, name: &str, new_owner: Address, spend_code: Option<&str>) -> Result<Transaction, String> {
        let name = Self::normalize_name(name);
        let cur = chain.names.get(&name).ok_or(crate::i18n::t("pseudo inconnu", "unknown name"))?;
        if !self.is_mine(&cur.owner) {
            return Err(crate::i18n::t("ce pseudo ne vous appartient pas", "this name is not yours").into());
        }
        let prefer = Some(cur.owner);
        self.build_tx(
            chain,
            mempool,
            BuildSpec { outputs: vec![], extra_fee: 0, memo: Vec::new(), name_op: Some(NameOp { kind: NameKind::Update, name, owner: new_owner }), prefer },
            spend_code,
        )
    }

    /// Pseudos qui désignent une de mes adresses : (pseudo, hauteur du premier enregistrement).
    pub fn my_names(&self, chain: &Chain) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = chain.names.iter().filter(|(_, e)| self.is_mine(&e.owner)).map(|(n, e)| (n.clone(), e.height)).collect();
        v.sort();
        v
    }

    // ---------- Groupes multi-signature ----------

    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.name.eq_ignore_ascii_case(name.trim()))
    }

    /// Crée un groupe M-sur-N à partir des adresses de ses membres (la mienne y figure en général). Renvoie l'adresse du groupe.
    pub fn add_group(&mut self, name: &str, m: u8, members: &[Address]) -> Result<Address, String> {
        let name = name.trim();
        if name.is_empty() || name.len() > 40 || name.contains(char::is_whitespace) {
            return Err(crate::i18n::t("le nom du groupe fait 1 à 40 caractères, sans espace", "the group name is 1 to 40 characters, without spaces").into());
        }
        if self.group(name).is_some() {
            return Err(crate::tf!("le groupe « {name} » existe déjà", "the group “{name}” already exists"));
        }
        let members = normalize_members(m, members).map_err(|e| e.0)?;
        let g = Group { name: name.to_string(), m, members };
        let a = g.address();
        if self.groups.iter().any(|x| x.address() == a) {
            return Err(crate::i18n::t("ce groupe existe déjà sous un autre nom", "this group already exists under another name").into());
        }
        self.groups.push(g);
        self.save()?;
        Ok(a)
    }

    pub fn remove_group(&mut self, name: &str) -> Result<(), String> {
        let before = self.groups.len();
        self.groups.retain(|g| !g.name.eq_ignore_ascii_case(name.trim()));
        if self.groups.len() == before {
            return Err(crate::tf!("groupe « {name} » inconnu", "unknown group “{name}”"));
        }
        self.save()
    }

    /// (disponible, verrouillé ou en maturation) pour l'adresse d'un groupe.
    pub fn group_balance(&self, chain: &Chain, mempool: &Mempool, g: &Group) -> (u64, u64) {
        let (next, mtp) = (chain.height() + 1, chain.next_mtp());
        let ga = g.address();
        let (mut avail, mut other) = (0u64, 0u64);
        for (op, u) in chain.utxo.iter().filter(|(_, u)| u.address == ga) {
            if (u.coinbase && next < u.height + COINBASE_MATURITY) || !is_unlocked(u.lock_until, next, mtp) || mempool.spends(op) {
                other += u.amount;
            } else {
                avail += u.amount;
            }
        }
        (avail, other)
    }

    /// Prépare un paiement depuis un groupe : renvoie une proposition à faire signer par ses membres. Aucun secret n'est utilisé.
    pub fn ms_propose(&self, chain: &Chain, mempool: &Mempool, group: &str, to: Address, amount: u64, memo: &str) -> Result<String, String> {
        let g = self.group(group).ok_or_else(|| crate::tf!("groupe « {group} » inconnu", "unknown group “{group}”"))?;
        if memo.len() > MAX_MEMO {
            return Err(crate::tf!("message trop long : {} octets sur {MAX_MEMO}", "message too long: {} bytes out of {MAX_MEMO}", memo.len()));
        }
        let (next, mtp) = (chain.height() + 1, chain.next_mtp());
        let ga = g.address();
        let mut usable: Vec<(OutPoint, u64)> = chain
            .utxo
            .iter()
            .filter(|(op, u)| u.address == ga && !(u.coinbase && next < u.height + COINBASE_MATURITY) && is_unlocked(u.lock_until, next, mtp) && !mempool.spends(op))
            .map(|(op, u)| (*op, u.amount))
            .collect();
        usable.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.txid.cmp(&b.0.txid)).then(a.0.vout.cmp(&b.0.vout)));
        let (m, n) = (g.m as usize, g.members.len());
        let size_for = |n_in: usize| 10 + n_in * multi_input_size(m, n) + 2 * 77 + 1 + memo.len() + 1 + 8;
        let mut chosen = Vec::new();
        let mut total = 0u64;
        let mut fee = min_fee(size_for(1));
        for u in usable {
            total += u.1;
            chosen.push(u);
            fee = min_fee(size_for(chosen.len()));
            if total >= amount + fee {
                break;
            }
        }
        if total < amount + fee {
            return Err(crate::tf!(
                "fonds insuffisants dans le groupe : {} disponibles pour {} + frais {}",
                "not enough funds in the group: {} available for {} + fee {}",
                crate::wallet::format_amount(total),
                crate::wallet::format_amount(amount),
                crate::wallet::format_amount(fee)
            ));
        }
        let mut outputs = vec![TxOut::new(amount, to)];
        let change = total - amount - fee;
        if change > 0 {
            outputs.push(TxOut::new(change, ga));
        }
        let inputs = chosen.iter().map(|(op, _)| TxIn::multisig(*op, g.m, g.members.clone())).collect();
        let tx = Transaction::new(inputs, outputs, memo.as_bytes().to_vec());
        Ok(tx_to_proposal(&tx))
    }

    /// Relecture d'une proposition avant de signer : où va l'argent, combien de frais, qui a signé.
    pub fn ms_info(&self, text: &str, chain: &Chain) -> Result<ProposalInfo, String> {
        let tx = proposal_to_tx(text)?;
        let mut in_sum = Some(0u64);
        for i in &tx.inputs {
            in_sum = match (in_sum, chain.utxo.get(&i.prev)) {
                (Some(s), Some(u)) => Some(s + u.amount),
                _ => None,
            };
        }
        let out_sum = tx.output_sum().unwrap_or(0);
        let mut signatures = Vec::new();
        let (mut member, mut signed) = (false, false);
        for i in &tx.inputs {
            let w = i.multi.as_ref().unwrap();
            signatures.push((w.sigs.len(), w.m));
            let mine: Vec<usize> = w.members.iter().enumerate().filter(|(_, a)| self.is_mine(a)).map(|(k, _)| k).collect();
            member |= !mine.is_empty();
            signed |= w.sigs.iter().any(|s| mine.contains(&(s.index as usize)));
        }
        Ok(ProposalInfo {
            outputs: tx.outputs.iter().map(|o| (o.address, o.amount)).collect(),
            fee: in_sum.map(|s| s.saturating_sub(out_sum)),
            memo: String::from_utf8_lossy(&tx.memo).into_owned(),
            ready: signatures.iter().all(|(h, m)| *h == *m as usize),
            signatures,
            i_am_member: member,
            i_signed: signed,
        })
    }

    /// Ajoute ma signature à chaque entrée de la proposition et renvoie la proposition mise à jour.
    pub fn ms_sign(&mut self, text: &str, spend_code: Option<&str>) -> Result<String, String> {
        let mut tx = proposal_to_tx(text)?;
        // Contrôle avant de déchiffrer quoi que ce soit : suis-je membre, ai-je déjà signé ?
        for i in &tx.inputs {
            let w = i.multi.as_ref().unwrap();
            let Some(k) = w.members.iter().position(|a| self.is_mine(a)) else {
                return Err(crate::i18n::t("vous n'êtes pas membre de ce groupe", "you are not a member of this group").into());
            };
            if w.sigs.iter().any(|s| s.index as usize == k) {
                return Err(crate::i18n::t("vous avez déjà signé cette proposition", "you have already signed this proposal").into());
            }
            if w.sigs.len() >= w.m as usize {
                return Err(crate::i18n::t("il y a déjà assez de signatures", "there are already enough signatures").into());
            }
        }
        let seed = self.seed_with(spend_code)?;
        let sighash = tx.sighash();
        for i in tx.inputs.iter_mut() {
            let w = i.multi.as_mut().unwrap();
            let k = w.members.iter().position(|a| self.by_addr.contains_key(a)).unwrap();
            let kp: KeyPair = derive(&seed, self.by_addr[&w.members[k]] as u32);
            w.sigs.push(PartialSig { index: k as u8, pubkey: kp.public_key_bytes().to_vec(), signature: kp.sign(&sighash).map_err(|e| e.to_string())?.to_vec() });
            w.sigs.sort_by_key(|s| s.index);
        }
        Ok(tx_to_proposal(&tx))
    }

    // ---------- Preuve de réserve ----------

    /// Prouve que ce portefeuille détient au moins `min_amount` unités, en ne révélant que les adresses nécessaires.
    pub fn prove_reserve(&mut self, chain: &Chain, min_amount: u64, challenge: &str, spend_code: Option<&str>) -> Result<String, String> {
        if challenge.len() > 60 {
            return Err(crate::i18n::t("le mot de défi fait 60 octets au maximum", "the challenge word is 60 bytes at most").into());
        }
        let mut per_addr: HashMap<Address, u64> = HashMap::new();
        for u in chain.utxo.values().filter(|u| self.is_mine(&u.address)) {
            *per_addr.entry(u.address).or_insert(0) += u.amount;
        }
        let mut list: Vec<(Address, u64)> = per_addr.into_iter().collect();
        list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let (mut chosen, mut sum) = (Vec::new(), 0u64);
        for (a, v) in list {
            if sum >= min_amount {
                break;
            }
            sum += v;
            chosen.push(a);
        }
        if sum < min_amount || chosen.is_empty() || chosen.len() > MAX_PROOF_ADDRESSES {
            return Err(crate::i18n::t("vous ne détenez pas ce montant (ou il est réparti sur trop d'adresses)", "you do not hold this amount (or it is spread over too many addresses)").into());
        }
        let seed: Zeroizing<[u8; 32]> = self.seed_with(spend_code)?;
        let height = chain.height();
        let hash = chain.hash_at(height).ok_or("chaîne vide")?;
        let msg = reserve_message(height, &hash, min_amount, challenge);
        let mut raw = Vec::new();
        raw.extend_from_slice(&height.to_be_bytes());
        raw.extend_from_slice(&hash);
        raw.extend_from_slice(&min_amount.to_be_bytes());
        raw.push(challenge.len() as u8);
        raw.extend_from_slice(challenge.as_bytes());
        raw.push(chosen.len() as u8);
        for a in &chosen {
            let kp = derive(&seed, self.by_addr[a] as u32);
            raw.extend_from_slice(&kp.public_key_bytes());
            raw.extend_from_slice(&kp.sign(&msg).map_err(|e| e.to_string())?);
        }
        Ok(format!("{PROOF_PREFIX}{}", hex(&raw)))
    }
}

/// Texte d'une adresse de groupe, pour l'affichage.
pub fn group_address_string(g: &Group) -> String {
    address_to_string(&multisig_address(g.m, &g.members))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::PaymentOptions;
    use crate::chain::tests::{make_block, test_genesis};
    use crate::config::GENESIS_TIMESTAMP;

    fn now() -> u64 {
        GENESIS_TIMESTAMP + 10_000_000
    }

    /// Mine `n` blocs dont les récompenses vont au portefeuille.
    fn mined(w: &mut Wallet, n: u64) -> Chain {
        let mut c = Chain::with_genesis(test_genesis());
        for _ in 0..n {
            let to = w.mining_address();
            let b = make_block(&c, c.tip(), vec![], to, 691, b"");
            c.add_block(b, now()).unwrap();
            w.rotate_mining_address();
        }
        c
    }

    fn add(c: &mut Chain, txs: Vec<Transaction>) {
        let b = make_block(c, c.tip(), txs, [0; 32], 691, b"");
        c.add_block(b, now()).unwrap();
    }

    const MATURE: u64 = COINBASE_MATURITY + 10;

    #[test]
    fn lien_de_paiement_aller_retour() {
        let a = address_to_string(&[7; 32]);
        let uri = payment_uri(&a, Some(1_250_000_000), "Merci pour le déjeuner, à 12 h & plus !");
        let r = parse_payment_uri(&uri).unwrap();
        assert_eq!(r, PaymentRequest { recipient: a.clone(), amount: Some(1_250_000_000), message: "Merci pour le déjeuner, à 12 h & plus !".into() });
        assert_eq!(parse_payment_uri(&payment_uri("alice.nfr", None, "")).unwrap(), PaymentRequest { recipient: "alice.nfr".into(), amount: None, message: String::new() });
        assert_eq!(payment_uri(&a, Some(100_000_000), ""), format!("nfr:{a}?amount=1"));
        assert!(parse_payment_uri("bitcoin:abc").is_err());
        assert!(parse_payment_uri("nfr:").is_err());
        assert!(parse_payment_uri(&format!("nfr:{a}?amount=abc")).is_err());
        assert!(parse_payment_uri(&format!("nfr:{a}?message=%ZZ")).is_err());
        assert!(parse_payment_uri(&format!("nfr:{a}?message=%FF%FE")).is_err());
        assert!(parse_payment_uri(&format!("nfr:{a}?message={}", "a".repeat(141))).is_err());
        // Paramètres inconnus ignorés, ordre libre.
        let r = parse_payment_uri(&format!("nfr:{a}?foo=1&message=Hi&amount=2,5")).unwrap();
        assert_eq!((r.amount, r.message.as_str()), (Some(250_000_000), "Hi"));
    }

    #[test]
    fn protection_paiement_retenu_et_annulation() {
        let mut w = Wallet::from_seed([42; 32]);
        let mut c = mined(&mut w, MATURE);
        let friend = Wallet::from_seed([1; 32]).keys[0].0;
        w.set_protection(Some(Protection { threshold: 500_000_000, delay_secs: 3_600, guardian: None })).unwrap();
        let mp = Mempool::default();

        // Petit paiement : aucune retenue. Gros paiement : retenu et annulable.
        let small = w.create_payment(&c, &mp, friend, 100_000_000, &PaymentOptions::default(), None).unwrap();
        assert_eq!(small.outputs[0].cancel, None);
        let big = w.create_payment(&c, &mp, friend, 1_000_000_000, &PaymentOptions::default(), None).unwrap();
        assert_eq!(big.outputs[0].cancel, Some(w.keys[0].0));
        assert_eq!(big.outputs[0].lock_until as u64, c.next_mtp() + 3_600);
        let mut mp = Mempool::default();
        mp.accept(big.clone(), &c).unwrap();
        w.mark_spent(&big);
        add(&mut c, vec![big]);

        // Je vois le paiement en attente, je peux l'annuler ; le destinataire ne peut pas encore le dépenser.
        let pending = w.retained_by_me(&c);
        assert_eq!(pending.len(), 1);
        assert_eq!((pending[0].amount, pending[0].to), (1_000_000_000, friend));
        let before = w.balance(&c, &Mempool::default()).available;
        let cancel = w.cancel_retained(&c, &Mempool::default(), pending[0].op, None).unwrap();
        cancel.check_stateless().unwrap();
        let mut mp2 = Mempool::default();
        mp2.accept(cancel.clone(), &c).unwrap();
        add(&mut c, vec![cancel]);
        assert!(w.retained_by_me(&c).is_empty());
        let after = w.balance(&c, &Mempool::default()).available;
        assert!(after > before, "les fonds sont revenus");
        // Une seconde annulation est impossible.
        assert!(w.cancel_retained(&c, &Mempool::default(), pending[0].op, None).is_err());
    }

    #[test]
    fn gardien_externe_peut_annuler_pas_l_expediteur_seul() {
        let mut w = Wallet::from_seed([42; 32]);
        let c = mined(&mut w, MATURE);
        let guardian = Wallet::from_seed([77; 32]);
        let g_addr = guardian.keys[0].0;
        w.set_protection(Some(Protection { threshold: 1, delay_secs: 3_600, guardian: Some(g_addr) })).unwrap();
        let tx = w.create_payment(&c, &Mempool::default(), [9; 32], 100_000_000, &PaymentOptions::default(), None).unwrap();
        assert_eq!(tx.outputs[0].cancel, Some(g_addr));
        // Le portefeuille de l'expéditeur lui-même ne peut pas annuler : seul le gardien le peut.
        let mut c2 = c;
        add(&mut c2, vec![tx]);
        assert!(w.retained_by_me(&c2).is_empty());
        assert_eq!(guardian.retained_by_me(&c2).len(), 1);
    }

    #[test]
    fn reglages_de_protection_valides() {
        let mut w = Wallet::from_seed([1; 32]);
        assert!(w.set_protection(Some(Protection { threshold: 0, delay_secs: 60, guardian: None })).is_err());
        assert!(w.set_protection(Some(Protection { threshold: 1, delay_secs: 0, guardian: None })).is_err());
        assert!(w.set_protection(Some(Protection { threshold: 1, delay_secs: 31 * 86_400, guardian: None })).is_err());
        assert!(w.set_protection(Some(Protection { threshold: 1, delay_secs: 86_400, guardian: None })).is_ok());
        assert!(w.set_protection(None).is_ok());
    }

    #[test]
    fn pseudo_enregistrer_resoudre_payer_et_transferer() {
        let mut w = Wallet::from_seed([42; 32]);
        let mut c = mined(&mut w, MATURE);
        let mp = Mempool::default();
        let tx = w.register_name(&c, &mp, "Alice.nfr", None).unwrap();
        tx.check_stateless().unwrap();
        assert_eq!(tx.name_op.as_ref().unwrap().name, "alice");
        let mut mpool = Mempool::default();
        mpool.accept(tx.clone(), &c).unwrap();
        w.mark_spent(&tx);
        add(&mut c, vec![tx]);
        assert_eq!(w.my_names(&c).iter().map(|n| n.0.as_str()).collect::<Vec<_>>(), vec!["alice"]);

        // Un autre portefeuille peut payer « alice.nfr » ; un pseudo inconnu est refusé.
        let other = Wallet::from_seed([5; 32]);
        let owner = c.names["alice"].owner;
        assert_eq!(other.resolve_recipient_with("alice.nfr", &c).unwrap(), owner);
        assert_eq!(other.resolve_recipient_with("ALICE.NFR", &c).unwrap(), owner);
        assert!(other.resolve_recipient_with("inconnu.nfr", &c).is_err());
        assert!(other.resolve_recipient_with("a.nfr", &c).is_err());
        // Déjà pris, non valide, ou frais insuffisants.
        assert!(w.register_name(&c, &mp, "alice", None).is_err());
        assert!(w.register_name(&c, &mp, "Pas Valide", None).is_err());

        // Transfert : seul le propriétaire peut le faire ; l'autre portefeuille ne le peut pas.
        let dest = other.keys[0].0;
        let mut other_w = Wallet::from_seed([5; 32]);
        assert!(other_w.transfer_name(&c, &mp, "alice", dest, None).is_err());
        let t = w.transfer_name(&c, &mp, "alice", dest, None).unwrap();
        t.check_stateless().unwrap();
        add(&mut c, vec![t]);
        assert_eq!(other.resolve_recipient_with("alice.nfr", &c).unwrap(), dest);
    }

    #[test]
    fn multisignature_de_bout_en_bout_entre_trois_portefeuilles() {
        let mut a = Wallet::from_seed([21; 32]);
        let mut b = Wallet::from_seed([22; 32]);
        let mut d = Wallet::from_seed([23; 32]);
        let members = [a.keys[0].0, b.keys[0].0, d.keys[0].0];
        let ga = a.add_group("famille", 2, &members).unwrap();
        assert_eq!(b.add_group("famille", 2, &members).unwrap(), ga);
        d.add_group("famille", 2, &members).unwrap();

        // A finance le groupe.
        let mut c = mined(&mut a, MATURE);
        let fund = a.create_payment(&c, &Mempool::default(), ga, 2_000_000_000, &PaymentOptions::default(), None).unwrap();
        add(&mut c, vec![fund]);
        let (avail, other) = b.group_balance(&c, &Mempool::default(), b.group("famille").unwrap());
        assert_eq!((avail, other), (2_000_000_000, 0));

        // B propose un paiement ; B puis D signent ; A, qui n'a pas signé, n'est pas nécessaire.
        let dest = [9u8; 32];
        let p0 = b.ms_propose(&c, &Mempool::default(), "famille", dest, 500_000_000, "Cadeau").unwrap();
        let info = b.ms_info(&p0, &c).unwrap();
        assert_eq!(info.outputs[0], (dest, 500_000_000));
        assert_eq!(info.memo, "Cadeau");
        assert!(info.fee.unwrap() > 0 && !info.ready && info.i_am_member && !info.i_signed);
        assert!(finalize_proposal(&p0).is_err());
        let p1 = b.ms_sign(&p0, None).unwrap();
        assert!(b.ms_sign(&p1, None).is_err(), "pas de double signature");
        assert!(!b.ms_info(&p1, &c).unwrap().ready);
        assert!(b.ms_info(&p1, &c).unwrap().i_signed);
        let p2 = d.ms_sign(&p1, None).unwrap();
        assert!(d.ms_info(&p2, &c).unwrap().ready);
        assert!(a.ms_sign(&p2, None).is_err(), "assez de signatures");
        // Un étranger au groupe ne peut pas signer.
        let mut stranger = Wallet::from_seed([99; 32]);
        assert!(stranger.ms_sign(&p0, None).is_err());

        let tx = finalize_proposal(&p2).unwrap();
        let mut mp = Mempool::default();
        mp.accept(tx.clone(), &c).unwrap();
        add(&mut c, vec![tx]);
        let received: u64 = c.utxo.values().filter(|u| u.address == dest).map(|u| u.amount).sum();
        assert_eq!(received, 500_000_000);
        // La monnaie est restée dans le groupe.
        let (avail, _) = b.group_balance(&c, &Mempool::default(), b.group("famille").unwrap());
        assert!(avail > 1_400_000_000 && avail < 1_500_000_000);
    }

    #[test]
    fn regles_des_groupes_du_portefeuille() {
        let mut w = Wallet::from_seed([1; 32]);
        assert!(w.add_group("deux mots", 1, &[[1; 32], [2; 32]]).is_err());
        assert!(w.add_group("g", 3, &[[1; 32], [2; 32]]).is_err());
        assert!(w.add_group("g", 1, &[[1; 32], [1; 32]]).is_err());
        let a = w.add_group("g", 1, &[[2; 32], [1; 32]]).unwrap();
        assert_eq!(a, multisig_address(1, &[[1; 32], [2; 32]]));
        assert!(w.add_group("G", 1, &[[3; 32], [4; 32]]).is_err());
        assert!(w.add_group("h", 1, &[[1; 32], [2; 32]]).is_err());
        w.remove_group("g").unwrap();
        assert!(w.remove_group("g").is_err());
    }

    #[test]
    fn preuve_de_reserve_valide_refusee_si_falsifiee() {
        let mut w = Wallet::from_seed([42; 32]);
        let c = mined(&mut w, MATURE);
        let total: u64 = c.utxo.values().filter(|u| w.is_mine(&u.address)).map(|u| u.amount).sum();
        // 2,5 récompenses : la preuve ne révèle que 3 adresses sur toutes celles du portefeuille.
        let proof = w.prove_reserve(&c, 1_500_000_000, "Banque-2026", None).unwrap();
        let info = verify_reserve(&proof, &c, Some("Banque-2026")).unwrap();
        assert_eq!((info.claimed, info.addresses.len(), info.age_blocks), (1_500_000_000, 3, 0));
        assert!(info.proven >= 1_500_000_000);
        assert!(w.prove_reserve(&c, total + 1, "", None).is_err());
        // Mauvais mot de défi, texte abîmé, montant gonflé, bloc inconnu.
        assert!(verify_reserve(&proof, &c, Some("Autre")).is_err());
        let mut bad = proof.clone();
        bad.replace_range(bad.len() - 20..bad.len() - 18, "ff");
        assert!(verify_reserve(&bad, &c, None).is_err());
        assert!(verify_reserve("NFRPROOF1-00", &c, None).is_err());
        assert!(verify_reserve("n'importe quoi", &c, None).is_err());
        let mut raw = from_hex(proof.strip_prefix(PROOF_PREFIX).unwrap()).unwrap();
        raw[72..80].copy_from_slice(&(total * 2).to_be_bytes()); // montant réclamé modifié
        assert!(verify_reserve(&format!("{PROOF_PREFIX}{}", hex(&raw)), &c, None).is_err());
        // Une autre chaîne ne reconnaît pas le bloc cité.
        let empty = Chain::with_genesis(test_genesis());
        assert!(verify_reserve(&proof, &empty, None).is_err());
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nfr-plus-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const OUV: &str = "Ouverture-Test-2026";
    const DEP: &str = "Depense#Code42-Plage";

    #[test]
    fn gel_et_degel_avec_les_trois_codes() {
        let dir = temp_dir("gel");
        let p = dir.join("wallet.dat");
        let (mut w, shares) = Wallet::create_encrypted(&p, OUV, DEP, vault::TEST).unwrap();
        let main = w.keys[0].0;
        let c = mined(&mut w, MATURE);
        let mp = Mempool::default();
        w.create_payment(&c, &mp, [9; 32], 100_000_000, &PaymentOptions::default(), Some(DEP)).unwrap();

        // Gel : mauvais code refusé ; avec le bon, la graine disparaît du fichier.
        assert!(w.freeze("Mauvais#Code-Faux-1234").is_err());
        w.freeze(DEP).unwrap();
        assert!(w.is_frozen() && w.is_encrypted());
        assert!(w.create_payment(&c, &mp, [9; 32], 100_000_000, &PaymentOptions::default(), Some(DEP)).unwrap_err().contains("gelé"));
        // Rouvrir le fichier : toujours gelé, les adresses sont là, plus aucune graine, même avec les deux mots de passe.
        let mut w2 = Wallet::unlock(&p, OUV).unwrap();
        assert!(w2.is_frozen());
        assert_eq!(w2.keys[0].0, main);
        assert_eq!(w2.balance(&c, &mp), w.balance(&c, &mp));
        assert!(w2.create_payment(&c, &mp, [9; 32], 100_000_000, &PaymentOptions::default(), Some(DEP)).is_err());
        assert!(w2.recovery_shares(DEP).is_err());
        let file = std::fs::read(&p).unwrap();
        let seed = vault::join_shares(&shares[0], &shares[1]).unwrap();
        assert!(!file.windows(32).any(|x| x == seed.as_slice()));
        assert!(w2.freeze(DEP).is_err());

        // Dégel : refus si un des codes est faux ou si les morceaux sont ceux d'un autre portefeuille.
        let (_, other_shares) = Wallet::create_encrypted(&dir.join("autre.dat"), OUV, DEP, vault::TEST).unwrap();
        assert!(w2.unfreeze("Mauvais-Ouverture-99", DEP, &shares[0], &shares[1]).is_err());
        assert!(w2.unfreeze(OUV, DEP, &other_shares[0], &other_shares[1]).is_err());
        assert!(w2.unfreeze(OUV, DEP, &shares[0], &shares[0]).is_err());
        assert!(w2.unfreeze(OUV, "court", &shares[0], &shares[1]).is_err());
        assert!(w2.is_frozen());
        w2.unfreeze(OUV, "Nouveau#Code99-Tambour", &shares[2], &shares[0]).unwrap();
        assert!(!w2.is_frozen());
        let tx = w2.create_payment(&c, &mp, [9; 32], 100_000_000, &PaymentOptions::default(), Some("Nouveau#Code99-Tambour")).unwrap();
        tx.check_stateless().unwrap();
        // L'ancien code ne marche plus, le nouveau marche, et l'état dégelé survit à la réouverture.
        let w3 = Wallet::unlock(&p, OUV).unwrap();
        assert!(!w3.is_frozen());
        assert!(w3.check_spend_code(DEP).is_err());
        w3.check_spend_code("Nouveau#Code99-Tambour").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reglages_conserves_apres_fermeture() {
        let dir = temp_dir("reglages");
        let p = dir.join("wallet.dat");
        let (mut w, _) = Wallet::create_encrypted(&p, OUV, DEP, vault::TEST).unwrap();
        w.set_protection(Some(Protection { threshold: 123, delay_secs: 7_200, guardian: Some([4; 32]) })).unwrap();
        w.add_group("famille", 2, &[[1; 32], [2; 32], [3; 32]]).unwrap();
        let w2 = Wallet::unlock(&p, OUV).unwrap();
        assert_eq!(w2.protection(), Some(&Protection { threshold: 123, delay_secs: 7_200, guardian: Some([4; 32]) }));
        assert_eq!(w2.groups().len(), 1);
        assert_eq!(w2.group("FAMILLE").unwrap().m, 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ancien_fichier_v03_toujours_lisible() {
        // Un fichier NFRWAL03 (v0.4 / v0.5) n'a ni octet de coffre ni section d'options.
        let dir = temp_dir("v03");
        let p = dir.join("wallet.dat");
        let (w, _) = Wallet::create_encrypted(&p, OUV, DEP, vault::TEST).unwrap();
        let new = std::fs::read(&p).unwrap();
        // Reconstruit l'ancien format : magic 03 + vue (sans la section d'options) + coffre.
        let mut r = Reader::new(&new[8..]);
        let view_s = vault::Sealed::decode(&mut r).unwrap();
        assert_eq!(r.u8().unwrap(), 0);
        let vault_s = vault::Sealed::decode(&mut r).unwrap();
        let key = vault::derive_key(OUV, &view_s.salt, view_s.params).unwrap();
        let mut plain = vault::open(&key, b"vue", &view_s).unwrap().to_vec();
        // Retire la section d'options : 1 + 1 + 1 + 4 octets (gel absent, protection absente, 0 groupe).
        plain.truncate(plain.len() - 7);
        let old_view = vault::seal(&key, view_s.params, view_s.salt, b"vue", &plain).unwrap();
        let mut old = b"NFRWAL03".to_vec();
        old_view.encode(&mut old);
        vault_s.encode(&mut old);
        std::fs::write(&p, &old).unwrap();
        assert_eq!(crate::wallet::file_status(&p), crate::wallet::WalletFile::Encrypted);
        let w2 = Wallet::unlock(&p, OUV).unwrap();
        assert_eq!(w2.keys[0].0, w.keys[0].0);
        assert!(!w2.is_frozen() && w2.groups().is_empty() && w2.protection().is_none());
        w2.check_spend_code(DEP).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
