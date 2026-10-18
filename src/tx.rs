//! Transactions UTXO (format déclaratif, sans langage de script).
//!
//! Trois mécanismes en plus d'un paiement simple, tous décrits par des champs fixes :
//! - une sortie peut être « retenue » : jusqu'à sa date de déblocage, son expéditeur
//!   peut l'annuler (la reprendre) ; après, seul le destinataire peut la dépenser ;
//! - une entrée peut être signée à plusieurs (multi-signature M parmi N) ;
//! - une transaction peut enregistrer ou transférer un pseudo (« alice.nfr »).

use crate::config::{
    HARD_CAP, LOCK_TIME_THRESHOLD, MAX_MEMO, MAX_MULTISIG_MEMBERS, MAX_TX_SIZE, MIN_FEE_PER_KB, NAME_FEE_3, NAME_FEE_4,
    NAME_FEE_5_7, NAME_FEE_8_PLUS, NAME_MAX_LEN, NAME_MIN_LEN,
};
use crate::encoding::{put_varint, DecodeError, Reader};
use crate::hashing::{hash512, sha3_512};
use crate::signature::{verify, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use std::collections::HashSet;

pub type Hash = [u8; 64];
/// Adresse : les 256 premiers bits de SHA3-512(clé publique).
pub type Address = [u8; 32];
pub const COINBASE_VOUT: u32 = u32::MAX;
pub const TX_VERSION: u32 = 4;

/// Une sortie verrouillée est-elle dépensable dans un bloc de hauteur `height`
/// dont le temps médian passé (MTP) est `mtp` ? Verrou 0 = libre ; inférieur à
/// 500 000 000 = hauteur de bloc ; sinon = date Unix comparée au MTP (comme Bitcoin, BIP 113).
pub fn is_unlocked(lock: u32, height: u64, mtp: u64) -> bool {
    if lock == 0 {
        true
    } else if lock < LOCK_TIME_THRESHOLD {
        height >= lock as u64
    } else {
        mtp >= lock as u64
    }
}

/// Adresse correspondant à une clé publique ML-DSA-87.
pub fn address_of_pubkey(pubkey: &[u8]) -> Address {
    sha3_512(pubkey)[..32].try_into().unwrap()
}

/// Adresse d'un groupe M-sur-N : empreinte du seuil et de la liste TRIÉE des adresses des membres.
pub fn multisig_address(m: u8, members: &[Address]) -> Address {
    let mut data = b"NFR-MULTISIG".to_vec();
    data.push(m);
    data.push(members.len() as u8);
    for a in members {
        data.extend_from_slice(a);
    }
    sha3_512(&data)[..32].try_into().unwrap()
}

/// Trie et contrôle une liste de membres (2 à 15, sans doublon) et un seuil (1 à N).
pub fn normalize_members(m: u8, members: &[Address]) -> Result<Vec<Address>, TxError> {
    let mut v = members.to_vec();
    v.sort();
    if v.windows(2).any(|p| p[0] == p[1]) {
        return err("une adresse apparaît deux fois");
    }
    if v.len() < 2 || v.len() > MAX_MULTISIG_MEMBERS {
        return err("une multi-signature compte de 2 à 15 membres");
    }
    if m < 1 || m as usize > v.len() {
        return err("le seuil doit être entre 1 et le nombre de membres");
    }
    Ok(v)
}

/// Frais supplémentaires pour enregistrer un pseudo de `len` caractères.
pub fn name_fee(len: usize) -> u64 {
    match len {
        0..=3 => NAME_FEE_3,
        4 => NAME_FEE_4,
        5..=7 => NAME_FEE_5_7,
        _ => NAME_FEE_8_PLUS,
    }
}

/// Un pseudo : 3 à 32 caractères parmi a-z, 0-9 et « - » (jamais au début, à la fin ni doublé).
pub fn check_name(name: &str) -> Result<(), &'static str> {
    if name.len() < NAME_MIN_LEN || name.len() > NAME_MAX_LEN {
        return Err("un pseudo fait de 3 à 32 caractères");
    }
    if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err("un pseudo ne contient que a-z, 0-9 et le tiret");
    }
    if name.starts_with('-') || name.ends_with('-') || name.contains("--") {
        return Err("pas de tiret au début, à la fin ou doublé");
    }
    Ok(())
}

/// Référence à une sortie existante.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: Hash,
    pub vout: u32,
}

/// Signature d'un membre d'un groupe (index dans la liste triée des membres).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSig {
    pub index: u8,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Preuve d'une entrée multi-signature : le seuil, tous les membres, et au moins le seuil de signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiWitness {
    pub m: u8,
    pub members: Vec<Address>,
    pub sigs: Vec<PartialSig>,
}

/// Entrée. Pour la coinbase, `signature` contient les données coinbase (hauteur + extra).
/// Une entrée multi-signature a `multi` renseigné et laisse `pubkey` et `signature` vides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prev: OutPoint,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub multi: Option<MultiWitness>,
}

impl TxIn {
    pub fn single(prev: OutPoint, pubkey: Vec<u8>, signature: Vec<u8>) -> Self {
        Self { prev, pubkey, signature, multi: None }
    }

    /// Entrée multi-signature sans aucune signature (à compléter par les membres).
    pub fn multisig(prev: OutPoint, m: u8, members: Vec<Address>) -> Self {
        Self { prev, pubkey: Vec::new(), signature: Vec::new(), multi: Some(MultiWitness { m, members, sigs: Vec::new() }) }
    }

    pub fn is_coinbase_shaped(&self) -> bool {
        self.prev.txid == [0u8; 64] && self.prev.vout == COINBASE_VOUT
    }

    /// Adresse que cette entrée prétend dépenser (à comparer à celle de la sortie dépensée).
    pub fn spender(&self) -> Address {
        match &self.multi {
            Some(w) => multisig_address(w.m, &w.members),
            None => address_of_pubkey(&self.pubkey),
        }
    }
}

/// Sortie : un montant, l'adresse du destinataire et un verrou
/// (0 = dépensable tout de suite ; < 500 000 000 = à partir de ce bloc ; sinon à partir de cette date Unix).
/// Si `cancel` est renseigné (le verrou est alors obligatoire), cette adresse peut reprendre
/// la sortie à tout moment AVANT le déblocage ; après, seul le destinataire peut la dépenser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub amount: u64,
    pub address: Address,
    pub lock_until: u32,
    pub cancel: Option<Address>,
}

impl TxOut {
    pub fn new(amount: u64, address: Address) -> Self {
        Self { amount, address, lock_until: 0, cancel: None }
    }

    /// Sortie retenue : annulable par `cancel` jusqu'à `lock_until`.
    pub fn retained(amount: u64, address: Address, lock_until: u32, cancel: Address) -> Self {
        Self { amount, address, lock_until, cancel: Some(cancel) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    /// Premier enregistrement d'un pseudo libre.
    Register,
    /// Changement de l'adresse associée : réservé au propriétaire actuel.
    Update,
}

/// Enregistrement ou transfert d'un pseudo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameOp {
    pub kind: NameKind,
    pub name: String,
    pub owner: Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub locktime: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    /// Message public joint au paiement (texte UTF-8, 140 octets au maximum), signé avec la transaction.
    pub memo: Vec<u8>,
    /// Pseudo enregistré ou transféré par cette transaction (au plus un).
    pub name_op: Option<NameOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxError(pub String);

fn err<T>(msg: &str) -> Result<T, TxError> {
    Err(TxError(msg.to_string()))
}

impl Transaction {
    /// Transaction ordinaire, sans pseudo.
    pub fn new(inputs: Vec<TxIn>, outputs: Vec<TxOut>, memo: Vec<u8>) -> Self {
        Self { version: TX_VERSION, locktime: 0, inputs, outputs, memo, name_op: None }
    }

    /// Crée la transaction coinbase d'un bloc. Les 8 premiers octets des données
    /// sont la hauteur : chaque coinbase a donc un identifiant unique.
    pub fn coinbase(height: u64, extra: &[u8], outputs: Vec<TxOut>) -> Self {
        let mut data = height.to_be_bytes().to_vec();
        data.extend_from_slice(extra);
        Self {
            version: TX_VERSION,
            locktime: 0,
            inputs: vec![TxIn {
                prev: OutPoint { txid: [0u8; 64], vout: COINBASE_VOUT },
                pubkey: Vec::new(),
                signature: data,
                multi: None,
            }],
            outputs,
            memo: Vec::new(),
            name_op: None,
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase_shaped()
    }

    /// Hauteur inscrite dans une coinbase.
    pub fn coinbase_height(&self) -> Option<u64> {
        if !self.is_coinbase() {
            return None;
        }
        let d = &self.inputs[0].signature;
        if d.len() < 8 {
            return None;
        }
        Some(u64::from_be_bytes(d[0..8].try_into().ok()?))
    }

    fn write(&self, out: &mut Vec<u8>, blank_witness: bool) {
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.locktime.to_be_bytes());
        put_varint(out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.prev.txid);
            out.extend_from_slice(&i.prev.vout.to_be_bytes());
            if i.is_coinbase_shaped() {
                out.push(i.signature.len() as u8);
                out.extend_from_slice(&i.signature);
                continue;
            }
            match &i.multi {
                None => {
                    out.push(0);
                    if blank_witness {
                        out.extend_from_slice(&[0u8; PUBLIC_KEY_SIZE]);
                        out.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
                    } else {
                        out.extend_from_slice(&i.pubkey);
                        out.extend_from_slice(&i.signature);
                    }
                }
                Some(w) => {
                    // Le seuil et la liste des membres sont toujours signés ; les signatures, jamais.
                    out.push(1);
                    out.push(w.m);
                    out.push(w.members.len() as u8);
                    for a in &w.members {
                        out.extend_from_slice(a);
                    }
                    if !blank_witness {
                        out.push(w.sigs.len() as u8);
                        for s in &w.sigs {
                            out.push(s.index);
                            out.extend_from_slice(&s.pubkey);
                            out.extend_from_slice(&s.signature);
                        }
                    }
                }
            }
        }
        put_varint(out, self.outputs.len() as u64);
        for o in &self.outputs {
            out.extend_from_slice(&o.amount.to_be_bytes());
            out.extend_from_slice(&o.address);
            out.extend_from_slice(&o.lock_until.to_be_bytes());
            match &o.cancel {
                None => out.push(0),
                Some(c) => {
                    out.push(1);
                    out.extend_from_slice(c);
                }
            }
        }
        put_varint(out, self.memo.len() as u64);
        out.extend_from_slice(&self.memo);
        match &self.name_op {
            None => out.push(0),
            Some(n) => {
                out.push(1);
                out.push(match n.kind {
                    NameKind::Register => 0,
                    NameKind::Update => 1,
                });
                out.push(n.name.len() as u8);
                out.extend_from_slice(n.name.as_bytes());
                out.extend_from_slice(&n.owner);
            }
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out, false);
        out
    }

    pub fn size(&self) -> usize {
        self.serialize().len()
    }

    /// Message joint, prêt à afficher : les caractères de contrôle (codes d'échappement du terminal)
    /// et les caractères qui inversent le sens du texte sont retirés.
    pub fn memo_text(&self) -> String {
        clean_text(&String::from_utf8_lossy(&self.memo))
    }

    /// Identifiant : double SHA3-512 de la transaction complète.
    pub fn txid(&self) -> Hash {
        hash512(&self.serialize())
    }

    /// Empreinte signée : transaction avec clés et signatures retirées ou remplacées par des zéros.
    pub fn sighash(&self) -> Hash {
        let mut out = b"NFR-SIGHASH".to_vec();
        self.write(&mut out, true);
        hash512(&out)
    }

    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        let version = r.u32()?;
        let locktime = r.u32()?;
        let n_in = r.count(69)?;
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let txid: Hash = r.array()?;
            let vout = r.u32()?;
            let prev = OutPoint { txid, vout };
            if txid == [0u8; 64] && vout == COINBASE_VOUT {
                let len = r.u8()? as usize;
                let data = r.bytes(len)?.to_vec();
                inputs.push(TxIn { prev, pubkey: Vec::new(), signature: data, multi: None });
                continue;
            }
            match r.u8()? {
                0 => {
                    let pubkey = r.bytes(PUBLIC_KEY_SIZE)?.to_vec();
                    let signature = r.bytes(SIGNATURE_SIZE)?.to_vec();
                    inputs.push(TxIn { prev, pubkey, signature, multi: None });
                }
                1 => {
                    let m = r.u8()?;
                    let n = r.u8()? as usize;
                    if n > MAX_MULTISIG_MEMBERS {
                        return Err(DecodeError("trop de signataires"));
                    }
                    let mut members = Vec::with_capacity(n);
                    for _ in 0..n {
                        members.push(r.array()?);
                    }
                    let k = r.u8()? as usize;
                    if k > n {
                        return Err(DecodeError("trop de signatures"));
                    }
                    let mut sigs = Vec::with_capacity(k);
                    for _ in 0..k {
                        let index = r.u8()?;
                        let pubkey = r.bytes(PUBLIC_KEY_SIZE)?.to_vec();
                        let signature = r.bytes(SIGNATURE_SIZE)?.to_vec();
                        sigs.push(PartialSig { index, pubkey, signature });
                    }
                    inputs.push(TxIn { prev, pubkey: Vec::new(), signature: Vec::new(), multi: Some(MultiWitness { m, members, sigs }) });
                }
                _ => return Err(DecodeError("type d'entrée inconnu")),
            }
        }
        let n_out = r.count(45)?;
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let amount = r.u64()?;
            let address: Address = r.array()?;
            let lock_until = r.u32()?;
            let cancel = match r.u8()? {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(DecodeError("indicateur de sortie inconnu")),
            };
            outputs.push(TxOut { amount, address, lock_until, cancel });
        }
        let memo_len = r.varint()? as usize;
        if memo_len > MAX_MEMO {
            return Err(DecodeError("message joint trop long"));
        }
        let memo = r.bytes(memo_len)?.to_vec();
        let name_op = match r.u8()? {
            0 => None,
            1 => {
                let kind = match r.u8()? {
                    0 => NameKind::Register,
                    1 => NameKind::Update,
                    _ => return Err(DecodeError("type de pseudo inconnu")),
                };
                let len = r.u8()? as usize;
                let name = String::from_utf8(r.bytes(len)?.to_vec()).map_err(|_| DecodeError("pseudo illisible"))?;
                let owner: Address = r.array()?;
                Some(NameOp { kind, name, owner })
            }
            _ => return Err(DecodeError("indicateur de pseudo inconnu")),
        };
        Ok(Self { version, locktime, inputs, outputs, memo, name_op })
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(b);
        let tx = Self::read(&mut r)?;
        r.finish()?;
        Ok(tx)
    }

    pub fn output_sum(&self) -> Option<u64> {
        self.outputs.iter().try_fold(0u64, |acc, o| acc.checked_add(o.amount))
    }

    /// Vérifications qui ne dépendent pas de l'état de la chaîne,
    /// y compris les signatures ML-DSA-87.
    pub fn check_stateless(&self) -> Result<(), TxError> {
        self.check_rules(true)
    }

    /// Mêmes vérifications sans les signatures : uniquement pour des blocs déjà
    /// entièrement vérifiés par ce nœud (rechargement de son propre fichier).
    pub fn check_structure(&self) -> Result<(), TxError> {
        self.check_rules(false)
    }

    fn check_rules(&self, verify_signatures: bool) -> Result<(), TxError> {
        if self.version != TX_VERSION {
            return err("version de transaction inconnue");
        }
        if self.inputs.is_empty() {
            return err("aucune entrée");
        }
        if self.size() > MAX_TX_SIZE {
            return err("transaction trop grande");
        }
        for o in &self.outputs {
            if o.amount == 0 || o.amount > HARD_CAP {
                return err("montant de sortie invalide");
            }
            if o.cancel.is_some() && o.lock_until == 0 {
                return err("une sortie annulable doit avoir une date de déblocage");
            }
        }
        match self.output_sum() {
            Some(s) if s <= HARD_CAP => {}
            _ => return err("somme des sorties invalide"),
        }

        if self.memo.len() > MAX_MEMO {
            return err("message joint trop long");
        }
        if std::str::from_utf8(&self.memo).is_err() {
            return err("le message joint doit être du texte");
        }
        if let Some(n) = &self.name_op {
            check_name(&n.name).map_err(|e| TxError(e.to_string()))?;
        }
        if self.is_coinbase() {
            if !self.memo.is_empty() {
                return err("pas de message joint dans une coinbase");
            }
            if self.name_op.is_some() || self.outputs.iter().any(|o| o.cancel.is_some()) {
                return err("une coinbase ne peut ni enregistrer un pseudo ni retenir une sortie");
            }
            let len = self.inputs[0].signature.len();
            if !(8..=100).contains(&len) {
                return err("données coinbase de taille invalide");
            }
            return Ok(());
        }

        if self.outputs.is_empty() {
            return err("aucune sortie");
        }
        let mut seen = HashSet::new();
        let sighash = self.sighash();
        for i in &self.inputs {
            if i.is_coinbase_shaped() {
                return err("entrée coinbase dans une transaction normale");
            }
            if !seen.insert(i.prev) {
                return err("entrée en double");
            }
            match &i.multi {
                None => {
                    if i.pubkey.len() != PUBLIC_KEY_SIZE || i.signature.len() != SIGNATURE_SIZE {
                        return err("clé ou signature de taille incorrecte");
                    }
                    if verify_signatures && !verify(&i.pubkey, &sighash, &i.signature) {
                        return err("signature ML-DSA-87 invalide");
                    }
                }
                Some(w) => check_multi(w, &sighash, verify_signatures)?,
            }
        }
        Ok(())
    }
}

fn check_multi(w: &MultiWitness, sighash: &Hash, verify_signatures: bool) -> Result<(), TxError> {
    let n = w.members.len();
    if !(2..=MAX_MULTISIG_MEMBERS).contains(&n) {
        return err("une multi-signature compte de 2 à 15 membres");
    }
    if w.m < 1 || w.m as usize > n {
        return err("seuil de multi-signature invalide");
    }
    if !w.members.windows(2).all(|p| p[0] < p[1]) {
        return err("membres non triés ou en double");
    }
    if w.sigs.len() != w.m as usize {
        return err("il faut exactement autant de signatures que le seuil");
    }
    let mut last: Option<u8> = None;
    for s in &w.sigs {
        if s.index as usize >= n {
            return err("index de signataire invalide");
        }
        if matches!(last, Some(l) if s.index <= l) {
            return err("signatures non triées ou en double");
        }
        last = Some(s.index);
        if s.pubkey.len() != PUBLIC_KEY_SIZE || s.signature.len() != SIGNATURE_SIZE {
            return err("clé ou signature de taille incorrecte");
        }
        if address_of_pubkey(&s.pubkey) != w.members[s.index as usize] {
            return err("la clé ne correspond pas au membre indiqué");
        }
        if verify_signatures && !verify(&s.pubkey, sighash, &s.signature) {
            return err("signature de membre invalide");
        }
    }
    Ok(())
}

/// Frais minimaux pour une taille donnée : 1 000 unités par kilo-octet entamé.
pub fn min_fee(size: usize) -> u64 {
    (size as u64).div_ceil(1_000) * MIN_FEE_PER_KB
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::KeyPair;

    fn signed_tx(kp: &KeyPair) -> Transaction {
        let mut tx = Transaction::new(
            vec![TxIn::single(OutPoint { txid: [9u8; 64], vout: 0 }, kp.public_key_bytes().to_vec(), vec![0u8; SIGNATURE_SIZE])],
            vec![TxOut::new(1000, [1u8; 32]), TxOut::new(2000, address_of_pubkey(b"change"))],
            Vec::new(),
        );
        let sig = kp.sign(&tx.sighash()).unwrap();
        tx.inputs[0].signature = sig.to_vec();
        tx
    }

    #[test]
    fn taille_standard_1_entree_2_sorties() {
        let kp = KeyPair::from_seed(&[1; 32]);
        assert_eq!(signed_tx(&kp).size(), 7390);
    }

    #[test]
    fn aller_retour_binaire() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let tx = signed_tx(&kp);
        assert_eq!(Transaction::from_bytes(&tx.serialize()).unwrap(), tx);
        let cb = Transaction::coinbase(42, b"extra", vec![TxOut::new(5, [2; 32])]);
        assert_eq!(Transaction::from_bytes(&cb.serialize()).unwrap(), cb);
        assert_eq!(cb.coinbase_height(), Some(42));
    }

    #[test]
    fn signature_valide_acceptee() {
        let kp = KeyPair::from_seed(&[1; 32]);
        signed_tx(&kp).check_stateless().unwrap();
    }

    #[test]
    fn montant_modifie_apres_signature_rejete() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut tx = signed_tx(&kp);
        tx.outputs[0].amount = 999_999;
        assert!(tx.check_stateless().is_err());
    }

    #[test]
    fn destinataire_modifie_apres_signature_rejete() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut tx = signed_tx(&kp);
        tx.outputs[0].address = [66u8; 32];
        assert!(tx.check_stateless().is_err());
    }

    #[test]
    fn entree_en_double_rejetee() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut tx = signed_tx(&kp);
        tx.inputs.push(tx.inputs[0].clone());
        assert!(tx.check_stateless().is_err());
    }

    #[test]
    fn coinbases_de_hauteurs_differentes_ont_des_txid_differents() {
        let out = vec![TxOut::new(5, [2; 32])];
        let a = Transaction::coinbase(1, b"", out.clone());
        let b = Transaction::coinbase(2, b"", out);
        assert_ne!(a.txid(), b.txid());
    }

    #[test]
    fn message_joint_signe_et_limite() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut tx = signed_tx(&kp);
        tx.memo = "Merci pour le déjeuner !".as_bytes().to_vec();
        // Le message n'était pas dans la signature : la transaction est refusée.
        assert!(tx.check_stateless().is_err());
        let sig = kp.sign(&tx.sighash()).unwrap();
        tx.inputs[0].signature = sig.to_vec();
        tx.check_stateless().unwrap();
        assert_eq!(Transaction::from_bytes(&tx.serialize()).unwrap(), tx);
        // Trop long ou pas du texte : refusé.
        tx.memo = vec![b'a'; 141];
        assert!(tx.check_stateless().is_err());
        tx.memo = vec![0xFF, 0xFE];
        assert!(tx.check_stateless().is_err());
    }

    #[test]
    fn date_de_deblocage_signee() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut tx = signed_tx(&kp);
        tx.outputs[0].lock_until = 5;
        assert!(tx.check_stateless().is_err());
    }

    #[test]
    fn frais_minimaux() {
        assert_eq!(min_fee(7390), 8_000);
        assert_eq!(min_fee(1000), 1_000);
    }

    #[test]
    fn sortie_retenue_signee_et_obligatoirement_verrouillee() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut tx = signed_tx(&kp);
        // Annulable sans date de déblocage : refusé.
        tx.outputs[0].cancel = Some([7; 32]);
        assert!(tx.check_structure().is_err());
        tx.outputs[0].lock_until = 1_800_000_000;
        tx.inputs[0].signature = kp.sign(&tx.sighash()).unwrap().to_vec();
        tx.check_stateless().unwrap();
        assert_eq!(Transaction::from_bytes(&tx.serialize()).unwrap(), tx);
        // L'adresse d'annulation est signée : la changer invalide la signature.
        tx.outputs[0].cancel = Some([8; 32]);
        assert!(tx.check_stateless().is_err());
    }

    fn group(m: u8) -> (Vec<KeyPair>, Vec<Address>) {
        let kps: Vec<KeyPair> = (1..=3u8).map(|i| KeyPair::from_seed(&[i; 32])).collect();
        let addrs: Vec<Address> = kps.iter().map(|k| address_of_pubkey(&k.public_key_bytes())).collect();
        let members = normalize_members(m, &addrs).unwrap();
        (kps, members)
    }

    fn multisig_tx(m: u8, signers: &[usize]) -> Transaction {
        let (kps, members) = group(m);
        let mut tx = Transaction::new(
            vec![TxIn::multisig(OutPoint { txid: [9; 64], vout: 0 }, m, members.clone())],
            vec![TxOut::new(1000, [1; 32])],
            Vec::new(),
        );
        let sh = tx.sighash();
        let mut sigs = Vec::new();
        for &s in signers {
            let pk = kps[s].public_key_bytes();
            let index = members.iter().position(|a| *a == address_of_pubkey(&pk)).unwrap() as u8;
            sigs.push(PartialSig { index, pubkey: pk.to_vec(), signature: kps[s].sign(&sh).unwrap().to_vec() });
        }
        sigs.sort_by_key(|s| s.index);
        tx.inputs[0].multi.as_mut().unwrap().sigs = sigs;
        tx
    }

    #[test]
    fn multisignature_2_sur_3() {
        let tx = multisig_tx(2, &[0, 2]);
        tx.check_stateless().unwrap();
        assert_eq!(Transaction::from_bytes(&tx.serialize()).unwrap(), tx);
        // L'adresse du groupe ne dépend pas de l'ordre des membres.
        let (_, members) = group(2);
        let mut rev = members.clone();
        rev.reverse();
        assert_eq!(multisig_address(2, &members), multisig_address(2, &normalize_members(2, &rev).unwrap()));
        assert_eq!(tx.inputs[0].spender(), multisig_address(2, &members));
        // Une seule signature sur deux requises : refusé. Trois : refusé aussi (forme canonique).
        assert!(multisig_tx(2, &[1]).check_stateless().is_err());
        assert!(multisig_tx(2, &[0, 1, 2]).check_stateless().is_err());
    }

    #[test]
    fn multisignature_signature_falsifiee_ou_hors_groupe_refusee() {
        let mut tx = multisig_tx(2, &[0, 1]);
        tx.outputs[0].amount = 999;
        assert!(tx.check_stateless().is_err());
        // Un étranger au groupe signe à la place d'un membre.
        let mut tx = multisig_tx(2, &[0, 1]);
        let intruder = KeyPair::from_seed(&[99; 32]);
        let sh = tx.sighash();
        let w = tx.inputs[0].multi.as_mut().unwrap();
        w.sigs[1].pubkey = intruder.public_key_bytes().to_vec();
        w.sigs[1].signature = intruder.sign(&sh).unwrap().to_vec();
        assert!(tx.check_stateless().is_err());
        // Le même membre ne peut pas signer deux fois pour atteindre le seuil.
        let mut tx = multisig_tx(2, &[0, 1]);
        let dup = tx.inputs[0].multi.as_ref().unwrap().sigs[0].clone();
        tx.inputs[0].multi.as_mut().unwrap().sigs[1] = dup;
        assert!(tx.check_stateless().is_err());
    }

    #[test]
    fn regles_des_groupes() {
        assert!(normalize_members(1, &[[1; 32]]).is_err());
        assert!(normalize_members(3, &[[1; 32], [2; 32]]).is_err());
        assert!(normalize_members(0, &[[1; 32], [2; 32]]).is_err());
        assert!(normalize_members(1, &[[1; 32], [1; 32]]).is_err());
        assert!(normalize_members(2, &(0..16u8).map(|i| [i; 32]).collect::<Vec<_>>()).is_err());
        assert!(normalize_members(2, &(0..15u8).map(|i| [i; 32]).collect::<Vec<_>>()).is_ok());
    }

    #[test]
    fn pseudos_valides_et_invalides() {
        for ok in ["alice", "alice-42", "abc", "a1b2c3"] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        for bad in ["ab", "Alice", "ali ce", "-abc", "abc-", "a--b", "é-ric", &"a".repeat(33)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        assert!(name_fee(3) > name_fee(4) && name_fee(4) > name_fee(5) && name_fee(7) > name_fee(8));
    }

    #[test]
    fn pseudo_dans_la_transaction_signe_et_se_relit() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let mut tx = signed_tx(&kp);
        tx.name_op = Some(NameOp { kind: NameKind::Register, name: "alice".into(), owner: [4; 32] });
        assert!(tx.check_stateless().is_err()); // non signé
        tx.inputs[0].signature = kp.sign(&tx.sighash()).unwrap().to_vec();
        tx.check_stateless().unwrap();
        assert_eq!(Transaction::from_bytes(&tx.serialize()).unwrap(), tx);
        tx.name_op.as_mut().unwrap().name = "Mauvais Nom".into();
        assert!(tx.check_structure().is_err());
    }

    #[test]
    fn lectures_malformees_refusees() {
        let kp = KeyPair::from_seed(&[1; 32]);
        let tx = signed_tx(&kp);
        let b = tx.serialize();
        for cut in [1usize, 5, 100, b.len() - 1] {
            assert!(Transaction::from_bytes(&b[..b.len() - cut]).is_err());
        }
        let mut bad = b.clone();
        bad[4 + 4 + 1 + 64 + 4] = 7; // type d'entrée inconnu
        assert!(Transaction::from_bytes(&bad).is_err());
    }
}

/// Retire d'un texte venu du réseau ce qui pourrait tromper l'affichage : caractères de contrôle
/// (dont les séquences ANSI du terminal) et caractères de direction du texte (U+202A…U+202E, U+2066…U+2069…).
pub fn clean_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !matches!(*c, '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
        .collect()
}

#[cfg(test)]
mod tests_texte {
    #[test]
    fn message_joint_nettoye() {
        assert_eq!(super::clean_text("Merci\u{1b}[2J\u{1b}[31m !"), "Merci[2J[31m !");
        assert_eq!(super::clean_text("abc\u{202E}fdp.exe"), "abcfdp.exe");
        assert_eq!(super::clean_text("Café 🍰"), "Café 🍰");
    }
}
