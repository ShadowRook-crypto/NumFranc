//! File d'attente des transactions en attente d'être incluses dans un bloc.

use crate::chain::{check_name_op, check_tx_inputs, Chain};
use crate::tx::{Hash, OutPoint, Transaction};
use std::collections::{HashMap, HashSet};

/// Taille maximale de la file : 64 Mo.
const MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct Mempool {
    /// Taille maximale choisie (0 = la valeur normale, 64 Mo). Sert aux tests.
    limit: usize,
    txs: HashMap<Hash, (Transaction, u64)>, // transaction, frais
    spends: HashMap<OutPoint, Hash>,
    /// Pseudos déjà visés par une transaction en attente (un seul à la fois, sinon un bloc invalide serait possible).
    names: HashSet<String>,
    bytes: usize,
}

impl Mempool {
    /// File d'attente d'une taille maximale choisie (pour les tests).
    pub fn with_limit(limit: usize) -> Self {
        Mempool { limit, ..Default::default() }
    }

    fn max_bytes(&self) -> usize {
        if self.limit == 0 { MAX_MEMPOOL_BYTES } else { self.limit }
    }

    /// Quand la file est pleine, comme Bitcoin : une transaction qui paie plus cher (par octet) prend la place
    /// des moins chères, au lieu d'être refusée. Renvoie celles à retirer, ou None si ce n'est pas possible.
    fn victims_for(&self, size: usize, fee: u64) -> Option<Vec<Hash>> {
        let mut cheaper: Vec<(&Hash, &(Transaction, u64))> = self
            .txs
            .iter()
            // frais/taille strictement plus bas que la nouvelle : fee_i * size < fee * size_i
            .filter(|(_, (t, f))| (*f as u128) * (size as u128) < (fee as u128) * (t.size() as u128))
            .collect();
        cheaper.sort_by(|a, b| {
            let (ra, rb) = (a.1.1 as u128 * b.1.0.size() as u128, b.1.1 as u128 * a.1.0.size() as u128);
            ra.cmp(&rb)
        });
        let mut freed = 0usize;
        let mut out = Vec::new();
        for (h, (t, _)) in cheaper {
            if self.bytes - freed + size <= self.max_bytes() {
                break;
            }
            freed += t.size();
            out.push(*h);
        }
        (self.bytes - freed + size <= self.max_bytes()).then_some(out)
    }

    fn remove(&mut self, txid: &Hash) {
        if let Some((tx, _)) = self.txs.remove(txid) {
            for i in &tx.inputs {
                self.spends.remove(&i.prev);
            }
            if let Some(n) = &tx.name_op {
                self.names.remove(&n.name);
            }
            self.bytes -= tx.size();
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
    pub fn contains(&self, txid: &Hash) -> bool {
        self.txs.contains_key(txid)
    }
    pub fn spends(&self, op: &OutPoint) -> bool {
        self.spends.contains_key(op)
    }

    /// Accepte une transaction si elle est valide pour le prochain bloc.
    /// Comme Bitcoin, les vérifications vont de la moins chère à la plus chère :
    /// taille et forme, pièces dépensées existantes, puis seulement les signatures.
    pub fn accept(&mut self, tx: Transaction, chain: &Chain) -> Result<Hash, String> {
        self.precheck(&tx, chain)?;
        tx.check_stateless().map_err(|e| e.0)?;
        self.insert_checked(tx, chain)
    }

    /// À utiliser seulement pour une transaction dont les signatures ont déjà été vérifiées
    /// (`check_stateless`), par exemple hors des verrous, ou déjà présente dans la file.
    pub fn accept_verified(&mut self, tx: Transaction, chain: &Chain) -> Result<Hash, String> {
        self.precheck(&tx, chain)?;
        self.insert_checked(tx, chain)
    }

    /// Vérifications bon marché (sans les signatures). Renvoie une erreur dès qu'un point échoue.
    pub fn precheck(&self, tx: &Transaction, chain: &Chain) -> Result<(), String> {
        if self.txs.contains_key(&tx.txid()) {
            return Err("déjà connue".into());
        }
        if tx.is_coinbase() {
            return Err("une coinbase ne peut pas circuler seule".into());
        }
        if tx.locktime != 0 {
            return Err("champ locktime non nul (réservé)".into());
        }
        tx.check_structure().map_err(|e| e.0)?;
        for i in &tx.inputs {
            if self.spends.contains_key(&i.prev) {
                return Err("double dépense d'une transaction en attente".into());
            }
            if !chain.utxo.contains_key(&i.prev) {
                return Err("entrée inexistante".into());
            }
        }
        if tx.outputs.iter().any(|o| o.amount < crate::config::DUST) {
            return Err("montant trop petit (moins de 0,0001 NFR) : non relayé".into());
        }
        let fee = check_tx_inputs(&chain.utxo, tx, chain.height() + 1, chain.next_mtp())?;
        check_name_op(&chain.names, tx, fee)?;
        if let Some(n) = &tx.name_op {
            if self.names.contains(&n.name) {
                return Err("une autre transaction en attente vise déjà ce pseudo".into());
            }
        }
        if self.bytes + tx.size() > self.max_bytes() && self.victims_for(tx.size(), fee).is_none() {
            return Err("file d'attente pleine : frais trop bas pour y entrer".into());
        }
        Ok(())
    }

    fn insert_checked(&mut self, tx: Transaction, chain: &Chain) -> Result<Hash, String> {
        let txid = tx.txid();
        let fee = check_tx_inputs(&chain.utxo, &tx, chain.height() + 1, chain.next_mtp())?;
        let size = tx.size();
        if self.bytes + size > self.max_bytes() {
            let victims = self.victims_for(size, fee).ok_or("file d'attente pleine : frais trop bas pour y entrer")?;
            for v in victims {
                self.remove(&v);
            }
        }
        for i in &tx.inputs {
            self.spends.insert(i.prev, txid);
        }
        if let Some(n) = &tx.name_op {
            self.names.insert(n.name.clone());
        }
        self.bytes += size;
        self.txs.insert(txid, (tx, fee));
        Ok(txid)
    }

    /// Après un nouveau bloc : retire les transactions incluses ou devenues invalides.
    pub fn revalidate(&mut self, chain: &Chain) {
        let old: Vec<Transaction> = self.txs.drain().map(|(_, (t, _))| t).collect();
        self.spends.clear();
        self.names.clear();
        self.bytes = 0;
        for tx in old {
            // Signatures déjà vérifiées à l'entrée dans la file : seules les règles liées à l'état changent.
            let _ = self.accept_verified(tx, chain);
        }
    }

    /// Sélection pour un bloc : frais par octet décroissants, dans la limite de taille.
    pub fn select(&self, max_bytes: usize) -> (Vec<Transaction>, u64) {
        let mut v: Vec<&(Transaction, u64)> = self.txs.values().collect();
        v.sort_by(|a, b| {
            let ra = a.1 as u128 * b.0.size() as u128;
            let rb = b.1 as u128 * a.0.size() as u128;
            rb.cmp(&ra)
        });
        let mut out = Vec::new();
        let mut size = 0;
        let mut fees = 0;
        for (tx, fee) in v {
            let s = tx.size();
            if size + s > max_bytes {
                continue;
            }
            size += s;
            fees += fee;
            out.push(tx.clone());
        }
        (out, fees)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests::{make_block, test_genesis};
    use crate::config::{COINBASE_MATURITY, GENESIS_TIMESTAMP};
    use crate::wallet::Wallet;
    use crate::wallet_plus::BuildSpec;
    use crate::tx::TxOut;

    /// Trois paiements de frais différents (0,01 / 1 / 0,5 NFR) ; une file qui n'en tient que deux.
    #[test]
    fn file_pleine_les_frais_eleves_passent_devant() {
        let now = GENESIS_TIMESTAMP + 10_000_000;
        let mut c = Chain::with_genesis(test_genesis());
        let mut w = Wallet::from_seed([42; 32]);
        for _ in 0..(COINBASE_MATURITY + 6) {
            let to = w.mining_address();
            let b = make_block(&c, c.tip(), vec![], to, 691, b"");
            c.add_block(b, now).unwrap();
            w.rotate_mining_address();
        }
        let dest = Wallet::from_seed([1; 32]).mining_address();
        // Les trois transactions sont fabriquées dans une file de travail, pour qu'elles dépensent des pièces différentes.
        let mut scratch = Mempool::default();
        let mut txs = Vec::new();
        for fee in [1_000_000u64, 100_000_000, 50_000_000] {
            let spec = BuildSpec {
                outputs: vec![TxOut { amount: 100_000_000, address: dest, lock_until: 0, cancel: None }],
                extra_fee: fee,
                memo: vec![],
                name_op: None,
                prefer: None,
            };
            let tx = w.build_tx(&c, &scratch, spec, None).unwrap();
            scratch.accept(tx.clone(), &c).unwrap();
            txs.push(tx);
        }
        let size = txs[0].size();
        let mut mp = Mempool::with_limit(size * 2 + size / 2);
        let (low, high, mid) = (txs[0].txid(), txs[1].txid(), txs[2].txid());
        mp.accept(txs[0].clone(), &c).unwrap();
        mp.accept(txs[1].clone(), &c).unwrap();
        // File pleine : la 3e paie plus que la plus basse, elle entre ; la plus basse sort.
        mp.accept(txs[2].clone(), &c).unwrap();
        assert!(!mp.contains(&low) && mp.contains(&high) && mp.contains(&mid));
        assert_eq!(mp.len(), 2);
        // Une transaction qui paie moins que toutes celles en attente est refusée.
        assert!(mp.accept(txs[0].clone(), &c).unwrap_err().contains("frais trop bas"));
        // Les pièces de la transaction évincée sont de nouveau libres.
        assert!(!mp.spends(&txs[0].inputs[0].prev));
    }
}
