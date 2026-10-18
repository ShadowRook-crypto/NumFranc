//! File d'attente des transactions en attente d'être incluses dans un bloc.

use crate::chain::{check_name_op, check_tx_inputs, Chain};
use crate::tx::{Hash, OutPoint, Transaction};
use std::collections::{HashMap, HashSet};

/// Taille maximale de la file : 64 Mo.
const MAX_MEMPOOL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct Mempool {
    txs: HashMap<Hash, (Transaction, u64)>, // transaction, frais
    spends: HashMap<OutPoint, Hash>,
    /// Pseudos déjà visés par une transaction en attente (un seul à la fois, sinon un bloc invalide serait possible).
    names: HashSet<String>,
    bytes: usize,
}

impl Mempool {
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
    pub fn accept(&mut self, tx: Transaction, chain: &Chain) -> Result<Hash, String> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err("déjà connue".into());
        }
        if tx.is_coinbase() {
            return Err("une coinbase ne peut pas circuler seule".into());
        }
        tx.check_stateless().map_err(|e| e.0)?;
        for i in &tx.inputs {
            if self.spends.contains_key(&i.prev) {
                return Err("double dépense d'une transaction en attente".into());
            }
        }
        let fee = check_tx_inputs(&chain.utxo, &tx, chain.height() + 1, chain.next_mtp())?;
        check_name_op(&chain.names, &tx, fee)?;
        if let Some(n) = &tx.name_op {
            if self.names.contains(&n.name) {
                return Err("une autre transaction en attente vise déjà ce pseudo".into());
            }
        }
        let size = tx.size();
        if self.bytes + size > MAX_MEMPOOL_BYTES {
            return Err("file d'attente pleine".into());
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
            let _ = self.accept(tx, chain);
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
