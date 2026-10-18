//! En-tête de bloc (212 octets, big-endian), bloc complet et preuve de travail.

use crate::config::{HEADER_SIZE, PROTOCOL_VERSION};
use crate::encoding::{put_varint, DecodeError, Reader};
use crate::hashing::{hash512, hash_below_target, pow_hash};
use crate::merkle::merkle_root;
use crate::tx::{Hash, Transaction};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_block_hash: Hash,
    pub merkle_root: Hash,
    pub timestamp: u64,
    pub target: [u8; 64],
    pub nonce: u64,
}

impl BlockHeader {
    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(&self.version.to_be_bytes());
        out[4..68].copy_from_slice(&self.previous_block_hash);
        out[68..132].copy_from_slice(&self.merkle_root);
        out[132..140].copy_from_slice(&self.timestamp.to_be_bytes());
        out[140..204].copy_from_slice(&self.target);
        out[204..212].copy_from_slice(&self.nonce.to_be_bytes());
        out
    }

    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            version: r.u32()?,
            previous_block_hash: r.array()?,
            merkle_root: r.array()?,
            timestamp: r.u64()?,
            target: r.array()?,
            nonce: r.u64()?,
        })
    }

    /// Empreinte de l'en-tête : double SHA3-512 des 212 octets.
    pub fn hash(&self) -> Hash {
        hash512(&self.serialize())
    }

    /// Empreinte de preuve de travail (Argon2d, gourmande en mémoire).
    pub fn pow(&self) -> [u8; 64] {
        pow_hash(&self.serialize())
    }

    /// La preuve de travail est valide si l'empreinte Argon2d est inférieure à la cible.
    pub fn meets_target(&self) -> bool {
        hash_below_target(&self.pow(), &self.target)
    }
}

/// Cherche un nonce valide par force brute (utilisé par les tests et le genesis).
pub fn mine(header: &mut BlockHeader, max_nonce: u64) -> bool {
    for n in 0..=max_nonce {
        header.nonce = n;
        if header.meets_target() {
            return true;
        }
    }
    false
}

pub fn new_header(prev_hash: Hash, merkle_root: Hash, timestamp: u64, target: [u8; 64]) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        previous_block_hash: prev_hash,
        merkle_root,
        timestamp,
        target,
        nonce: 0,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn compute_merkle_root(&self) -> Hash {
        let ids: Vec<Hash> = self.txs.iter().map(|t| t.txid()).collect();
        merkle_root(&ids)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.header.serialize().to_vec();
        put_varint(&mut out, self.txs.len() as u64);
        for t in &self.txs {
            out.extend_from_slice(&t.serialize());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(b);
        let header = BlockHeader::read(&mut r)?;
        let n = r.count(80)?;
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            txs.push(Transaction::read(&mut r)?);
        }
        r.finish()?;
        Ok(Self { header, txs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::TxOut;

    fn easy_target() -> [u8; 64] {
        let mut t = [0xFFu8; 64];
        t[0] = 0x0F;
        t
    }

    #[test]
    fn en_tete_fait_212_octets() {
        let h = new_header([0; 64], [0; 64], 1, easy_target());
        assert_eq!(h.serialize().len(), 212);
    }

    #[test]
    fn champs_aux_bons_offsets() {
        let mut prev = [0u8; 64];
        prev[0] = 0xAA;
        let h = new_header(prev, [0; 64], 0x0102030405060708, easy_target());
        let s = h.serialize();
        assert_eq!(&s[0..4], &PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(s[4], 0xAA);
        assert_eq!(&s[132..140], &0x0102030405060708u64.to_be_bytes());
    }

    #[test]
    fn bloc_suivant_reference_le_precedent() {
        let mut genesis = new_header([0; 64], [0; 64], 1_700_000_000, easy_target());
        assert!(mine(&mut genesis, 1_000_000));
        let genesis_hash = genesis.hash();
        let mut block1 = new_header(genesis_hash, [0; 64], 1_700_000_691, easy_target());
        assert!(mine(&mut block1, 1_000_000));
        genesis.nonce += 1;
        assert_ne!(genesis.hash(), block1.previous_block_hash);
    }

    #[test]
    fn bloc_aller_retour_binaire() {
        let cb = Transaction::coinbase(3, b"x", vec![TxOut::new(10, [4; 32])]);
        let mut b = Block { header: new_header([0; 64], [0; 64], 5, easy_target()), txs: vec![cb] };
        b.header.merkle_root = b.compute_merkle_root();
        assert_eq!(Block::from_bytes(&b.serialize()).unwrap(), b);
    }
}
