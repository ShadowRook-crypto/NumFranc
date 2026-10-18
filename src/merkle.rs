//! Arbre de Merkle avec séparation de domaine (feuilles 0x00, nœuds 0x01).

use crate::hashing::hash512;
use crate::tx::Hash;

pub fn merkle_root(txids: &[Hash]) -> Hash {
    if txids.is_empty() {
        return [0u8; 64];
    }
    let mut level: Vec<Hash> = txids
        .iter()
        .map(|t| {
            let mut d = vec![0x00];
            d.extend_from_slice(t);
            hash512(&d)
        })
        .collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|p| {
                let mut d = vec![0x01];
                d.extend_from_slice(&p[0]);
                d.extend_from_slice(&p[1]);
                hash512(&d)
            })
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordre_et_contenu_changent_la_racine() {
        let a = [1u8; 64];
        let b = [2u8; 64];
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
        assert_ne!(merkle_root(&[a]), merkle_root(&[a, b]));
    }

    #[test]
    fn feuille_differente_de_son_txid() {
        let a = [1u8; 64];
        assert_ne!(merkle_root(&[a]), a);
    }
}
