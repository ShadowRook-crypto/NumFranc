//! Fonctions de hachage : SHA3-512 (FIPS 202), double SHA3-512,
//! et preuve de travail Argon2d gourmande en mémoire.

use crate::config::{POW_MEMORY_KIB, POW_SALT};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use sha3::{Digest, Sha3_512};
use std::cell::RefCell;

/// Empreinte simple SHA3-512 (64 octets).
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).into()
}

/// Double SHA3-512 : utilisé pour l'en-tête de bloc, les txid et l'arbre de Merkle.
pub fn hash512(data: &[u8]) -> [u8; 64] {
    sha3_512(&sha3_512(data))
}

thread_local! {
    /// Mémoire de travail Argon2 (4 Mio), réutilisée d'un calcul à l'autre sur chaque fil.
    static POW_MEMORY: RefCell<Vec<Block>> = RefCell::new(vec![Block::default(); POW_MEMORY_KIB as usize]);
}

/// Preuve de travail : Argon2d (RFC 9106), 4 Mio de mémoire, 1 passe, 64 octets de sortie,
/// calculé sur les 212 octets de l'en-tête. Chaque essai oblige à remplir et relire
/// 4 Mio de mémoire de façon imprévisible : les puces spécialisées et les cartes graphiques
/// perdent l'essentiel de leur avance sur un processeur ordinaire.
pub fn pow_hash(header: &[u8]) -> [u8; 64] {
    let params = Params::new(POW_MEMORY_KIB, 1, 1, Some(64)).expect("paramètres Argon2 valides");
    let a = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);
    let mut out = [0u8; 64];
    POW_MEMORY.with(|m| {
        a.hash_password_into_with_memory(header, POW_SALT, &mut out, m.borrow_mut().as_mut_slice())
            .expect("calcul Argon2");
    });
    out
}

/// Compare deux empreintes de 64 octets comme entiers big-endian 512 bits.
/// Renvoie true si `hash < target`.
pub fn hash_below_target(hash: &[u8; 64], target: &[u8; 64]) -> bool {
    hash < target // comparaison lexicographique = comparaison big-endian
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_512_vecteur_connu() {
        // Vecteur officiel NIST pour la chaîne vide.
        let h = sha3_512(b"");
        assert_eq!(
            hex(&h),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn preuve_de_travail_deterministe_et_sensible() {
        let a = pow_hash(&[0u8; 212]);
        assert_eq!(a, pow_hash(&[0u8; 212]));
        let mut h = [0u8; 212];
        h[211] = 1;
        assert_ne!(a, pow_hash(&h));
    }

    #[test]
    fn double_hash_est_deux_fois_simple() {
        assert_eq!(hash512(b"abc"), sha3_512(&sha3_512(b"abc")));
    }

    #[test]
    fn comparaison_big_endian() {
        let mut small = [0u8; 64];
        small[63] = 1;
        let mut big = [0u8; 64];
        big[0] = 1;
        assert!(hash_below_target(&small, &big));
        assert!(!hash_below_target(&big, &small));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
