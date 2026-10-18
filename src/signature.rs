//! Signatures ML-DSA-87 (NIST FIPS 204, niveau 5) via la crate `fips204`.

use crate::config::SIG_CONTEXT;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

pub const PUBLIC_KEY_SIZE: usize = ml_dsa_87::PK_LEN; // 2 592
pub const SIGNATURE_SIZE: usize = ml_dsa_87::SIG_LEN; // 4 627

/// Paire de clés ML-DSA-87. La clé privée ne quitte jamais la machine.
pub struct KeyPair {
    public: ml_dsa_87::PublicKey,
    private: ml_dsa_87::PrivateKey,
}

impl KeyPair {
    /// Génère une paire aléatoire.
    pub fn generate() -> Result<Self, &'static str> {
        let (public, private) = ml_dsa_87::try_keygen()?;
        Ok(Self { public, private })
    }

    /// Dérive une paire de façon déterministe à partir d'une graine de 32 octets.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (public, private) = ml_dsa_87::KG::keygen_from_seed(seed);
        Self { public, private }
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public.clone().into_bytes()
    }

    /// Signe `message` avec le contexte NumFranc.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_SIZE], &'static str> {
        self.private.try_sign(message, SIG_CONTEXT)
    }
}

/// Vérifie une signature ML-DSA-87 (contexte NumFranc).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        <[u8; PUBLIC_KEY_SIZE]>::try_from(public_key),
        <[u8; SIGNATURE_SIZE]>::try_from(signature),
    ) else {
        return false;
    };
    match ml_dsa_87::PublicKey::try_from_bytes(pk) {
        Ok(pk) => pk.verify(message, &sig, SIG_CONTEXT),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailles_conformes_a_la_spec() {
        assert_eq!(PUBLIC_KEY_SIZE, 2592);
        assert_eq!(SIGNATURE_SIZE, 4627);
    }

    #[test]
    fn signature_valide_acceptee() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"message de test").unwrap();
        assert!(verify(&kp.public_key_bytes(), b"message de test", &sig));
    }

    #[test]
    fn message_modifie_rejete() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"message de test").unwrap();
        assert!(!verify(&kp.public_key_bytes(), b"message modifie", &sig));
    }

    #[test]
    fn autre_cle_rejetee() {
        let kp1 = KeyPair::generate().unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let sig = kp1.sign(b"x").unwrap();
        assert!(!verify(&kp2.public_key_bytes(), b"x", &sig));
    }

    #[test]
    fn derivation_deterministe() {
        let a = KeyPair::from_seed(&[7u8; 32]);
        let b = KeyPair::from_seed(&[7u8; 32]);
        let c = KeyPair::from_seed(&[8u8; 32]);
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_ne!(a.public_key_bytes(), c.public_key_bytes());
    }

    #[test]
    fn mauvaises_tailles_rejetees() {
        assert!(!verify(&[0u8; 10], b"x", &[0u8; SIGNATURE_SIZE]));
    }
}
