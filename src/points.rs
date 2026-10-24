//! Points de contrôle signés (protection contre les attaques à 51 % pendant le démarrage du réseau).
//!
//! Un nœud qui possède la « clé de points de contrôle » (fichier `cle-points.key` dans son dossier de données)
//! signe régulièrement, en ML-DSA-87, l'empreinte d'un bloc enterré sous quelques blocs de sa chaîne. Les autres
//! nœuds vérifient la signature et refusent ensuite toute réécriture de l'histoire avant ce bloc : un attaquant,
//! même plus puissant que tout le réseau, ne peut plus annuler que les toutes dernières minutes.
//!
//! Garde-fous :
//! - seule la clé dont l'empreinte est inscrite dans le logiciel (`POINTS_CLE_EMPREINTE`) est acceptée ;
//! - un point n'est appliqué que s'il correspond à un bloc que l'on connaît : une clé volée ne peut pas inventer
//!   une chaîne, seulement choisir entre des branches qui existent ;
//! - le système s'arrête tout seul à la date `POINTS_FIN` (le réseau devra alors être assez grand).

use crate::config::{POINTS_CLE_EMPREINTE, POINTS_FIN};
use crate::encoding::{hex, DecodeError, Reader};
use crate::hashing::sha3_512;
use crate::signature::{verify, KeyPair, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use crate::tx::Hash;
use std::path::Path;

/// Séparation de domaine : une signature de point ne peut servir à rien d'autre.
const DOMAINE: &[u8] = b"NumFranc-point-de-controle-v1";
/// Fichier de la clé privée (graine de 32 octets en hexadécimal), dans le dossier de données du nœud signataire.
pub const FICHIER_CLE: &str = "cle-points.key";
/// Dernier point accepté, gardé pour le redémarrage.
const FICHIER_POINT: &str = "point-signe.bin";
/// Taille d'un message « point » sur le réseau.
pub const TAILLE: usize = 8 + 64 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointSigne {
    pub height: u64,
    pub hash: Hash,
    pub cle: Vec<u8>,
    pub signature: Vec<u8>,
}

fn message(height: u64, hash: &Hash) -> Vec<u8> {
    let mut m = DOMAINE.to_vec();
    m.extend_from_slice(&height.to_be_bytes());
    m.extend_from_slice(hash);
    m
}

/// Empreinte (SHA3-512, hexadécimal) d'une clé publique de points de contrôle.
pub fn empreinte_cle(cle: &[u8]) -> String {
    hex(&sha3_512(cle))
}

/// Le système de points signés est-il actif (clé inscrite dans le logiciel, date de fin pas atteinte) ?
pub fn actif(maintenant: u64) -> bool {
    POINTS_CLE_EMPREINTE.is_some() && maintenant < POINTS_FIN
}

impl PointSigne {
    pub fn signer(cle: &KeyPair, height: u64, hash: Hash) -> Result<Self, String> {
        let signature = cle.sign(&message(height, &hash)).map_err(|e| e.to_string())?.to_vec();
        Ok(PointSigne { height, hash, cle: cle.public_key_bytes().to_vec(), signature })
    }

    /// Vrai si la clé est celle inscrite dans le logiciel et la signature est bonne.
    pub fn verifier(&self) -> bool {
        self.cle_officielle() && verify(&self.cle, &message(self.height, &self.hash), &self.signature)
    }

    /// La clé est-elle celle inscrite dans le logiciel ? (Une autre clé n'est pas une faute : version différente.)
    pub fn cle_officielle(&self) -> bool {
        POINTS_CLE_EMPREINTE.is_some_and(|e| e == empreinte_cle(&self.cle))
    }

    pub fn encoder(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TAILLE);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&self.cle);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decoder(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let height = r.u64()?;
        let hash: Hash = r.array()?;
        let cle = r.bytes(PUBLIC_KEY_SIZE)?.to_vec();
        let signature = r.bytes(SIGNATURE_SIZE)?.to_vec();
        r.finish()?;
        Ok(PointSigne { height, hash, cle, signature })
    }
}

/// Clé de points de contrôle de ce nœud, s'il en a une et que c'est bien la clé officielle.
pub fn charger_cle(dossier: &Path) -> Option<KeyPair> {
    let texte = std::fs::read_to_string(dossier.join(FICHIER_CLE)).ok()?;
    let octets = crate::encoding::from_hex(texte.trim())?;
    let graine: [u8; 32] = octets.try_into().ok()?;
    let cle = KeyPair::from_seed(&graine);
    POINTS_CLE_EMPREINTE.is_some_and(|e| e == empreinte_cle(&cle.public_key_bytes())).then_some(cle)
}

pub fn enregistrer(dossier: &Path, p: &PointSigne) {
    let tmp = dossier.join(format!("{FICHIER_POINT}.tmp"));
    if std::fs::write(&tmp, p.encoder()).is_ok() {
        let _ = std::fs::rename(&tmp, dossier.join(FICHIER_POINT));
    }
}

/// Dernier point accepté avant l'arrêt (revérifié).
pub fn charger(dossier: &Path) -> Option<PointSigne> {
    let p = PointSigne::decoder(&std::fs::read(dossier.join(FICHIER_POINT)).ok()?).ok()?;
    p.verifier().then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_et_signature() {
        let cle = KeyPair::from_seed(&[9; 32]);
        let p = PointSigne::signer(&cle, 300, [7; 64]).unwrap();
        assert_eq!(p.encoder().len(), TAILLE);
        let q = PointSigne::decoder(&p.encoder()).unwrap();
        assert_eq!(p, q);
        // Signature correcte, mais la clé n'est pas forcément l'officielle : on vérifie la signature seule.
        assert!(verify(&q.cle, &message(q.height, &q.hash), &q.signature));
        // Hauteur ou bloc modifiés : signature fausse.
        assert!(!verify(&q.cle, &message(301, &q.hash), &q.signature));
        assert!(!verify(&q.cle, &message(300, &[8; 64]), &q.signature));
        // Une clé qui n'est pas l'officielle n'est jamais acceptée.
        if POINTS_CLE_EMPREINTE != Some(empreinte_cle(&q.cle).as_str()) {
            assert!(!q.verifier());
        }
    }
}
