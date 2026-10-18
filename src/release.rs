//! Signature des versions publiées (SLH-DSA-SHAKE-128s, norme FIPS 205).
//!
//! Pourquoi SLH-DSA pour les versions et ML-DSA-87 pour les transactions ?
//! - SLH-DSA ne repose que sur les fonctions de hachage : c'est l'hypothèse de sécurité la plus prudente.
//! - Sa signature (7 856 octets) est trop lourde pour des transactions en masse, mais sans importance
//!   pour un fichier de manifeste livré une fois par version.
//!
//! Ce qui est signé : le fichier SHA3SUMS.txt, qui contient l'empreinte SHA3-512 de chaque fichier
//! du paquet. Signer le manifeste couvre donc tout le paquet.

use crate::hashing::sha3_512;
use crate::vault::{gf_inv, gf_mul};
use fips205::slh_dsa_shake_128s as slh;
use fips205::traits::{SerDes, Signer, Verifier};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 7856;

/// Crée une paire de clés. La clé secrète ne doit JAMAIS être publiée ni committée.
pub fn keygen() -> Result<([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]), String> {
    let (pk, sk) = slh::try_keygen().map_err(|e| e.to_string())?;
    Ok((pk.into_bytes(), sk.into_bytes()))
}

/// Signe le contenu d'un manifeste (vide de contexte, signature aléatoire « hedged » : plus robuste).
pub fn sign(manifest: &[u8], secret: &[u8; SECRET_KEY_LEN]) -> Result<Vec<u8>, String> {
    let sk = slh::PrivateKey::try_from_bytes(secret).map_err(|e| e.to_string())?;
    let sig = sk.try_sign(manifest, &[], true).map_err(|e| e.to_string())?;
    Ok(sig.to_vec())
}

/// Vérifie une signature avec la clé publique. Renvoie une erreur lisible si elle est fausse.
pub fn verify(manifest: &[u8], signature: &[u8], public: &[u8; PUBLIC_KEY_LEN]) -> Result<(), String> {
    if signature.len() != SIGNATURE_LEN {
        return Err(format!("taille de signature incorrecte ({} octets au lieu de {SIGNATURE_LEN})", signature.len()));
    }
    let pk = slh::PublicKey::try_from_bytes(public).map_err(|e| e.to_string())?;
    let sig: [u8; SIGNATURE_LEN] = signature.try_into().unwrap();
    if pk.verify(manifest, &sig, &[]) {
        Ok(())
    } else {
        Err("signature FAUSSE : ne pas utiliser ce fichier".into())
    }
}

/// Coupe la clé secrète en 3 morceaux ; 2 suffisent pour la reconstituer (partage de Shamir octet par octet).
/// Un seul morceau ne donne aucune information sur la clé. Chaque morceau porte une somme de contrôle.
pub fn split_key(secret: &[u8; SECRET_KEY_LEN]) -> Result<[String; 3], String> {
    let mut coeff = [0u8; SECRET_KEY_LEN];
    getrandom::getrandom(&mut coeff).map_err(|e| e.to_string())?;
    let mut out: [String; 3] = Default::default();
    for x in 1u8..=3 {
        let mut raw = vec![x];
        for i in 0..SECRET_KEY_LEN {
            raw.push(secret[i] ^ gf_mul(coeff[i], x));
        }
        let check = sha3_512(&raw);
        raw.extend_from_slice(&check[..4]);
        out[x as usize - 1] = crate::encoding::hex(&raw);
    }
    Ok(out)
}

fn parse_piece(piece: &str) -> Result<(u8, [u8; SECRET_KEY_LEN]), String> {
    let raw = crate::encoding::from_hex(piece.trim()).ok_or("morceau illisible (pas de l'hexadécimal)")?;
    if raw.len() != 1 + SECRET_KEY_LEN + 4 {
        return Err(format!("morceau de longueur incorrecte ({} octets, {} attendus) : coupé ?", raw.len(), 1 + SECRET_KEY_LEN + 4));
    }
    if sha3_512(&raw[..1 + SECRET_KEY_LEN])[..4] != raw[1 + SECRET_KEY_LEN..] {
        return Err("somme de contrôle du morceau fausse : faute de frappe ?".into());
    }
    let x = raw[0];
    if !(1..=3).contains(&x) {
        return Err("numéro de morceau invalide".into());
    }
    Ok((x, raw[1..1 + SECRET_KEY_LEN].try_into().unwrap()))
}

/// Reconstitue la clé secrète à partir de deux morceaux différents.
pub fn join_key(a: &str, b: &str) -> Result<[u8; SECRET_KEY_LEN], String> {
    let (xa, ya) = parse_piece(a)?;
    let (xb, yb) = parse_piece(b)?;
    if xa == xb {
        return Err("les deux morceaux sont identiques : il en faut deux DIFFÉRENTS".into());
    }
    let inv = gf_inv(xa ^ xb);
    let mut secret = [0u8; SECRET_KEY_LEN];
    for i in 0..SECRET_KEY_LEN {
        let c = gf_mul(ya[i] ^ yb[i], inv);
        secret[i] = ya[i] ^ gf_mul(c, xa);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_aller_retour_et_falsification_refusee() {
        let (pk, sk) = keygen().unwrap();
        let manifest = b"abc123  NumFranc/LISEZMOI.txt\n";
        let sig = sign(manifest, &sk).unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        verify(manifest, &sig, &pk).unwrap();
        // Un seul caractère changé dans le manifeste : refusé.
        assert!(verify(b"abc124  NumFranc/LISEZMOI.txt\n", &sig, &pk).is_err());
        // Une autre clé publique : refusée.
        let (other, _) = keygen().unwrap();
        assert!(verify(manifest, &sig, &other).is_err());
        // Signature tronquée : refusée proprement, sans panique.
        assert!(verify(manifest, &sig[..100], &pk).is_err());
    }

    #[test]
    fn partage_de_la_cle_2_sur_3() {
        let (pk, sk) = keygen().unwrap();
        let pieces = split_key(&sk).unwrap();
        let manifest = b"test";
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let back = join_key(&pieces[a], &pieces[b]).unwrap();
            assert_eq!(back, sk);
            verify(manifest, &sign(manifest, &back).unwrap(), &pk).unwrap();
        }
        // Un seul morceau : refusé. Deux identiques : refusés. Un morceau abîmé : refusé.
        assert!(join_key(&pieces[0], &pieces[0]).is_err());
        let mut bad = pieces[1].clone();
        bad.replace_range(10..12, if &bad[10..12] == "00" { "11" } else { "00" });
        assert!(join_key(&pieces[0], &bad).is_err());
    }
}
