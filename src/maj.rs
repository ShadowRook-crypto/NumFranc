//! « Vérifier les mises à jour » : on télécharge le manifeste SHA3SUMS.txt de la dernière version
//! publiée et sa signature SHA3SUMS.txt.sig, puis on vérifie la signature SLH-DSA avec la clé
//! publique inscrite dans le programme. On ne propose la nouvelle version que si la signature
//! est valide : un faux site ou un faux fichier ne peut donc pas se faire passer pour une mise à jour.
//!
//! Le numéro de version est lu dans la première ligne du manifeste (« # NumFranc 1.0.0 »),
//! qui est elle-même couverte par la signature.
//! Le téléchargement passe par l'outil `curl` du système (présent sur macOS, Windows 10+ et Linux) :
//! pas besoin d'ajouter une bibliothèque réseau, et la sécurité repose sur la signature, pas sur le site.

use crate::release::{PUBLIC_KEY_LEN, verify};
use std::path::Path;

/// Clé publique de signature des versions (la même que packaging/cle-publique.txt).
pub const RELEASE_PUBLIC_KEY: [u8; PUBLIC_KEY_LEN] = [
    0x5e, 0x1d, 0x1c, 0x80, 0xfd, 0xd0, 0x7d, 0x3b, 0xc4, 0x09, 0x5f, 0x45, 0xa0, 0x56, 0x49, 0xfc,
    0x00, 0x6b, 0xce, 0x34, 0x76, 0x09, 0xb1, 0x56, 0x6b, 0x3c, 0x25, 0xe9, 0x40, 0x88, 0x17, 0x36,
];

/// Page où l'on télécharge la dernière version.
pub const PAGE_TELECHARGEMENT: &str = "https://github.com/ShadowRook-crypto/NumFranc/releases/latest";
const BASE: &str = "https://github.com/ShadowRook-crypto/NumFranc/releases/latest/download/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resultat {
    /// Une version plus récente existe, et sa signature est valide.
    Nouvelle(String),
    /// On a déjà la dernière version (signée).
    AJour(String),
}

/// Compare deux numéros « 1.2.3 ». Renvoie true si `a` est plus récent que `b`.
pub fn plus_recente(a: &str, b: &str) -> bool {
    let n = |v: &str| -> Vec<u64> { v.trim().trim_start_matches('v').split('.').map(|x| x.parse().unwrap_or(0)).collect() };
    let (mut x, mut y) = (n(a), n(b));
    let len = x.len().max(y.len());
    x.resize(len, 0);
    y.resize(len, 0);
    x > y
}

/// Vérifie le manifeste et sa signature, puis en lit la version. Fonction pure (testable).
pub fn analyser(manifeste: &[u8], signature: &[u8], cle: &[u8; PUBLIC_KEY_LEN], version_actuelle: &str) -> Result<Resultat, String> {
    // Le fichier .sig publié est écrit en hexadécimal (outil signer_version) ; on accepte aussi les octets bruts.
    let decodee;
    let signature = if signature.len() == crate::release::SIGNATURE_LEN {
        signature
    } else {
        let texte = std::str::from_utf8(signature).map_err(|_| "signature illisible".to_string())?;
        decodee = crate::encoding::from_hex(texte.trim()).ok_or("signature illisible (pas de l'hexadécimal)")?;
        &decodee[..]
    };
    verify(manifeste, signature, cle).map_err(|e| format!("mise à jour refusée : {e}"))?;
    let texte = std::str::from_utf8(manifeste).map_err(|_| "manifeste illisible".to_string())?;
    let version = texte
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("# NumFranc "))
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 20 && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .ok_or("numéro de version absent du manifeste")?
        .to_string();
    Ok(if plus_recente(&version, version_actuelle) { Resultat::Nouvelle(version) } else { Resultat::AJour(version) })
}

/// Télécharge un fichier avec curl (https uniquement, taille et durée limitées).
fn telecharger(nom: &str, destination: &Path) -> Result<Vec<u8>, String> {
    let url = format!("{BASE}{nom}");
    let ok = std::process::Command::new(crate::install::system_tool("curl"))
        .args(["-fsSL", "--proto", "=https", "--proto-redir", "=https", "--max-time", "30", "--max-filesize", "1000000", "-o"])
        .arg(destination)
        .arg(&url)
        .status()
        .map_err(|_| "curl est introuvable sur cet ordinateur".to_string())?;
    if !ok.success() {
        return Err(format!("téléchargement de {nom} impossible (pas d'Internet, ou fichier pas encore publié)"));
    }
    let data = std::fs::read(destination).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(destination);
    Ok(data)
}

/// Vérifie en ligne s'il existe une version plus récente, signée par l'auteur.
pub fn verifier(dossier: &Path) -> Result<Resultat, String> {
    let tmp = dossier.join("maj");
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let manifeste = telecharger("SHA3SUMS.txt", &tmp.join("SHA3SUMS.txt"))?;
    let signature = telecharger("SHA3SUMS.txt.sig", &tmp.join("SHA3SUMS.txt.sig"))
        .map_err(|_| "la dernière version n'est pas encore signée : réessaie plus tard".to_string())?;
    let _ = std::fs::remove_dir(&tmp);
    analyser(&manifeste, &signature, &RELEASE_PUBLIC_KEY, env!("CARGO_PKG_VERSION"))
}

/// Ouvre la page de téléchargement dans le navigateur (adresse fixe, sans interpréteur de commandes).
pub fn ouvrir_page() {
    let (prog, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[PAGE_TELECHARGEMENT])
    } else if cfg!(target_os = "windows") {
        ("explorer", &[PAGE_TELECHARGEMENT])
    } else {
        ("xdg-open", &[PAGE_TELECHARGEMENT])
    };
    let _ = std::process::Command::new(crate::install::system_tool(prog)).args(args).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::{keygen, sign};

    #[test]
    fn cle_publique_identique_au_fichier_publie() {
        let txt = include_str!("../packaging/cle-publique.txt").trim();
        assert_eq!(crate::encoding::from_hex(txt).unwrap(), RELEASE_PUBLIC_KEY.to_vec());
    }

    #[test]
    fn comparaison_des_versions() {
        assert!(plus_recente("1.0.1", "1.0.0"));
        assert!(plus_recente("1.10.0", "1.9.9"));
        assert!(plus_recente("2", "1.9"));
        assert!(!plus_recente("1.0.0", "1.0.0"));
        assert!(!plus_recente("0.7.0", "1.0.0"));
    }

    #[test]
    fn seule_une_version_bien_signee_est_proposee() {
        let (pk, sk) = keygen().unwrap();
        let manifeste = b"# NumFranc 1.2.0\nabc  bin/numfranc\n".to_vec();
        let sig = sign(&manifeste, &sk).unwrap();
        assert_eq!(analyser(&manifeste, &sig, &pk, "1.0.0"), Ok(Resultat::Nouvelle("1.2.0".into())));
        // Même signature au format du fichier .sig publié (hexadécimal + retour à la ligne).
        let sig_hex = (crate::encoding::hex(&sig) + "\n").into_bytes();
        assert_eq!(analyser(&manifeste, &sig_hex, &pk, "1.0.0"), Ok(Resultat::Nouvelle("1.2.0".into())));
        assert_eq!(analyser(&manifeste, &sig, &pk, "1.2.0"), Ok(Resultat::AJour("1.2.0".into())));
        // Manifeste modifié après signature (ex. version gonflée) : refusé.
        let mut faux = manifeste.clone();
        faux[13] = b'9';
        assert!(analyser(&faux, &sig, &pk, "1.0.0").is_err());
        // Signé par quelqu'un d'autre : refusé.
        let (_, autre) = keygen().unwrap();
        let sig2 = sign(&manifeste, &autre).unwrap();
        assert!(analyser(&manifeste, &sig2, &pk, "1.0.0").is_err());
        // Signature tronquée : refusée.
        assert!(analyser(&manifeste, &sig[..100], &pk, "1.0.0").is_err());
        // Manifeste sans numéro de version : refusé.
        let sans = b"abc  bin/numfranc\n".to_vec();
        let sig3 = sign(&sans, &sk).unwrap();
        assert!(analyser(&sans, &sig3, &pk, "1.0.0").is_err());
    }
}
