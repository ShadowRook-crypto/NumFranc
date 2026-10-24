//! Crée la clé des points de contrôle signés (une seule fois), sur TON ordinateur, et inscrit son empreinte
//! dans src/config.rs.
//!
//!   cargo run --release --example creer_cle_points
//!       -> crée ~/cles-numfranc/cle-points.key (SECRÈTE) si elle n'existe pas,
//!          puis écrit l'empreinte de sa clé publique dans src/config.rs (POINTS_CLE_EMPREINTE).
//!
//! La clé doit ensuite être copiée dans le dossier de données du nœud qui reste allumé (le HP) :
//! c'est lui qui signera les points de contrôle. Elle ne va JAMAIS dans le dépôt Git.

use numfranc::points::{empreinte_cle, FICHIER_CLE};
use numfranc::signature::KeyPair;
use std::path::PathBuf;

fn run() -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|_| "dossier personnel introuvable")?;
    let dossier = PathBuf::from(home).join("cles-numfranc");
    std::fs::create_dir_all(&dossier).map_err(|e| e.to_string())?;
    let chemin = dossier.join(FICHIER_CLE);
    let graine: [u8; 32] = match std::fs::read_to_string(&chemin) {
        Ok(t) => numfranc::encoding::from_hex(t.trim()).and_then(|v| v.try_into().ok()).ok_or("clé existante illisible")?,
        Err(_) => {
            let mut g = [0u8; 32];
            getrandom::getrandom(&mut g).map_err(|e| e.to_string())?;
            std::fs::write(&chemin, numfranc::encoding::hex(&g) + "\n").map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600));
            }
            g
        }
    };
    let empreinte = empreinte_cle(&KeyPair::from_seed(&graine).public_key_bytes());

    // Inscription de l'empreinte dans src/config.rs.
    let config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/config.rs");
    let texte = std::fs::read_to_string(&config).map_err(|e| e.to_string())?;
    let debut = "pub const POINTS_CLE_EMPREINTE: Option<&str> = ";
    let ligne = texte.lines().find(|l| l.starts_with(debut)).ok_or("ligne POINTS_CLE_EMPREINTE introuvable dans src/config.rs")?;
    let nouvelle = format!("{debut}Some(\"{empreinte}\");");
    std::fs::write(&config, texte.replacen(ligne, &nouvelle, 1)).map_err(|e| e.to_string())?;

    Ok(format!(
        "Clé des points de contrôle : {}\n(SECRÈTE : jamais dans le dépôt, jamais envoyée, jamais en photo.)\n\nEmpreinte inscrite dans src/config.rs :\n{empreinte}",
        chemin.display()
    ))
}

fn main() {
    match run() {
        Ok(m) => println!("{m}"),
        Err(e) => {
            eprintln!("ERREUR : {e}");
            std::process::exit(1);
        }
    }
}
