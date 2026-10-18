//! Outil de signature des versions (à lancer SUR TON ORDINATEUR, jamais dans le dépôt).
//!
//!   cargo run --release --example signer_version -- keygen MACLE
//!       -> crée MACLE.pub (clé publique, à publier) et MACLE.key (clé SECRÈTE, à garder hors ligne)
//!   cargo run --release --example signer_version -- signer SHA3SUMS.txt MACLE.key
//!       -> crée SHA3SUMS.txt.sig
//!   cargo run --release --example signer_version -- verifier SHA3SUMS.txt SHA3SUMS.txt.sig MACLE.pub
//!   cargo run --release --example signer_version -- partager MACLE.key          -> 3 morceaux, 2 suffisent
//!   cargo run --release --example signer_version -- reconstruire M1 M2 MACLE.pub MACLE.key.rec

use numfranc::release::{join_key, keygen, sign, split_key, verify, PUBLIC_KEY_LEN, SECRET_KEY_LEN};
use std::path::Path;

fn read_fixed<const N: usize>(path: &str) -> Result<[u8; N], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path} : {e}"))?;
    let raw = numfranc::encoding::from_hex(text.trim()).ok_or(format!("{path} : pas du texte hexadécimal"))?;
    raw.try_into().map_err(|_| format!("{path} : mauvaise longueur"))
}

fn run(args: &[String]) -> Result<String, String> {
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", name] => {
            let (pk, sk) = keygen()?;
            let key_path = format!("{name}.key");
            if Path::new(&key_path).exists() {
                return Err(format!("{key_path} existe déjà : ne pas écraser une clé"));
            }
            std::fs::write(format!("{name}.pub"), numfranc::encoding::hex(&pk) + "\n").map_err(|e| e.to_string())?;
            std::fs::write(&key_path, numfranc::encoding::hex(&sk) + "\n").map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(format!(
                "Clé créée : {name}.pub (publique, à donner) et {key_path} (SECRÈTE : hors ligne, jamais dans le dépôt, jamais envoyée)."
            ))
        }
        ["signer", manifest, key] => {
            let sk: [u8; SECRET_KEY_LEN] = read_fixed(key)?;
            let data = std::fs::read(manifest).map_err(|e| format!("{manifest} : {e}"))?;
            let sig = sign(&data, &sk)?;
            let out = format!("{manifest}.sig");
            std::fs::write(&out, numfranc::encoding::hex(&sig) + "\n").map_err(|e| e.to_string())?;
            Ok(format!("Signé : {out}"))
        }
        ["verifier", manifest, sig, public] => {
            let pk: [u8; PUBLIC_KEY_LEN] = read_fixed(public)?;
            let data = std::fs::read(manifest).map_err(|e| format!("{manifest} : {e}"))?;
            let text = std::fs::read_to_string(sig).map_err(|e| format!("{sig} : {e}"))?;
            let raw = numfranc::encoding::from_hex(text.trim()).ok_or("signature : pas du texte hexadécimal")?;
            verify(&data, &raw, &pk)?;
            Ok("OK : signature valide, ce manifeste vient bien de la clé publique.".into())
        }
        ["partager", key] => {
            let sk: [u8; SECRET_KEY_LEN] = read_fixed(key)?;
            let pieces = split_key(&sk)?;
            for (i, p) in pieces.iter().enumerate() {
                std::fs::write(format!("{key}.morceau{}", i + 1), p.clone() + "\n").map_err(|e| e.to_string())?;
            }
            Ok(format!(
                "Créé : {key}.morceau1, .morceau2, .morceau3. Il en faut DEUX pour reconstituer la clé. Rangez-les séparément, sur papier ou clé USB, et supprimez les fichiers .morceau une fois recopiés ailleurs."
            ))
        }
        ["reconstruire", a, b, public, out] => {
            let pk: [u8; PUBLIC_KEY_LEN] = read_fixed(public)?;
            let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p} : {e}"));
            let sk = join_key(&read(a)?, &read(b)?)?;
            // Contrôle : la clé reconstituée doit signer une phrase que la clé publique reconnaît.
            let test = b"verification de la cle reconstituee";
            verify(test, &sign(test, &sk)?, &pk).map_err(|_| "la clé reconstituée ne correspond PAS à la clé publique : mauvais morceaux".to_string())?;
            if Path::new(out).exists() {
                return Err(format!("{out} existe déjà"));
            }
            std::fs::write(out, numfranc::encoding::hex(&sk) + "\n").map_err(|e| e.to_string())?;
            Ok(format!("Clé reconstituée et vérifiée : {out}"))
        }
        _ => Err("usage : keygen NOM | signer MANIFESTE CLE.key | verifier MANIFESTE SIG PUB | partager CLE.key | reconstruire MORCEAU1 MORCEAU2 PUB SORTIE".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("ERREUR : {e}");
            std::process::exit(1);
        }
    }
}
