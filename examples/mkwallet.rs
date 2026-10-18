//! Outil de test : crée un portefeuille chiffré dans un dossier (usage : mkwallet DOSSIER).
use numfranc::{vault, wallet::Wallet};
fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("dossier"));
    std::fs::create_dir_all(&dir).unwrap();
    let (_w, _s) = Wallet::create_encrypted(&dir.join("wallet.dat"), "Ouverture-Test-2026", "Depense#Code42-Plage", vault::STRONG).unwrap();
    println!("ok");
}
