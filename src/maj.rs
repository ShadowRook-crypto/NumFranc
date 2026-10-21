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
    // Nom temporaire unique : deux vérifications en même temps ne se marchent pas dessus, et la liste
    // gardée pour l'installation (même dossier) n'est jamais écrasée ici.
    let dossier = destination.parent().unwrap_or(Path::new("."));
    let destination = &nom_temporaire(dossier, nom);
    let url = format!("{BASE}{nom}");
    let ok = std::process::Command::new(crate::install::system_tool("curl"))
        .args(["-fsSL", "--proto", "=https", "--proto-redir", "=https", "--max-time", "30", "--max-filesize", "1000000", "-o"])
        .arg(destination)
        .arg(&url)
        .status()
        .map_err(|_| "curl est introuvable sur cet ordinateur".to_string())?;
    if !ok.success() {
        let _ = std::fs::remove_file(destination);
        return Err(format!("téléchargement de {nom} impossible (pas d'Internet, ou fichier pas encore publié)"));
    }
    let data = std::fs::read(destination).map_err(|e| e.to_string());
    let _ = std::fs::remove_file(destination);
    data
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

// ---------------------------------------------------------------------------
// Mise à jour automatique
// ---------------------------------------------------------------------------
//
// 1. Toutes les 6 heures (et au démarrage), on lit le manifeste signé de la dernière version.
// 2. S'il y a plus récent, on télécharge l'installeur de cet ordinateur, puis on vérifie que son
//    empreinte SHA3-512 est celle écrite dans le manifeste (lui-même signé) : un fichier trafiqué
//    est effacé et jamais installé.
// 3. L'utilisateur clique sur « Installer et relancer » : NumFranc remplace l'app et redémarre.
// 4. La 2e ligne du manifeste peut donner une « version minimale sûre » : en dessous, NumFranc
//    affiche une alerte rouge et bloque les envois de NFR (recevoir et miner continuent).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static DANGEREUSE: AtomicBool = AtomicBool::new(false);

/// Cette version a-t-elle été déclarée dangereuse par l'auteur (faille connue) ?
pub fn version_dangereuse() -> bool {
    DANGEREUSE.load(Ordering::Relaxed)
}

/// Ce que dit le manifeste signé de la dernière version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub version: String,
    pub nouvelle: bool,
    /// Version minimale sûre (None ou « 0 » : pas d'alerte).
    pub minimale: Option<String>,
    manifeste: String,
}

impl Info {
    /// La version installée est-elle en dessous de la version minimale sûre ?
    pub fn dangereuse(&self) -> bool {
        self.minimale.as_deref().is_some_and(|m| plus_recente(m, env!("CARGO_PKG_VERSION")))
    }
}

/// « # Version minimale sûre 1.2.2 » (2e ligne du manifeste signé).
pub fn version_minimale(manifeste: &str) -> Option<String> {
    manifeste
        .lines()
        .take(5)
        .find_map(|l| l.strip_prefix("# Version minimale sûre "))
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 20 && v.chars().all(|c| c.is_ascii_digit() || c == '.') && *v != "0")
        .map(str::to_string)
}

/// Empreinte de l'installeur `nom` dans le manifeste (ligne « HEX  installeurs/NOM »).
pub fn empreinte(manifeste: &str, nom: &str) -> Option<String> {
    let cible = format!("installeurs/{nom}");
    manifeste.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let (h, chemin) = l.split_once("  ")?;
        (chemin == cible && h.len() == 128 && h.chars().all(|c| c.is_ascii_hexdigit())).then(|| h.to_ascii_lowercase())
    })
}

/// Nom de l'installeur qui convient à cet ordinateur.
pub fn nom_installeur() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        Some("NumFranc-macos.dmg")
    } else if cfg!(target_os = "windows") {
        Some("NumFranc-windows-installation.exe")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("NumFranc-linux-amd64.deb")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("NumFranc-linux-arm64.deb")
    } else {
        None
    }
}

/// NumFranc peut-il se mettre à jour tout seul ici ? (installé par l'installeur officiel, pas lancé
/// depuis le dossier téléchargé). Sinon, on propose seulement la page de téléchargement.
pub fn peut_installer() -> bool {
    nom_installeur().is_some() && crate::install::installe_par_paquet()
}

/// Une seule vérification ou installation de mise à jour à la fois (bouton + vérification automatique).
pub static VERROU_MAJ: std::sync::Mutex<()> = std::sync::Mutex::new(());

const ETAT: &str = "maj-etat.txt";

/// Mémoire de la plus récente liste signée déjà vue : (version, version minimale sûre).
fn etat_lu(dossier: &Path) -> (String, String) {
    let t = std::fs::read_to_string(dossier.join(ETAT)).unwrap_or_default();
    let champ = |k: &str| t.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string()).unwrap_or_else(|| "0".into());
    (champ("vue="), champ("minimale="))
}

/// Au démarrage : si une liste signée déjà vue déclarait cette version dangereuse, l'alerte reste
/// active (même sans Internet, même si quelqu'un sert ensuite une ancienne liste).
pub fn charger_etat(dossier: &Path) {
    let (_, mini) = etat_lu(dossier);
    if plus_recente(&mini, env!("CARGO_PKG_VERSION")) {
        DANGEREUSE.store(true, Ordering::SeqCst);
    }
}

/// Vérifie le manifeste signé de la dernière version et garde son texte (pour les empreintes).
pub fn verifier_tout(dossier: &Path) -> Result<Info, String> {
    let tmp = dossier.join("maj");
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let manifeste = telecharger("SHA3SUMS.txt", &tmp.join("SHA3SUMS.txt"))?;
    let signature = telecharger("SHA3SUMS.txt.sig", &tmp.join("SHA3SUMS.txt.sig"))
        .map_err(|_| "la dernière version n'est pas encore signée : réessaie plus tard".to_string())?;
    let r = analyser(&manifeste, &signature, &RELEASE_PUBLIC_KEY, env!("CARGO_PKG_VERSION"))?;
    let texte = String::from_utf8(manifeste.clone()).map_err(|_| "manifeste illisible".to_string())?;
    let (version, nouvelle) = match r {
        Resultat::Nouvelle(v) => (v, true),
        Resultat::AJour(v) => (v, false),
    };
    // Retour en arrière refusé : une liste signée plus ancienne que la plus récente déjà vue est ignorée
    // (quelqu'un pourrait resservir une vieille liste pour cacher une alerte de sécurité).
    let (vue, mini_vue) = etat_lu(dossier);
    if plus_recente(&vue, &version) {
        return Err("liste signée plus ancienne que celle déjà vue : ignorée".into());
    }
    // Une « version minimale » plus récente que la version publiée elle-même serait une erreur : ignorée.
    let minimale = version_minimale(&texte).filter(|m| !plus_recente(m, &version));
    let mini = match &minimale {
        Some(m) if plus_recente(m, &mini_vue) => m.clone(),
        _ => mini_vue,
    };
    let _ = std::fs::write(dossier.join(ETAT), format!("vue={version}\nminimale={mini}\n"));
    // Liste et signature gardées : l'installation les revérifie juste avant d'installer.
    let _ = std::fs::write(tmp.join("SHA3SUMS.txt"), &manifeste);
    let _ = std::fs::write(tmp.join("SHA3SUMS.txt.sig"), &signature);
    let info = Info { version, nouvelle, minimale: Some(mini.clone()).filter(|m| m != "0"), manifeste: texte };
    DANGEREUSE.store(plus_recente(&mini, env!("CARGO_PKG_VERSION")), Ordering::SeqCst);
    Ok(info)
}

fn hex_sha3(d: &[u8]) -> String {
    crate::encoding::hex(&crate::hashing::sha3_512(d))
}

fn nom_temporaire(dir: &Path, base: &str) -> PathBuf {
    let mut r = [0u8; 8];
    let _ = getrandom::getrandom(&mut r);
    dir.join(format!("{base}.{}.tmp", crate::encoding::hex(&r)))
}

/// Télécharge l'installeur de la nouvelle version et vérifie son empreinte (manifeste signé).
/// Le téléchargement va dans un fichier temporaire au nom aléatoire, renommé seulement une fois vérifié.
pub fn telecharger_installeur(dossier: &Path, info: &Info) -> Result<PathBuf, String> {
    let nom = nom_installeur().ok_or("pas d'installeur pour ce système")?;
    let attendue = empreinte(&info.manifeste, nom).ok_or("installeur absent de la liste signée")?;
    let dir = dossier.join("maj");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let fichier = dir.join(nom);
    if std::fs::read(&fichier).is_ok_and(|d| hex_sha3(&d) == attendue) {
        return Ok(fichier);
    }
    let tmp = nom_temporaire(&dir, nom);
    let url = format!("{BASE}{nom}");
    let ok = std::process::Command::new(crate::install::system_tool("curl"))
        .args(["-fsSL", "--proto", "=https", "--proto-redir", "=https", "--max-time", "900", "--max-filesize", "300000000", "-o"])
        .arg(&tmp)
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|_| "curl est introuvable sur cet ordinateur".to_string())?;
    let d = if ok.success() { std::fs::read(&tmp).unwrap_or_default() } else { Vec::new() };
    if !ok.success() || hex_sha3(&d) != attendue {
        let _ = std::fs::remove_file(&tmp);
        return Err(if ok.success() {
            "fichier téléchargé différent de celui signé par l'auteur : effacé, rien n'est installé".into()
        } else {
            format!("téléchargement de {nom} impossible")
        });
    }
    std::fs::rename(&tmp, &fichier).map_err(|e| e.to_string())?;
    Ok(fichier)
}

/// Relit la liste signée et l'installeur gardés dans `dir`, et revérifie TOUT juste avant l'installation :
/// signature de l'auteur, version plus récente que celle installée, empreinte de l'installeur.
/// Renvoie le contenu vérifié (en mémoire : il ne peut plus être échangé entre la vérification et l'usage).
pub fn reverifier(dir: &Path) -> Result<Vec<u8>, String> {
    let lire = |nom: &str| -> Result<Vec<u8>, String> {
        let mut o = std::fs::OpenOptions::new();
        o.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.custom_flags(0o400000); // O_NOFOLLOW : pas de lien symbolique
        }
        let mut f = o.open(dir.join(nom)).map_err(|e| format!("{nom} : {e}"))?;
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut v).map_err(|e| e.to_string())?;
        Ok(v)
    };
    let nom = nom_installeur().ok_or("pas d'installeur pour ce système")?;
    let manifeste = lire("SHA3SUMS.txt")?;
    let signature = lire("SHA3SUMS.txt.sig")?;
    match analyser(&manifeste, &signature, &RELEASE_PUBLIC_KEY, env!("CARGO_PKG_VERSION"))? {
        Resultat::Nouvelle(_) => {}
        Resultat::AJour(_) => return Err("pas plus récent que la version installée : rien à installer".into()),
    }
    let texte = String::from_utf8(manifeste).map_err(|_| "manifeste illisible".to_string())?;
    let attendue = empreinte(&texte, nom).ok_or("installeur absent de la liste signée")?;
    let d = lire(nom)?;
    if hex_sha3(&d) != attendue {
        return Err("l'installeur a été modifié depuis le téléchargement : rien n'est installé".into());
    }
    Ok(d)
}

/// Installe la mise à jour téléchargée et prépare le redémarrage. En cas de succès, l'appelant doit quitter
/// NumFranc tout de suite : la nouvelle version se lance d'elle-même.
pub fn installer(fichier: &Path) -> Result<(), String> {
    if !peut_installer() {
        return Err("NumFranc n'a pas été installé avec l'installeur officiel : utilise la page de téléchargement".into());
    }
    let _verrou = VERROU_MAJ.lock().unwrap_or_else(|e| e.into_inner());
    let dir = fichier.parent().ok_or("dossier invalide")?;
    // Chemin complet : l'assistant administrateur (Linux) ne démarre pas dans le même dossier.
    let dir = dir.canonicalize().map_err(|e| e.to_string())?;
    installer_systeme(&dir)
}

/// Linux, en administrateur (lancé par pkexec) : revérifie tout depuis le dossier de l'utilisateur, copie
/// l'installeur vérifié dans un dossier réservé à root, puis l'installe avec dpkg.
#[cfg(target_os = "linux")]
pub fn appliquer_en_root(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let d = reverifier(dir)?;
    let cache = Path::new("/var/cache/numfranc");
    let _ = std::fs::remove_dir_all(cache);
    std::fs::DirBuilder::new().mode(0o700).create(cache).map_err(|e| format!("{} : {e}", cache.display()))?;
    let deb = cache.join("mise-a-jour.deb");
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&deb).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut f, &d).map_err(|e| e.to_string())?;
    drop(f);
    let st = std::process::Command::new("/usr/bin/dpkg").arg("-i").arg(&deb).status().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(cache);
    if st.success() { Ok(()) } else { Err("dpkg a échoué".into()) }
}

#[cfg(not(target_os = "linux"))]
pub fn appliquer_en_root(_dir: &Path) -> Result<(), String> {
    Err("réservé à Linux".into())
}

/// Copie privée (nom aléatoire, créée exprès) du contenu vérifié, pour l'installer sans qu'il puisse changer.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn copie_privee(dir: &Path, d: &[u8], ext: &str) -> Result<PathBuf, String> {
    // L'extension doit rester à la fin (Windows ne lance un programme que s'il finit par .exe).
    let mut r = [0u8; 8];
    let _ = getrandom::getrandom(&mut r);
    let p = dir.join(format!("verifie-{}.{ext}", crate::encoding::hex(&r)));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&p).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut f, d).map_err(|e| e.to_string())?;
    Ok(p)
}

#[cfg(target_os = "macos")]
fn installer_systeme(dir: &Path) -> Result<(), String> {
    let d = reverifier(dir)?;
    let copie = copie_privee(dir, &d, "dmg")?;
    let r = installer_dmg(&copie);
    let _ = std::fs::remove_file(&copie);
    r
}

#[cfg(target_os = "macos")]
fn installer_dmg(fichier: &Path) -> Result<(), String> {
    use std::process::Command;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let app = exe.ancestors().find(|p| p.extension().is_some_and(|e| e == "app")).ok_or("app NumFranc introuvable")?.to_path_buf();
    let montage = fichier.with_extension("montage");
    let _ = std::fs::create_dir_all(&montage);
    let ok = Command::new("/usr/bin/hdiutil").args(["attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint"]).arg(&montage).arg(fichier).status();
    if !ok.is_ok_and(|s| s.success()) {
        return Err("ouverture du .dmg impossible".into());
    }
    let source = montage.join("NumFranc.app");
    let nouvelle = app.with_extension("app-maj");
    let _ = std::fs::remove_dir_all(&nouvelle);
    let copie = source.exists() && Command::new("/usr/bin/ditto").arg(&source).arg(&nouvelle).status().is_ok_and(|s| s.success());
    let _ = Command::new("/usr/bin/hdiutil").args(["detach", "-quiet"]).arg(&montage).status();
    let _ = std::fs::remove_dir(&montage);
    if !copie {
        let _ = std::fs::remove_dir_all(&nouvelle);
        return Err("copie de la nouvelle app impossible (dossier Applications protégé ?)".into());
    }
    let ancienne = app.with_extension("app-ancienne");
    let _ = std::fs::remove_dir_all(&ancienne);
    std::fs::rename(&app, &ancienne).map_err(|e| format!("remplacement impossible : {e}"))?;
    if let Err(e) = std::fs::rename(&nouvelle, &app) {
        let _ = std::fs::rename(&ancienne, &app);
        return Err(format!("remplacement impossible : {e}"));
    }
    let _ = std::fs::remove_dir_all(&ancienne);
    let _ = std::fs::remove_file(fichier);
    // Le gardien « Toujours allumé » repart avec la nouvelle version, puis la fenêtre se rouvre.
    let uid = Command::new("/usr/bin/id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    let _ = Command::new("/bin/launchctl").args(["kickstart", "-k", &format!("gui/{uid}/org.numfranc.gardien")]).status();
    Command::new("/bin/sh").args(["-c", "sleep 2; /usr/bin/open \"$1\"", "sh"]).arg(&app).spawn().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn installer_systeme(dir: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let d = reverifier(dir)?;
    let fichier = copie_privee(dir, &d, "exe")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let (f, e) = (fichier.display().to_string(), exe.display().to_string());
    if f.contains(['"', '%', '!']) || e.contains(['"', '%', '!']) {
        return Err("chemin invalide".into());
    }
    // L'installeur (silencieux) arrête NumFranc, remplace le programme et relance le gardien ;
    // ensuite la fenêtre se rouvre.
    let cmd = crate::install::system_tool("cmd");
    std::process::Command::new(cmd)
        .raw_arg(format!("/c \"\"{f}\" /S & start \"\" \"{e}\"\""))
        .creation_flags(0x0800_0000 | 0x0000_0008)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn installer_systeme(dir: &Path) -> Result<(), String> {
    use std::process::Command;
    // Vérification côté utilisateur d'abord (message clair), puis le programme installé (/usr/bin/numfranc,
    // appartenant à root) revérifie tout lui-même en administrateur avant d'appeler dpkg.
    reverifier(dir)?;
    // Le système demande le mot de passe de l'ordinateur (fenêtre de pkexec).
    let st = Command::new("/usr/bin/pkexec").arg("/usr/bin/numfranc").arg("--appliquer-maj").arg(dir).status().map_err(|_| "pkexec introuvable".to_string())?;
    if !st.success() {
        return Err("installation annulée ou refusée (mot de passe ?)".into());
    }
    if let Some(n) = nom_installeur() {
        let _ = std::fs::remove_file(dir.join(n));
    }
    let _ = Command::new("/usr/bin/systemctl").args(["--user", "restart", "numfranc-gardien.service"]).status();
    Command::new("/usr/bin/numfranc").stdin(std::process::Stdio::null()).spawn().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn installer_systeme(_dir: &Path) -> Result<(), String> {
    Err("système non pris en charge".into())
}

/// Ouvre une adresse web dans le navigateur (sans interpréteur de commandes).
fn ouvrir_adresse(url: &str) {
    let (prog, args): (&str, [&str; 1]) = if cfg!(target_os = "macos") {
        ("open", [url])
    } else if cfg!(target_os = "windows") {
        ("explorer", [url])
    } else {
        ("xdg-open", [url])
    };
    let _ = std::process::Command::new(crate::install::system_tool(prog)).args(args).spawn();
}

/// Ouvre la page de téléchargement dans le navigateur (adresse fixe).
pub fn ouvrir_page() {
    ouvrir_adresse(PAGE_TELECHARGEMENT);
}

/// Ouvre la page d'administration de la box (adresse locale, donnée sous forme d'adresse IPv4 : rien d'autre ne passe).
pub fn ouvrir_page_box(ip: std::net::Ipv4Addr) {
    ouvrir_adresse(&format!("http://{ip}/"));
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
    fn manifeste_version_minimale_et_empreintes() {
        let h = "a".repeat(128);
        let m = format!("# NumFranc 1.3.0\n# Version minimale sûre 1.2.2\n{h}  installeurs/NumFranc-macos.dmg\n{h}  bin/x\n");
        assert_eq!(version_minimale(&m).as_deref(), Some("1.2.2"));
        assert_eq!(version_minimale("# NumFranc 1.3.0\n# Version minimale sûre 0\n"), None);
        assert_eq!(version_minimale("# NumFranc 1.3.0\n"), None);
        assert_eq!(empreinte(&m, "NumFranc-macos.dmg").as_deref(), Some(h.as_str()));
        assert_eq!(empreinte(&m, "x"), None);
        let info = Info { version: "1.3.0".into(), nouvelle: true, minimale: Some("999.0.0".into()), manifeste: m.clone() };
        assert!(info.dangereuse());
        let info = Info { minimale: Some("0.1.0".into()), ..info };
        assert!(!info.dangereuse());
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
