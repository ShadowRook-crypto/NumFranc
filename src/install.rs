//! Ajoute NumFranc au menu des applications (sans Terminal) : Linux, macOS et Windows.
//! Rien n'est installé ailleurs que dans le dossier personnel de l'utilisateur.

use std::path::{Path, PathBuf};

pub const LOGO_PNG_256: &[u8] = include_bytes!("../assets/logo-256.png");
pub const LOGO_PNG_512: &[u8] = include_bytes!("../assets/logo-512.png");
/// Icône de la fenêtre : 64 x 64 pixels RGBA.
pub const ICON_RGBA_64: &[u8] = include_bytes!("../assets/icon-64.rgba");

fn home() -> Result<PathBuf, String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| "dossier personnel introuvable".to_string())
}

/// Fichier .icns (macOS) contenant directement des images PNG.
pub fn icns(png_256: &[u8], png_512: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (kind, png) in [(b"ic08", png_256), (b"ic09", png_512)] {
        body.extend_from_slice(kind);
        body.extend_from_slice(&((png.len() + 8) as u32).to_be_bytes());
        body.extend_from_slice(png);
    }
    let mut out = b"icns".to_vec();
    out.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Fichier .ico (Windows) contenant directement une image PNG de 256 x 256.
pub fn ico(png_256: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 1, 0, 1, 0];
    out.extend_from_slice(&[0, 0, 0, 0]); // largeur et hauteur 256 (codées 0), palette, réservé
    out.extend_from_slice(&1u16.to_le_bytes()); // plans
    out.extend_from_slice(&32u16.to_le_bytes()); // bits par pixel
    out.extend_from_slice(&(png_256.len() as u32).to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes()); // position de l'image
    out.extend_from_slice(png_256);
    out
}

/// Dossier où se trouve le lanceur (et noeuds.txt) : celui qui contient code/.
fn launcher_dir(exe: &Path) -> PathBuf {
    exe.ancestors()
        .find(|p| p.join("code").is_dir() || p.join("noeuds.txt").is_file())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| exe.parent().unwrap_or(Path::new(".")).to_path_buf())
}

// ---------- Protection des chemins écrits dans les fichiers de lancement ----------
// Un chemin (dossier personnel, dossier de données) est écrit dans des scripts et des fichiers
// de configuration. Il ne doit jamais pouvoir y ajouter une commande ou une option.

/// Refuse les chemins contenant des caractères de contrôle (retour à la ligne, etc.).
fn check_path(s: &str) -> Result<(), String> {
    if s.chars().any(char::is_control) {
        return Err("chemin contenant des caractères invisibles : déplace NumFranc dans un dossier au nom simple".into());
    }
    Ok(())
}

/// Linux : les fichiers .desktop ont leurs propres règles d'échappement ; on refuse simplement
/// les caractères qui y ont un sens spécial.
fn check_desktop_path(s: &str) -> Result<(), String> {
    check_path(s)?;
    if s.chars().any(|c| matches!(c, '"' | '`' | '$' | '\\' | '%')) {
        return Err("chemin contenant \" ` $ \\ ou % : déplace NumFranc dans un dossier au nom simple".into());
    }
    Ok(())
}

#[allow(dead_code)] // plus utilisé par l'app macOS depuis la v1.0.1, gardé (et testé) pour les scripts
/// Bash : entre apostrophes, rien n'est interprété ; une apostrophe s'écrit '\''.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// PowerShell : entre apostrophes, une apostrophe s'écrit ''.
fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// XML (fichiers .plist de macOS).
fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Chemin complet d'un outil du système. Sous Windows et macOS, on n'appelle jamais un programme « cherché dans le PATH »
/// ou à côté de NumFranc : un faux `reg.exe` ou `curl.exe` posé dans un dossier modifiable y serait lancé à sa place.
pub fn system_tool(name: &str) -> PathBuf {
    if cfg!(target_os = "windows") {
        let root = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()));
        match name {
            "powershell" => root.join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe"),
            "explorer" => root.join("explorer.exe"),
            n => root.join("System32").join(format!("{n}.exe")),
        }
    } else if cfg!(target_os = "macos") {
        match name {
            "curl" | "open" => PathBuf::from(format!("/usr/bin/{name}")),
            n => PathBuf::from(n),
        }
    } else {
        PathBuf::from(name)
    }
}

/// Vrai si NumFranc a été installé par un paquet ou un installeur (.deb, .dmg glissé dans Applications,
/// installeur Windows), et non lancé depuis le dossier téléchargé : le menu et les liens nfr: sont alors déjà en place.
pub fn installe_par_paquet() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let exe = exe.canonicalize().unwrap_or(exe);
    if cfg!(target_os = "linux") {
        exe.starts_with("/usr/")
    } else if cfg!(target_os = "macos") {
        // Une vraie app : Contents/MacOS/NumFranc, sans le fichier lanceur.txt des copies faites par NumFranc.
        exe.parent().is_some_and(|m| m.ends_with("Contents/MacOS") && m.parent().is_some_and(|c| !c.join("Resources/lanceur.txt").exists()))
    } else if cfg!(target_os = "windows") {
        let s = exe.display().to_string().to_lowercase();
        s.ends_with("\\programs\\numfranc\\numfranc.exe")
    } else {
        false
    }
}

/// Premier lancement : NumFranc se range tout seul dans le menu des applications et prend en charge
/// les liens nfr:, sans que l'utilisateur ait quoi que ce soit à faire. Une seule fois (fichier-témoin).
pub fn premier_lancement(data_dir: &Path) {
    let marque = data_dir.join("menu-ok.txt");
    if marque.exists() {
        return;
    }
    let _ = std::fs::create_dir_all(data_dir);
    if add_to_menu(data_dir).is_ok() {
        let _ = std::fs::write(&marque, "ok\n");
    }
}

/// Faut-il montrer l'écran « Bienvenue » ? Oui, jusqu'à ce que l'utilisateur l'ait fermé une fois.
pub fn bienvenue_a_montrer(data_dir: &Path) -> bool {
    !data_dir.join("bienvenue-vue.txt").exists()
}

pub fn bienvenue_vue(data_dir: &Path) {
    let _ = std::fs::write(data_dir.join("bienvenue-vue.txt"), "ok\n");
}

/// Ajoute NumFranc au menu des applications. Renvoie une phrase décrivant ce qui a été fait.
pub fn add_to_menu(data_dir: &Path) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.canonicalize().unwrap_or(exe);
    if installe_par_paquet() {
        // Déjà installé proprement. Sur Mac, on signale seulement l'app au Finder (liens nfr:).
        if cfg!(target_os = "macos") {
            let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
            if let Some(bundle) = exe.parent().and_then(Path::parent).and_then(Path::parent) {
                let _ = std::process::Command::new(lsregister).arg("-f").arg(bundle).status();
            }
        }
        return Ok(crate::i18n::t(
            "NumFranc est déjà installé : il est dans le menu des applications, et les liens nfr: s'ouvrent avec lui.",
            "NumFranc is already installed: it is in the applications menu, and nfr: links open with it.",
        )
        .into());
    }
    let workdir = launcher_dir(&exe);
    let data = data_dir.display().to_string();
    for p in [exe.display().to_string(), workdir.display().to_string(), data.clone()] {
        if cfg!(target_os = "linux") { check_desktop_path(&p) } else { check_path(&p) }?;
    }
    let _ = std::fs::create_dir_all(data_dir);
    if cfg!(target_os = "linux") {
        let h = home()?;
        let icon_dir = h.join(".local/share/icons/hicolor/256x256/apps");
        let apps = h.join(".local/share/applications");
        std::fs::create_dir_all(&icon_dir).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&apps).map_err(|e| e.to_string())?;
        let icon = icon_dir.join("numfranc.png");
        std::fs::write(&icon, LOGO_PNG_256).map_err(|e| e.to_string())?;
        let desktop = format!(
            "[Desktop Entry]\nType=Application\nName=NumFranc\nComment=Monnaie post-quantique NumFranc (NFR)\nExec=\"{}\" --dossier \"{}\" %u\nPath={}\nIcon={}\nTerminal=false\nCategories=Finance;Network;\nMimeType=x-scheme-handler/nfr;\n",
            exe.display(),
            data,
            workdir.display(),
            icon.display()
        );
        let file = apps.join("numfranc.desktop");
        std::fs::write(&file, desktop).map_err(|e| e.to_string())?;
        set_executable(&file);
        // Les liens nfr:… s'ouvrent avec NumFranc (sans effet si xdg-mime est absent).
        let _ = std::process::Command::new("xdg-mime").args(["default", "numfranc.desktop", "x-scheme-handler/nfr"]).status();
        Ok(crate::tf!("NumFranc est dans le menu des applications ({}).", "NumFranc is in the applications menu ({}).", file.display()))
    } else if cfg!(target_os = "macos") {
        let h = home()?;
        let app = h.join("Applications/NumFranc.app/Contents");
        std::fs::create_dir_all(app.join("MacOS")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(app.join("Resources")).map_err(|e| e.to_string())?;
        std::fs::write(app.join("Resources/NumFranc.icns"), icns(LOGO_PNG_256, LOGO_PNG_512)).map_err(|e| e.to_string())?;
        // macOS n'accepte comme app qu'un VRAI programme rangé dans l'app (pas un script qui en lance
        // un autre ailleurs, ni un raccourci) : sinon il la ferme et ne lui envoie pas les liens nfr:.
        // On copie donc le programme dans l'app ; au démarrage, l'app se met à jour toute seule
        // si le programme du dossier NumFranc a changé (voir mac_bundle_launch).
        let (workdir, source) = match mac_bundle_info(&exe) {
            Some((w, _)) => {
                let src = w.join(mac_binary_name());
                (w, src)
            }
            None => (workdir, exe.clone()),
        };
        let launcher = app.join("MacOS/NumFranc");
        if source.canonicalize().ok() != launcher.canonicalize().ok() && source.is_file() {
            let tmp = app.join("MacOS/.NumFranc.nouveau");
            std::fs::copy(&source, &tmp).map_err(|e| e.to_string())?;
            set_executable(&tmp);
            std::fs::rename(&tmp, &launcher).map_err(|e| e.to_string())?;
        }
        // Dossier du lanceur (noeuds.txt) et dossier des données, relus au démarrage de l'app.
        std::fs::write(app.join("Resources/lanceur.txt"), format!("{}\n{}\n", workdir.display(), data)).map_err(|e| e.to_string())?;
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>CFBundleName</key><string>NumFranc</string>\n<key>CFBundleDisplayName</key><string>NumFranc</string>\n<key>CFBundleIdentifier</key><string>org.numfranc.app</string>\n<key>CFBundleExecutable</key><string>NumFranc</string>\n<key>CFBundleIconFile</key><string>NumFranc</string>\n<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleShortVersionString</key><string>{v}</string>\n<key>CFBundleVersion</key><string>{v}</string>\n<key>LSMinimumSystemVersion</key><string>11.0</string>\n<key>LSApplicationCategoryType</key><string>public.app-category.finance</string>\n<key>NSHumanReadableCopyright</key><string>ShadowRook — licence MIT</string>\n<key>NSHighResolutionCapable</key><true/>\n<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLName</key><string>org.numfranc.paiement</string><key>CFBundleTypeRole</key><string>Viewer</string><key>CFBundleURLSchemes</key><array><string>nfr</string></array></dict></array>\n</dict></plist>\n",
            v = env!("CARGO_PKG_VERSION")
        );
        std::fs::write(app.join("Info.plist"), plist).map_err(|e| e.to_string())?;
        // Signale l'app (et ses liens nfr:) au Finder tout de suite ; sinon macOS la découvre tout seul plus tard.
        let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
        if let Some(bundle) = app.parent() {
            let _ = std::process::Command::new(lsregister).arg("-f").arg(bundle).status();
        }
        Ok(crate::i18n::t(
            "NumFranc est dans le dossier Applications de ton compte (~/Applications) : ouvre-le depuis le Launchpad ou Spotlight.",
            "NumFranc is in your account's Applications folder (~/Applications): open it from Launchpad or Spotlight.",
        )
        .into())
    } else if cfg!(target_os = "windows") {
        let appdata = std::env::var("APPDATA").map_err(|_| "dossier APPDATA introuvable".to_string())?;
        let ico_path = data_dir.join("numfranc.ico");
        std::fs::write(&ico_path, ico(LOGO_PNG_256)).map_err(|e| e.to_string())?;
        let lnk = PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\NumFranc.lnk");
        let ps = format!(
            "$s=(New-Object -COM WScript.Shell).CreateShortcut('{}');$s.TargetPath='{}';$s.Arguments='--dossier \"{}\"';$s.WorkingDirectory='{}';$s.IconLocation='{}';$s.Save()",
            ps_quote(&lnk.display().to_string()),
            ps_quote(&exe.display().to_string()),
            ps_quote(&data),
            ps_quote(&workdir.display().to_string()),
            ps_quote(&ico_path.display().to_string())
        );
        let ok = std::process::Command::new(system_tool("powershell"))
            .args(["-NoProfile", "-Command", &ps])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            // Les liens nfr:… s'ouvrent avec NumFranc (registre de l'utilisateur, sans droits administrateur).
            // reg.exe est appelé directement, sans passer par un interpréteur de commandes.
            let cmd = format!("\"{}\" --dossier \"{}\" \"%1\"", exe.display(), data);
            let key = r"HKCU\Software\Classes\nfr";
            let reg = |args: &[&str]| std::process::Command::new(system_tool("reg")).args(args).status().map(|s| s.success()).unwrap_or(false);
            let _ = reg(&["add", key, "/ve", "/d", "URL:NumFranc", "/f"])
                && reg(&["add", key, "/v", "URL Protocol", "/d", "", "/f"])
                && reg(&["add", &format!(r"{key}\shell\open\command"), "/ve", "/d", &cmd, "/f"]);
            Ok(crate::i18n::t("NumFranc est dans le menu Démarrer.", "NumFranc is in the Start menu.").into())
        } else {
            Err("création du raccourci impossible".into())
        }
    } else {
        Err("système non pris en charge".into())
    }
}

/// Verrou d'instance unique : deux NumFranc sur le même dossier abîmeraient la chaîne.
/// Le verrou est gardé jusqu'à la fin du programme (le système le libère même après un plantage).
pub fn single_instance(data_dir: &Path) -> Result<(), String> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<std::fs::File> = OnceLock::new();
    if LOCK.get().is_some() {
        return Ok(());
    }
    let _ = std::fs::create_dir_all(data_dir);
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(data_dir.join("numfranc.lock")).map_err(|e| e.to_string())?;
    match f.try_lock() {
        Ok(()) => {
            let _ = LOCK.set(f);
            Ok(())
        }
        Err(_) => Err(crate::i18n::t(
            "NumFranc est déjà ouvert avec ce dossier de données (regarde dans la barre des tâches ou le Dock, ou ferme l'autre fenêtre).",
            "NumFranc is already running with this data folder (look in the taskbar or Dock, or close the other window).",
        )
        .into()),
    }
}

/// Fichier où un lien de paiement cliqué (nfr:…) attend que la fenêtre le prenne.
const LINK_FILE: &str = "lien-paiement.txt";

/// Dépose un lien de paiement nfr:… pour la fenêtre NumFranc.
/// Renvoie Ok(true) si un autre NumFranc est déjà ouvert sur ce dossier (c'est lui qui prendra le lien).
/// Le lien ne fait que remplir le formulaire « Envoyer » : rien n'est payé sans le code de dépense.
pub fn hand_over_link(data_dir: &Path, link: &str) -> Result<bool, String> {
    let link = link.trim();
    if link.len() > 2048 {
        return Err("lien trop long".into());
    }
    crate::wallet_plus::parse_payment_uri(link)?;
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let tmp = data_dir.join(format!("{LINK_FILE}.tmp"));
    std::fs::write(&tmp, link).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, data_dir.join(LINK_FILE)).map_err(|e| e.to_string())?;
    // Un autre NumFranc tient-il déjà le verrou du dossier ? (on teste sans le garder)
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(data_dir.join("numfranc.lock")).map_err(|e| e.to_string())?;
    Ok(f.try_lock().is_err())
}

/// Reprend le lien de paiement déposé par hand_over_link, s'il y en a un (et l'efface).
pub fn take_link(data_dir: &Path) -> Option<String> {
    let path = data_dir.join(LINK_FILE);
    let len = std::fs::metadata(&path).ok()?.len();
    let text = if len <= 4096 { std::fs::read_to_string(&path).ok() } else { None };
    let _ = std::fs::remove_file(&path);
    let link = text?.trim().to_string();
    crate::wallet_plus::parse_payment_uri(&link).ok()?;
    Some(link)
}

// ---------- macOS : l'app NumFranc.app ----------

/// Nom du programme macOS dans le dossier NumFranc, selon le processeur (comme `uname -m`).
fn mac_binary_name() -> String {
    let arch = if std::env::consts::ARCH == "aarch64" { "arm64" } else { std::env::consts::ARCH };
    format!("bin/numfranc-macos-{arch}")
}

/// Si `exe` est le programme rangé dans une app NumFranc.app, renvoie (dossier du lanceur, dossier des données)
/// lus dans Contents/Resources/lanceur.txt.
fn mac_bundle_info(exe: &Path) -> Option<(PathBuf, String)> {
    let macos = exe.parent()?;
    if !macos.ends_with("Contents/MacOS") {
        return None;
    }
    let text = std::fs::read_to_string(macos.parent()?.join("Resources/lanceur.txt")).ok()?;
    let mut lines = text.lines();
    let workdir = PathBuf::from(lines.next()?.trim());
    let data = lines.next()?.trim().to_string();
    if workdir.as_os_str().is_empty() || data.is_empty() {
        return None;
    }
    Some((workdir, data))
}

/// macOS, au démarrage : si NumFranc a été lancé depuis son app, se placer dans le dossier du lanceur et
/// renvoyer le dossier des données. Si le programme du dossier NumFranc est plus récent (mise à jour
/// installée), l'app se remplace par lui puis redémarre, une seule fois.
#[cfg(unix)]
pub fn mac_bundle_launch() -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let (workdir, data) = mac_bundle_info(&exe)?;
    let source = workdir.join(mac_binary_name());
    let differs = match (std::fs::metadata(&source), std::fs::metadata(&exe)) {
        (Ok(a), Ok(b)) if a.len() != b.len() => true,
        (Ok(_), Ok(_)) => std::fs::read(&source).ok() != std::fs::read(&exe).ok(),
        _ => false,
    };
    if differs && std::env::var_os("NUMFRANC_APP_MAJ").is_none() {
        let tmp = exe.with_file_name(".NumFranc.nouveau");
        if std::fs::copy(&source, &tmp).is_ok() {
            set_executable(&tmp);
            if std::fs::rename(&tmp, &exe).is_ok() {
                use std::os::unix::process::CommandExt;
                // Même processus (exec) : macOS continue de reconnaître l'app.
                let err = std::process::Command::new(&exe).args(std::env::args_os().skip(1)).env("NUMFRANC_APP_MAJ", "1").exec();
                eprintln!("Redémarrage après mise à jour impossible : {err}");
            }
        }
    }
    let _ = std::env::set_current_dir(&workdir);
    Some(PathBuf::from(data))
}

#[cfg(not(unix))]
pub fn mac_bundle_launch() -> Option<PathBuf> {
    None
}

const AUTOSTART_NAME: &str = "numfranc";

fn autostart_path() -> Result<PathBuf, String> {
    let h = home()?;
    if cfg!(target_os = "linux") {
        Ok(h.join(".config/autostart/numfranc.desktop"))
    } else if cfg!(target_os = "macos") {
        Ok(h.join("Library/LaunchAgents/org.numfranc.app.plist"))
    } else {
        Err("système sans fichier de démarrage".into())
    }
}

/// Le démarrage automatique à l'ouverture de session est-il en place ?
pub fn autostart_enabled() -> bool {
    if cfg!(target_os = "windows") {
        std::process::Command::new(system_tool("reg"))
            .args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", AUTOSTART_NAME])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        autostart_path().map(|p| p.exists()).unwrap_or(false)
    }
}

/// Active ou désactive le démarrage à l'ouverture de session. NumFranc démarre alors fenêtre réduite (--reduit) :
/// le nœud tourne, le minage continue, il suffit de cliquer pour voir la fenêtre. Le mot de passe d'ouverture reste demandé.
pub fn set_autostart(enable: bool, data_dir: &Path) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let workdir = launcher_dir(&exe);
    let data = data_dir.display().to_string();
    for p in [exe.display().to_string(), workdir.display().to_string(), data.clone()] {
        if cfg!(target_os = "linux") { check_desktop_path(&p) } else { check_path(&p) }?;
    }
    let on = crate::i18n::t("NumFranc démarrera tout seul à l'ouverture de ta session (fenêtre réduite).", "NumFranc will start by itself when you log in (window minimized).");
    let off = crate::i18n::t("Démarrage automatique désactivé.", "Automatic start disabled.");
    if cfg!(target_os = "windows") {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let ok = if enable {
            let cmd = format!("\"{}\" --reduit --dossier \"{}\"", exe.display(), data);
            std::process::Command::new(system_tool("reg")).args(["add", key, "/v", AUTOSTART_NAME, "/t", "REG_SZ", "/d", &cmd, "/f"]).status().map(|s| s.success()).unwrap_or(false)
        } else {
            let _ = std::process::Command::new(system_tool("reg")).args(["delete", key, "/v", AUTOSTART_NAME, "/f"]).status();
            true
        };
        return if ok { Ok(if enable { on } else { off }.into()) } else { Err("écriture du registre impossible".into()) };
    }
    let p = autostart_path()?;
    if !enable {
        let _ = std::fs::remove_file(&p);
        return Ok(off.into());
    }
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    let text = if cfg!(target_os = "linux") {
        format!(
            "[Desktop Entry]\nType=Application\nName=NumFranc\nComment=Monnaie post-quantique NumFranc (NFR)\nExec=\"{}\" --reduit --dossier \"{}\"\nPath={}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            exe.display(),
            data,
            workdir.display()
        )
    } else {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>org.numfranc.app</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--reduit</string><string>--dossier</string><string>{}</string></array>\n<key>WorkingDirectory</key><string>{}</string>\n<key>RunAtLoad</key><true/>\n</dict></plist>\n",
            xml(&exe.display().to_string()),
            xml(&data),
            xml(&workdir.display().to_string())
        )
    };
    std::fs::write(&p, text).map_err(|e| e.to_string())?;
    Ok(on.into())
}

#[cfg(unix)]
fn set_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn set_executable(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_d_icone() {
        let i = icns(LOGO_PNG_256, LOGO_PNG_512);
        assert_eq!(&i[..4], b"icns");
        assert_eq!(u32::from_be_bytes(i[4..8].try_into().unwrap()) as usize, i.len());
        let w = ico(LOGO_PNG_256);
        assert_eq!(&w[..6], &[0, 0, 1, 0, 1, 0]);
        assert_eq!(&w[22..30], &LOGO_PNG_256[..8]);
        assert_eq!(ICON_RGBA_64.len(), 64 * 64 * 4);
    }
}

#[cfg(test)]
mod tests_lien {
    use super::*;

    #[test]
    fn app_macos_retrouve_son_dossier() {
        let base = std::env::temp_dir().join(format!("nfr-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let app = base.join("NumFranc.app/Contents");
        std::fs::create_dir_all(app.join("MacOS")).unwrap();
        std::fs::create_dir_all(app.join("Resources")).unwrap();
        let exe = app.join("MacOS/NumFranc");
        // Sans lanceur.txt : ce n'est pas une app NumFranc préparée.
        assert_eq!(mac_bundle_info(&exe), None);
        std::fs::write(app.join("Resources/lanceur.txt"), "/Users/x/NumFranc/NumFranc\n/Users/x/Library/Application Support/NumFranc\n").unwrap();
        assert_eq!(
            mac_bundle_info(&exe),
            Some((PathBuf::from("/Users/x/NumFranc/NumFranc"), "/Users/x/Library/Application Support/NumFranc".to_string()))
        );
        // Un programme rangé ailleurs n'est pas concerné.
        assert_eq!(mac_bundle_info(&base.join("bin/numfranc")), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn chemins_pieges_neutralises() {
        // Bash : $(…), `…` et " restent du texte entre apostrophes.
        assert_eq!(sh_quote("/home/a b"), "'/home/a b'");
        assert_eq!(sh_quote("/x/$(calc)/`id`/\"q\""), "'/x/$(calc)/`id`/\"q\"'");
        assert_eq!(sh_quote("/x/l'appli"), "'/x/l'\\''appli'");
        // PowerShell : l'apostrophe est doublée, la chaîne ne peut plus être refermée.
        assert_eq!(ps_quote(r"C:\Users\Public\a';Start-Process calc;'"), r"C:\Users\Public\a'';Start-Process calc;''");
        // XML.
        assert_eq!(xml("/a<b>&c"), "/a&lt;b&gt;&amp;c");
        // Retours à la ligne et caractères spéciaux des fichiers .desktop refusés.
        assert!(check_path("/home/a\nExec=calc").is_err());
        assert!(check_desktop_path("/home/a\"b").is_err());
        assert!(check_desktop_path("/home/$HOME").is_err());
        assert!(check_desktop_path("/home/éloïse/NumFranc").is_ok());
    }

    #[test]
    fn lien_depose_puis_repris_une_seule_fois() {
        let dir = std::env::temp_dir().join(format!("nfr-lien-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lien = "nfr:alice.nfr?amount=1.5&message=merci";
        // Personne ne tient le verrou : ce lancement ouvrira lui-même la fenêtre.
        assert_eq!(hand_over_link(&dir, lien), Ok(false));
        assert_eq!(take_link(&dir).as_deref(), Some(lien));
        assert_eq!(take_link(&dir), None);
        // Un lien mal formé est refusé et rien n'est déposé.
        assert!(hand_over_link(&dir, "nfr:").is_err());
        assert!(hand_over_link(&dir, "http://exemple.fr").is_err());
        assert_eq!(take_link(&dir), None);
        // Un fichier trafiqué qui n'est pas un lien nfr: est ignoré.
        std::fs::write(dir.join(LINK_FILE), "rm -rf /").unwrap();
        assert_eq!(take_link(&dir), None);
        // NumFranc déjà ouvert (verrou tenu) : le second lancement doit s'arrêter et laisser le lien.
        let tenu = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("numfranc.lock")).unwrap();
        tenu.try_lock().unwrap();
        assert_eq!(hand_over_link(&dir, lien), Ok(true));
        assert_eq!(take_link(&dir).as_deref(), Some(lien));
        drop(tenu);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
