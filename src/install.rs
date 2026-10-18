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

/// Ajoute NumFranc au menu des applications. Renvoie une phrase décrivant ce qui a été fait.
pub fn add_to_menu(data_dir: &Path) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let workdir = launcher_dir(&exe);
    let data = data_dir.display().to_string();
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
            "[Desktop Entry]\nType=Application\nName=NumFranc\nComment=Monnaie post-quantique NumFranc (NFR)\nExec=\"{}\" --dossier \"{}\"\nPath={}\nIcon={}\nTerminal=false\nCategories=Finance;Network;\n",
            exe.display(),
            data,
            workdir.display(),
            icon.display()
        );
        let file = apps.join("numfranc.desktop");
        std::fs::write(&file, desktop).map_err(|e| e.to_string())?;
        set_executable(&file);
        Ok(crate::tf!("NumFranc est dans le menu des applications ({}).", "NumFranc is in the applications menu ({}).", file.display()))
    } else if cfg!(target_os = "macos") {
        let h = home()?;
        let app = h.join("Applications/NumFranc.app/Contents");
        std::fs::create_dir_all(app.join("MacOS")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(app.join("Resources")).map_err(|e| e.to_string())?;
        std::fs::write(app.join("Resources/NumFranc.icns"), icns(LOGO_PNG_256, LOGO_PNG_512)).map_err(|e| e.to_string())?;
        let script = format!(
            "#!/bin/bash\ncd \"{}\"\nexec \"{}\" --dossier \"{}\"\n",
            workdir.display(),
            exe.display(),
            data
        );
        let launcher = app.join("MacOS/NumFranc");
        std::fs::write(&launcher, script).map_err(|e| e.to_string())?;
        set_executable(&launcher);
        let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>CFBundleName</key><string>NumFranc</string>\n<key>CFBundleDisplayName</key><string>NumFranc</string>\n<key>CFBundleIdentifier</key><string>org.numfranc.app</string>\n<key>CFBundleExecutable</key><string>NumFranc</string>\n<key>CFBundleIconFile</key><string>NumFranc</string>\n<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleVersion</key><string>1</string>\n<key>NSHighResolutionCapable</key><true/>\n</dict></plist>\n";
        std::fs::write(app.join("Info.plist"), plist).map_err(|e| e.to_string())?;
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
            lnk.display(),
            exe.display(),
            data,
            workdir.display(),
            ico_path.display()
        );
        let ok = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
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
        std::process::Command::new("reg")
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
    let on = crate::i18n::t("NumFranc démarrera tout seul à l'ouverture de ta session (fenêtre réduite).", "NumFranc will start by itself when you log in (window minimized).");
    let off = crate::i18n::t("Démarrage automatique désactivé.", "Automatic start disabled.");
    if cfg!(target_os = "windows") {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let ok = if enable {
            let cmd = format!("\"{}\" --reduit --dossier \"{}\"", exe.display(), data);
            std::process::Command::new("reg").args(["add", key, "/v", AUTOSTART_NAME, "/t", "REG_SZ", "/d", &cmd, "/f"]).status().map(|s| s.success()).unwrap_or(false)
        } else {
            let _ = std::process::Command::new("reg").args(["delete", key, "/v", AUTOSTART_NAME, "/f"]).status();
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
            exe.display(),
            data,
            workdir.display()
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
