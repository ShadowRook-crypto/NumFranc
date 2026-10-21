//! Nœud permanent (serveur) sous Linux : installation en service système qui démarre avec
//! l'ordinateur et se relance tout seul s'il s'arrête, plante ou se fige.
//!
//! - `sudo numfranc --installer-serveur [NFR1-… [CŒURS]]` : installe et démarre le service ;
//! - `sudo numfranc --desinstaller-serveur` : l'arrête et le retire (les données restent).
//!
//! Trois filets de sécurité :
//!   1. systemd relance le programme 10 s après tout arrêt (Restart=always, sans limite) ;
//!   2. le « chien de garde » : le nœud prévient systemd toutes les 30 s qu'il va bien. S'il se
//!      fige (blocage interne), les nouvelles cessent et systemd le relance au bout de 3 minutes ;
//!   3. la mise en veille de l'ordinateur est désactivée.
//! Le service tourne sous un compte système jetable (DynamicUser), sans droit sur le reste du disque.

use std::path::Path;

/// Nom du service systemd.
pub const SERVICE: &str = "numfranc-serveur";
/// Fichier des réglages du service (adresse de minage, cœurs).
pub const REGLAGES: &str = "/etc/default/numfranc-serveur";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const UNITE: &str = "/etc/systemd/system/numfranc-serveur.service";
/// Dossier des données du service (créé par systemd, réservé au service).
pub const DONNEES: &str = "/var/lib/numfranc";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const VEILLE: [&str; 4] = ["sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target"];
/// Ordinateur portable : fermer l'écran ne doit pas l'endormir.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CAPOT: &str = "/etc/systemd/logind.conf.d/numfranc-serveur.conf";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CAPOT_TEXTE: &str = "# NumFranc : un nœud permanent reste éveillé, même écran fermé.\n[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\nHandleLidSwitchDocked=ignore\n";

/// Texte du fichier de service systemd. `exe` : chemin complet du programme.
pub fn unite(exe: &Path) -> String {
    format!(
        "[Unit]
Description=NumFranc - noeud permanent (se relance tout seul)
After=network-online.target
Wants=network-online.target
# Ne jamais abandonner les relances, même après plusieurs pannes de suite.
StartLimitIntervalSec=0

[Service]
Type=notify
NotifyAccess=main
EnvironmentFile=-{REGLAGES}
ExecStart={exe} --serveur --dossier {DONNEES} $NUMFRANC_ARGS
Restart=always
RestartSec=10
# Chien de garde : sans nouvelles pendant 3 minutes, le nœud est relancé.
WatchdogSec=180
TimeoutStartSec=300
# Priorité basse : l'ordinateur reste utilisable.
Nice=10
# Compte système jetable, aucun droit en dehors de {DONNEES}.
DynamicUser=yes
StateDirectory=numfranc
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
",
        exe = exe.display()
    )
}

/// Contenu du fichier de réglages : adresse qui reçoit les récompenses de minage, nombre de cœurs.
pub fn reglages(adresse: Option<&str>, coeurs: usize) -> String {
    let mut args = String::new();
    if let Some(a) = adresse {
        args.push_str(&format!("--adresse-minage {a} --coeurs {coeurs}"));
    }
    format!(
        "# Réglages du nœud permanent NumFranc. Après une modification : sudo systemctl restart {SERVICE}\n\
         # Sans adresse de minage, le nœud relaie seulement (il ne mine pas).\n\
         NUMFRANC_ARGS=\"{args}\"\n"
    )
}

// ---------------------------------------------------------------- chien de garde systemd

/// Envoie un message à systemd (READY=1, WATCHDOG=1…). Sans effet hors de systemd.
#[cfg(target_os = "linux")]
pub fn notifier(msg: &str) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Ok(chemin) = std::env::var("NOTIFY_SOCKET") else { return };
    let Ok(sock) = UnixDatagram::unbound() else { return };
    let adresse = match chemin.strip_prefix('@') {
        Some(nom) => SocketAddr::from_abstract_name(nom.as_bytes()),
        None => SocketAddr::from_pathname(&chemin),
    };
    if let Ok(a) = adresse {
        let _ = sock.send_to_addr(msg.as_bytes(), &a);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn notifier(_msg: &str) {}

// ---------------------------------------------------------------- installation

#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> Result<(), String> {
    let prog = ["/usr/bin/systemctl", "/bin/systemctl"].into_iter().find(|p| Path::new(p).exists()).ok_or("systemd introuvable sur cet ordinateur")?;
    let st = std::process::Command::new(prog).args(args).status().map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("systemctl {} a échoué", args.join(" ")))
    }
}

#[cfg(target_os = "linux")]
fn est_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.split_whitespace().nth(1) == Some("0")))
        .unwrap_or(false)
}

/// Installe et démarre le service. `adresse` : adresse NFR1-… qui reçoit les récompenses (None = pas de minage).
#[cfg(target_os = "linux")]
pub fn installer(adresse: Option<&str>, coeurs: usize) -> Result<String, String> {
    if !est_root() {
        return Err("il faut les droits d'administrateur : relance la commande avec sudo devant".into());
    }
    // Adresse réécrite sous sa forme exacte (espaces ou retours à la ligne collés par erreur retirés).
    let adresse = match adresse {
        Some(a) => Some(crate::wallet::address_to_string(&crate::wallet::parse_address(a)?)),
        None => None,
    };
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.canonicalize().unwrap_or(exe);
    // Le service ne lance que le programme installé par le paquet (/usr/…, appartenant à root) :
    // pas un fichier qu'un utilisateur pourrait remplacer.
    let texte = exe.to_string_lossy().to_string();
    if !texte.starts_with("/usr/") || texte.chars().any(|c| c.is_whitespace() || matches!(c, '%' | '$' | '\\' | '"')) {
        return Err("installe d'abord le paquet .deb (le programme doit être dans /usr/bin)".into());
    }
    std::fs::write(UNITE, unite(&exe)).map_err(|e| format!("{UNITE} : {e}"))?;
    std::fs::write(REGLAGES, reglages(adresse.as_deref(), coeurs)).map_err(|e| format!("{REGLAGES} : {e}"))?;
    systemctl(&["daemon-reload"])?;
    // Plus de mise en veille : un serveur doit rester éveillé.
    let mut masque = vec!["mask"];
    masque.extend(VEILLE);
    systemctl(&masque)?;
    if std::fs::create_dir_all("/etc/systemd/logind.conf.d").is_ok() {
        let _ = std::fs::write(CAPOT, CAPOT_TEXTE);
    }
    systemctl(&["enable", SERVICE])?;
    systemctl(&["restart", SERVICE])?;
    let mine = match adresse {
        Some(a) => format!("il mine sur {coeurs} cœur(s) et envoie les récompenses à {a}"),
        None => "il relaie les blocs sans miner".into(),
    };
    Ok(format!(
        "Nœud permanent installé et démarré : {mine}.\n\
         Il démarre avec l'ordinateur et se relance tout seul en cas d'arrêt ou de blocage.\n\
         La mise en veille de cet ordinateur est désactivée (même écran fermé, après le prochain redémarrage).\n\
         Voir son état :        systemctl status {SERVICE}\n\
         Voir son journal :     journalctl -u {SERVICE} -f      (Ctrl+C pour quitter)\n\
         Dernière étape, à faire une fois dans le BIOS : rallumage automatique après une coupure de courant (voir SERVEUR.txt)."
    ))
}

/// Arrête et retire le service (les données de la chaîne restent dans /var/lib/numfranc).
#[cfg(target_os = "linux")]
pub fn desinstaller() -> Result<String, String> {
    if !est_root() {
        return Err("il faut les droits d'administrateur : relance la commande avec sudo devant".into());
    }
    let _ = systemctl(&["disable", "--now", SERVICE]);
    let _ = std::fs::remove_file(UNITE);
    let _ = std::fs::remove_file(REGLAGES);
    let _ = std::fs::remove_file(CAPOT);
    let mut demasque = vec!["unmask"];
    demasque.extend(VEILLE);
    let _ = systemctl(&demasque);
    systemctl(&["daemon-reload"])?;
    Ok("Nœud permanent arrêté et retiré. La mise en veille est de nouveau possible.".into())
}

#[cfg(not(target_os = "linux"))]
pub fn installer(_adresse: Option<&str>, _coeurs: usize) -> Result<String, String> {
    Err("le nœud permanent s'installe sur un ordinateur Linux (Ubuntu, Debian…)".into())
}

#[cfg(not(target_os = "linux"))]
pub fn desinstaller() -> Result<String, String> {
    Err("le nœud permanent s'installe sur un ordinateur Linux (Ubuntu, Debian…)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fichier_de_service() {
        let u = unite(Path::new("/usr/bin/numfranc"));
        assert!(u.contains("ExecStart=/usr/bin/numfranc --serveur --dossier /var/lib/numfranc $NUMFRANC_ARGS"));
        assert!(u.contains("Restart=always"));
        assert!(u.contains("StartLimitIntervalSec=0"));
        assert!(u.contains("WatchdogSec=180"));
        assert!(u.contains("DynamicUser=yes"));
    }

    #[test]
    fn fichier_de_reglages() {
        let r = reglages(Some("NFR1-ABCD"), 3);
        assert!(r.contains("NUMFRANC_ARGS=\"--adresse-minage NFR1-ABCD --coeurs 3\""));
        assert!(reglages(None, 3).contains("NUMFRANC_ARGS=\"\""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_systemd() {
        use std::os::unix::net::UnixDatagram;
        let dir = std::env::temp_dir().join(format!("nfr-notify-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let chemin = dir.join("sock");
        let recv = UnixDatagram::bind(&chemin).unwrap();
        // SAFETY : test seul à lire cette variable.
        unsafe { std::env::set_var("NOTIFY_SOCKET", &chemin) };
        notifier("WATCHDOG=1");
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        let mut b = [0u8; 32];
        let n = recv.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"WATCHDOG=1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
