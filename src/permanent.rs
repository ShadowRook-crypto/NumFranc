//! « Toujours allumé » : NumFranc continue quand la fenêtre est fermée, démarre avec l'ordinateur
//! et se relance tout seul.
//!
//! Trois rôles, un seul programme :
//!   - le GARDIEN (`--gardien`) : tout petit, il ne fait que surveiller. Le système le lance au
//!     démarrage (Mac : LaunchAgent, Windows : clé « Run », Linux : service systemd de l'utilisateur)
//!     et le relance s'il disparaît ;
//!   - le NŒUD D'ARRIÈRE-PLAN (`--fond`) : lancé par le gardien quand la fenêtre est fermée. Il garde
//!     le réseau et mine vers l'adresse de réception (publique) : aucune clé secrète, le portefeuille
//!     reste fermé et chiffré ;
//!   - la FENÊTRE : quand elle s'ouvre, elle le signale (battement toutes les 3 s). Le gardien arrête
//!     alors le nœud d'arrière-plan et la fenêtre prend sa place. Quand elle se ferme, le gardien
//!     relance le nœud d'arrière-plan dans les 15 secondes.
//!
//! Le gardien relance aussi le nœud d'arrière-plan s'il plante (10 s après) ou s'il se fige
//! (plus de nouvelles depuis 3 minutes).

use crate::settings::Settings;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Battement de la fenêtre ouverte (date de modification mise à jour toutes les 3 s).
const FENETRE: &str = "fenetre-active.txt";
/// Battement du nœud d'arrière-plan (toutes les 30 s, après avoir vérifié qu'il n'est pas figé).
const FOND: &str = "fond-vivant.txt";
/// Un seul gardien par dossier de données.
const GARDIEN_VERROU: &str = "gardien.lock";
/// Journal du nœud d'arrière-plan.
pub const FOND_JOURNAL: &str = "fond.log";

const FENETRE_VIVANTE: Duration = Duration::from_secs(12);
const FOND_FIGE: Duration = Duration::from_secs(180);
const DEMARRAGE_LENT: Duration = Duration::from_secs(300);
const PAUSE_RELANCE: Duration = Duration::from_secs(10);

fn age(p: &Path) -> Option<Duration> {
    let m = std::fs::metadata(p).ok()?.modified().ok()?;
    Some(SystemTime::now().duration_since(m).unwrap_or(Duration::ZERO))
}

fn toucher(p: &Path) {
    let _ = std::fs::write(p, format!("{}\n", std::process::id()));
}

/// La fenêtre est-elle ouverte sur ce dossier de données ?
pub fn fenetre_active(dir: &Path) -> bool {
    age(&dir.join(FENETRE)).is_some_and(|a| a < FENETRE_VIVANTE)
}

/// Le nœud d'arrière-plan a-t-il donné des nouvelles récemment ?
pub fn fond_actif(dir: &Path) -> bool {
    age(&dir.join(FOND)).is_some_and(|a| a < Duration::from_secs(90))
}

/// Fenêtre : signale qu'elle est ouverte, toutes les 3 s, jusqu'à la fin du programme.
pub fn fenetre_battement(dir: &Path) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LANCE: AtomicBool = AtomicBool::new(false);
    if LANCE.swap(true, Ordering::SeqCst) {
        return;
    }
    let f = dir.join(FENETRE);
    toucher(&f);
    std::thread::spawn(move || loop {
        toucher(&f);
        std::thread::sleep(Duration::from_secs(3));
    });
}

/// Le verrou du dossier de données est-il tenu par un autre NumFranc ?
pub fn verrou_tenu(dir: &Path) -> bool {
    let Ok(f) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("numfranc.lock")) else {
        return false;
    };
    match f.try_lock() {
        Ok(()) => {
            let _ = f.unlock();
            false
        }
        Err(_) => true,
    }
}

/// Fenêtre : attend que le nœud d'arrière-plan ait laissé la place (au plus `max`).
pub fn attendre_place(dir: &Path, max: Duration) {
    let t = Instant::now();
    while verrou_tenu(dir) && t.elapsed() < max {
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Nœud d'arrière-plan : signale qu'il va bien.
pub fn fond_battement(dir: &Path) {
    toucher(&dir.join(FOND));
}

/// Nombre de cœurs pour miner maintenant (horaire jour/nuit si activé, sinon la moitié des cœurs).
pub fn coeurs_voulus(s: &Settings) -> usize {
    use chrono::Timelike;
    let total = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    match s.scheduled_cores(chrono::Local::now().hour() as u8) {
        Some(n) => n.min(total),
        None => (total / 2).max(1),
    }
}

fn programme() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.canonicalize().unwrap_or(exe))
}

fn lancer_fond(dir: &Path) -> Option<std::process::Child> {
    let exe = programme()?;
    let journal = dir.join(FOND_JOURNAL);
    // Journal limité à 1 Mio : il repart de zéro au-delà.
    if std::fs::metadata(&journal).map(|m| m.len() > 1 << 20).unwrap_or(false) {
        let _ = std::fs::remove_file(&journal);
    }
    let sortie = std::fs::OpenOptions::new().create(true).append(true).open(&journal).ok()?;
    let erreurs = sortie.try_clone().ok()?;
    let mut c = std::process::Command::new(exe);
    c.arg("--fond").arg("--dossier").arg(dir).stdin(std::process::Stdio::null()).stdout(sortie).stderr(erreurs);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // pas de fenêtre noire
    }
    c.spawn().ok()
}

/// Le gardien : tourne tant que « Toujours allumé » est activé.
pub fn gardien(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let Ok(verrou) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(GARDIEN_VERROU)) else {
        return;
    };
    if verrou.try_lock().is_err() {
        // Un autre gardien veille déjà sur ce dossier : on attend un peu (pour ne pas être relancé en boucle).
        std::thread::sleep(Duration::from_secs(60));
        return;
    }
    let mut enfant: Option<(std::process::Child, Instant)> = None;
    let mut prochain = Instant::now();
    loop {
        let reglages = Settings::load(dir);
        let fenetre = fenetre_active(dir);
        if let Some((c, depart)) = &mut enfant {
            let fini = matches!(c.try_wait(), Ok(Some(_)));
            let fige = depart.elapsed() > DEMARRAGE_LENT && age(&dir.join(FOND)).is_none_or(|a| a > FOND_FIGE);
            if fenetre || fini || fige || !reglages.permanent {
                if !fini {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                if fini || fige {
                    prochain = Instant::now() + PAUSE_RELANCE;
                }
                enfant = None;
            }
        }
        if !reglages.permanent {
            return;
        }
        if enfant.is_none() && !fenetre && Instant::now() >= prochain && !verrou_tenu(dir) {
            match lancer_fond(dir) {
                Some(c) => enfant = Some((c, Instant::now())),
                None => prochain = Instant::now() + PAUSE_RELANCE,
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn battements_et_verrou() {
        let dir = std::env::temp_dir().join(format!("nfr-permanent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!fenetre_active(&dir));
        toucher(&dir.join(FENETRE));
        assert!(fenetre_active(&dir));
        assert!(!fond_actif(&dir));
        fond_battement(&dir);
        assert!(fond_actif(&dir));
        assert!(!verrou_tenu(&dir));
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("numfranc.lock")).unwrap();
        f.try_lock().unwrap();
        assert!(verrou_tenu(&dir));
        drop(f);
        assert!(!verrou_tenu(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coeurs_raisonnables() {
        let s = Settings { schedule: false, ..Default::default() };
        assert!(coeurs_voulus(&s) >= 1);
        let s = Settings { schedule: true, night_start: 0, night_end: 0, cores_day: 0, cores_night: 0, ..Default::default() };
        assert_eq!(coeurs_voulus(&s), 0);
    }
}
