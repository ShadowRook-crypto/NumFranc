//! Journal d'événements partagé entre le nœud, la console et la fenêtre.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

static EVENTS: Mutex<VecDeque<(u64, String)>> = Mutex::new(VecDeque::new());
static SEQ: AtomicU64 = AtomicU64::new(0);
/// Afficher aussi les événements dans le terminal (mode console).
pub static ECHO: AtomicBool = AtomicBool::new(true);
const KEEP: usize = 500;

/// Enregistre un événement (et l'affiche dans le terminal en mode console).
pub fn log(msg: &str) {
    if ECHO.load(Ordering::Relaxed) {
        println!("{msg}");
    }
    let n = SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    let mut q = EVENTS.lock().unwrap();
    q.push_back((n, msg.to_string()));
    while q.len() > KEEP {
        q.pop_front();
    }
}

/// Événements de numéro strictement supérieur à `after` (pour les notifications).
pub fn since(after: u64) -> Vec<(u64, String)> {
    EVENTS.lock().unwrap().iter().filter(|(n, _)| *n > after).cloned().collect()
}

/// Les `n` derniers événements.
pub fn recent(n: usize) -> Vec<String> {
    let q = EVENTS.lock().unwrap();
    q.iter().skip(q.len().saturating_sub(n)).map(|(_, m)| m.clone()).collect()
}

pub fn last_seq() -> u64 {
    SEQ.load(Ordering::SeqCst)
}
