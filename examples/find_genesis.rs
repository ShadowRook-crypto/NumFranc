//! Trouve le nonce du bloc genesis (à exécuter une seule fois), sur tous les cœurs.
use numfranc::chain::genesis_block;
use numfranc::encoding::hex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

fn main() {
    let g = genesis_block();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as u64;
    let found = AtomicBool::new(false);
    let tries = AtomicU64::new(0);
    let start = std::time::Instant::now();
    std::thread::scope(|s| {
        for t in 0..threads {
            let (g, found, tries) = (&g, &found, &tries);
            s.spawn(move || {
                let mut h = g.header.clone();
                let mut n = t;
                while !found.load(Ordering::Relaxed) {
                    h.nonce = n;
                    if h.meets_target() {
                        found.store(true, Ordering::Relaxed);
                        println!("GENESIS_NONCE = {n}");
                        println!("GENESIS_HASH  = {}", hex(&h.hash()));
                        return;
                    }
                    n += threads;
                    let k = tries.fetch_add(1, Ordering::Relaxed);
                    if k % 100_000 == 0 && t == 0 {
                        eprintln!("{k} essais, {:.0} s", start.elapsed().as_secs_f64());
                    }
                }
            });
        }
    });
}
