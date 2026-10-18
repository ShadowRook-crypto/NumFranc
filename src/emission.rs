//! Politique d'émission : récompense par bloc, plafonnée au reliquat.

use crate::config::{HARD_CAP, PALIER_BLOCKS, PEAK_REWARD, SLOW_START_REWARD};

/// Récompense (en unités minimales) du bloc `height`, sachant que
/// `total_mined` unités ont déjà été émises.
pub fn block_reward(height: u64, total_mined: u64) -> u64 {
    let remaining = HARD_CAP.saturating_sub(total_mined);
    if remaining == 0 {
        return 0;
    }

    let palier = height / PALIER_BLOCKS;
    let calculated = if palier == 0 {
        SLOW_START_REWARD
    } else {
        // Palier 1 = pic, puis -10 % par palier en division entière.
        let mut r = PEAK_REWARD;
        for _ in 1..palier {
            r = r * 9 / 10;
            if r == 0 {
                return 0;
            }
        }
        r
    };

    calculated.min(remaining)
}

/// Déroule toute l'émission. Renvoie (total émis, hauteur du dernier bloc, récompense du dernier bloc).
pub fn simulate_full_emission() -> (u64, u64, u64) {
    let mut total = 0u64;
    let mut height = 0u64;
    let mut last = (0u64, 0u64);
    loop {
        let r = block_reward(height, total);
        if r == 0 {
            break;
        }
        total += r;
        last = (height, r);
        height += 1;
    }
    (total, last.0, last.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palier_0_slow_start() {
        assert_eq!(block_reward(0, 0), 691_000_000);
        assert_eq!(block_reward(99_999, 0), 691_000_000);
    }

    #[test]
    fn palier_1_pic() {
        assert_eq!(block_reward(100_000, 0), 6_910_000_000);
    }

    #[test]
    fn decroissance_de_10_pourcent() {
        assert_eq!(block_reward(200_000, 0), 6_219_000_000);
    }

    #[test]
    fn plafonne_au_reliquat() {
        let total_avant = HARD_CAP - 44_971_536;
        assert_eq!(block_reward(4_471_948, total_avant), 44_971_536);
    }

    #[test]
    fn zero_apres_plafond() {
        assert_eq!(block_reward(4_471_949, HARD_CAP), 0);
    }

    #[test]
    fn emission_totale_exacte() {
        let (total, last_h, last_r) = simulate_full_emission();
        assert_eq!(total, HARD_CAP);
        assert_eq!(last_h, 4_471_948);
        assert_eq!(last_r, 44_971_536);
    }
}

/// Total émis par le calendrier avant le bloc `height` (somme des récompenses
/// des blocs 0 à height-1). Calcul par palier, exact et rapide.
pub fn total_before(height: u64) -> u64 {
    let mut total = 0u64;
    let mut h = 0u64;
    while h < height {
        let r = block_reward(h, total);
        if r == 0 {
            break;
        }
        let palier_end = (h / PALIER_BLOCKS + 1) * PALIER_BLOCKS;
        let n = palier_end.min(height) - h;
        let remaining = HARD_CAP - total;
        if (r as u128) * (n as u128) <= remaining as u128 {
            total += r * n;
            h += n;
        } else {
            let full = remaining / r;
            total += full * r;
            h += full;
            if h < height && total < HARD_CAP {
                total = HARD_CAP;
            }
            break;
        }
    }
    total
}

#[cfg(test)]
mod total_tests {
    use super::*;

    #[test]
    fn total_before_correspond_a_la_somme_bloc_par_bloc() {
        let mut total = 0u64;
        for h in 0..300_500u64 {
            if h % 50_000 == 0 || h == 99_999 || h == 100_001 || h == 300_499 {
                assert_eq!(total_before(h), total, "hauteur {h}");
            }
            total += block_reward(h, total);
        }
    }

    #[test]
    fn total_before_atteint_le_plafond() {
        assert_eq!(total_before(4_471_948), HARD_CAP - 44_971_536);
        assert_eq!(total_before(4_471_949), HARD_CAP);
        assert_eq!(total_before(10_000_000), HARD_CAP);
    }
}
