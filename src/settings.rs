//! Réglages de l'application (fichier texte reglages.txt du dossier de données).

use crate::i18n::Lang;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub dark: bool,
    /// Indice dans ACCENTS.
    pub accent: usize,
    pub lang: Lang,
    /// Minage selon un horaire (nuit / jour).
    pub schedule: bool,
    /// Heure de début de la nuit (0-23) et de fin (0-23), heure locale.
    pub night_start: u8,
    pub night_end: u8,
    /// Cœurs utilisés la nuit et le jour (0 = pas de minage).
    pub cores_night: usize,
    pub cores_day: usize,
    /// Mode expert : tous les onglets visibles (sinon, l'essentiel et un menu « Plus »).
    pub expert: bool,
    /// L'utilisateur dit avoir ouvert le port lui-même sur sa box.
    pub manual_port: bool,
    /// NumFranc reste allumé en permanence (nœud d'arrière-plan quand la fenêtre est fermée).
    pub permanent: bool,
    /// La question « Garder NumFranc allumé en permanence ? » a-t-elle déjà été posée ?
    pub permanent_asked: bool,
    /// Case « Miner avec cet ordinateur » (retenue d'un lancement à l'autre, suivie en arrière-plan).
    pub mine: bool,
    /// Adresse de réception (publique) où le nœud d'arrière-plan envoie ses récompenses.
    pub reward_address: String,
}

/// Couleurs principales proposées : (nom FR, nom EN, couleur claire, couleur sombre).
pub const ACCENTS: [(&str, &str, [u8; 3], [u8; 3]); 6] = [
    ("Bleu", "Blue", [0, 38, 84], [130, 170, 230]),
    ("Vert", "Green", [20, 130, 70], [80, 200, 130]),
    ("Violet", "Purple", [110, 60, 170], [175, 130, 240]),
    ("Orange", "Orange", [200, 100, 0], [255, 160, 70]),
    ("Rouge", "Red", [190, 35, 50], [255, 110, 120]),
    ("Turquoise", "Teal", [0, 125, 130], [60, 200, 200]),
];

impl Default for Settings {
    fn default() -> Self {
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
        Self {
            dark: false,
            accent: 0,
            lang: crate::i18n::detect_system().unwrap_or(Lang::Fr),
            schedule: false,
            night_start: 22,
            night_end: 7,
            cores_night: cores.saturating_sub(1).max(1),
            cores_day: 1,
            expert: false,
            manual_port: false,
            permanent: false,
            permanent_asked: false,
            mine: true,
            reward_address: String::new(),
        }
    }
}

fn file(dir: &Path) -> PathBuf {
    dir.join("reglages.txt")
}

impl Settings {
    pub fn load(dir: &Path) -> Self {
        let mut s = Self::default();
        let Ok(text) = std::fs::read_to_string(file(dir)) else { return s };
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "theme" => s.dark = v == "sombre",
                "couleur" => s.accent = v.parse().unwrap_or(0).min(ACCENTS.len() - 1),
                "langue" => s.lang = Lang::from_code(v).unwrap_or(Lang::Fr),
                "horaire" => s.schedule = v == "oui",
                "nuit_debut" => s.night_start = v.parse().unwrap_or(22).min(23),
                "nuit_fin" => s.night_end = v.parse().unwrap_or(7).min(23),
                "coeurs_nuit" => s.cores_night = v.parse().unwrap_or(s.cores_night),
                "coeurs_jour" => s.cores_day = v.parse().unwrap_or(s.cores_day),
                "expert" => s.expert = v == "oui",
                "port_manuel" => s.manual_port = v == "oui",
                "permanent" => s.permanent = v == "oui",
                "permanent_demande" => s.permanent_asked = v == "oui",
                "minage" => s.mine = v != "non",
                "adresse_minage" => s.reward_address = v.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect(),
                _ => {}
            }
        }
        s
    }

    pub fn save(&self, dir: &Path) {
        let text = format!(
            "# Réglages NumFranc\ntheme={}\ncouleur={}\nlangue={}\nhoraire={}\nnuit_debut={}\nnuit_fin={}\ncoeurs_nuit={}\ncoeurs_jour={}\nexpert={}\nport_manuel={}\npermanent={}\npermanent_demande={}\nminage={}\nadresse_minage={}\n",
            if self.dark { "sombre" } else { "clair" },
            self.accent,
            self.lang.code(),
            if self.schedule { "oui" } else { "non" },
            self.night_start,
            self.night_end,
            self.cores_night,
            self.cores_day,
            if self.expert { "oui" } else { "non" },
            if self.manual_port { "oui" } else { "non" },
            if self.permanent { "oui" } else { "non" },
            if self.permanent_asked { "oui" } else { "non" },
            if self.mine { "oui" } else { "non" },
            self.reward_address
        );
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(file(dir), text);
    }

    /// Est-ce la nuit à l'heure `hour` (0-23) ? La nuit peut passer minuit (ex. 22 h → 7 h).
    pub fn is_night(&self, hour: u8) -> bool {
        if self.night_start == self.night_end {
            false
        } else if self.night_start < self.night_end {
            hour >= self.night_start && hour < self.night_end
        } else {
            hour >= self.night_start || hour < self.night_end
        }
    }

    /// Nombre de cœurs voulu à l'heure `hour` (None si l'horaire est désactivé).
    pub fn scheduled_cores(&self, hour: u8) -> Option<usize> {
        if !self.schedule {
            return None;
        }
        Some(if self.is_night(hour) { self.cores_night } else { self.cores_day })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn horaire_de_nuit() {
        let s = Settings { schedule: true, night_start: 22, night_end: 7, cores_night: 4, cores_day: 0, ..Default::default() };
        assert_eq!(s.scheduled_cores(23), Some(4));
        assert_eq!(s.scheduled_cores(3), Some(4));
        assert_eq!(s.scheduled_cores(7), Some(0));
        assert_eq!(s.scheduled_cores(15), Some(0));
        let off = Settings { schedule: false, ..s.clone() };
        assert_eq!(off.scheduled_cores(23), None);
    }

    #[test]
    fn sauvegarde_et_relecture() {
        let dir = std::env::temp_dir().join(format!("nfr-reglages-{}", std::process::id()));
        let s = Settings { dark: true, accent: 3, lang: Lang::De, schedule: true, night_start: 21, night_end: 6, cores_night: 3, cores_day: 1, expert: true, manual_port: true, permanent: true, permanent_asked: true, mine: false, reward_address: "NFR1-ABCD".into() };
        s.save(&dir);
        assert_eq!(Settings::load(&dir), s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
