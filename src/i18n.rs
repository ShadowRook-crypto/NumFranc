//! Langue de l'interface : français (par défaut) ou anglais.

use std::sync::atomic::{AtomicBool, Ordering};

static ENGLISH: AtomicBool = AtomicBool::new(false);

pub fn set_english(on: bool) {
    ENGLISH.store(on, Ordering::SeqCst);
}

pub fn en() -> bool {
    ENGLISH.load(Ordering::Relaxed)
}

/// Texte fixe dans la langue choisie.
pub fn t(fr: &'static str, en: &'static str) -> &'static str {
    if self::en() {
        en
    } else {
        fr
    }
}

/// Texte avec des valeurs : `tf!("bloc {h}", "block {h}")`.
#[macro_export]
macro_rules! tf {
    ($fr:literal, $en:literal $(,)?) => {
        if $crate::i18n::en() { format!($en) } else { format!($fr) }
    };
    ($fr:literal, $en:literal, $($arg:tt)*) => {
        if $crate::i18n::en() { format!($en, $($arg)*) } else { format!($fr, $($arg)*) }
    };
}
