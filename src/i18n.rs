//! Langue de l'interface : français (par défaut), anglais, espagnol, allemand, italien, portugais.
//!
//! Le code garde ses deux textes « français, anglais » à chaque endroit. Pour les autres langues,
//! le texte anglais sert de clé dans une table (fichiers `lang/xx.txt`). Si une phrase manque dans
//! la table, l'anglais s'affiche : jamais de trou, jamais de plantage.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Fr,
    En,
    Es,
    De,
    It,
    Pt,
}

impl Lang {
    pub const ALL: [Lang; 6] = [Lang::Fr, Lang::En, Lang::Es, Lang::De, Lang::It, Lang::Pt];

    /// Code court écrit dans reglages.txt.
    pub fn code(self) -> &'static str {
        match self {
            Lang::Fr => "fr",
            Lang::En => "en",
            Lang::Es => "es",
            Lang::De => "de",
            Lang::It => "it",
            Lang::Pt => "pt",
        }
    }

    /// Nom de la langue, écrit dans cette langue.
    pub fn name(self) -> &'static str {
        match self {
            Lang::Fr => "Français",
            Lang::En => "English",
            Lang::Es => "Español",
            Lang::De => "Deutsch",
            Lang::It => "Italiano",
            Lang::Pt => "Português",
        }
    }

    pub fn from_code(code: &str) -> Option<Lang> {
        let c = code.trim().to_ascii_lowercase();
        let c = c.split(['_', '-', '.', '@']).next().unwrap_or("");
        Lang::ALL.into_iter().find(|l| l.code() == c)
    }

    fn index(self) -> u8 {
        Lang::ALL.iter().position(|l| *l == self).unwrap_or(0) as u8
    }

    /// Virgule décimale (« 12,5 ») ou point (« 12.5 ») ?
    pub fn decimal_comma(self) -> bool {
        !matches!(self, Lang::En)
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(l: Lang) {
    CURRENT.store(l.index(), Ordering::SeqCst);
}

pub fn lang() -> Lang {
    Lang::ALL.get(CURRENT.load(Ordering::Relaxed) as usize).copied().unwrap_or(Lang::Fr)
}

/// Vrai pour toute langue autre que le français (le texte de base est alors l'anglais).
pub fn en() -> bool {
    lang() != Lang::Fr
}

/// Séparateur décimal de la langue choisie.
pub fn decimal_sep() -> char {
    if lang().decimal_comma() {
        ','
    } else {
        '.'
    }
}

/// Langue du système (variables d'environnement, puis réglage de macOS). None si inconnue
/// ou non prise en charge : l'appelant garde alors le français.
pub fn detect_system() -> Option<Lang> {
    for var in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            if let Some(l) = v.split(':').find_map(Lang::from_code) {
                return Some(l);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("/usr/bin/defaults").args(["read", "-g", "AppleLanguages"]).output() {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            for tok in text.split(|c: char| !(c.is_ascii_alphabetic() || c == '-')).filter(|t| t.len() >= 2) {
                if let Some(l) = Lang::from_code(tok) {
                    return Some(l);
                }
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if let Ok(out) = std::process::Command::new(crate::install::system_tool("powershell"))
            .args(["-NoProfile", "-Command", "(Get-UICulture).TwoLetterISOLanguageName"])
            .creation_flags(0x0800_0000) // pas de fenêtre noire
            .output()
        {
            if let Some(l) = Lang::from_code(String::from_utf8_lossy(&out.stdout).trim()) {
                return Some(l);
            }
        }
    }
    None
}

// ---------------------------------------------------------------- tables de traduction

const FILES: [&str; 4] = [
    include_str!("lang/es.txt"),
    include_str!("lang/de.txt"),
    include_str!("lang/it.txt"),
    include_str!("lang/pt.txt"),
];

type Table = HashMap<&'static str, &'static str>;

static TABLES: [OnceLock<Table>; 4] = [OnceLock::new(), OnceLock::new(), OnceLock::new(), OnceLock::new()];

/// Décode `\n`, `\t` et `\\` d'une ligne de table.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Une ligne = « anglais <tab> traduction ». Les lignes vides ou commençant par # sont ignorées.
pub fn parse_table(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .map(|(k, v)| (unescape(k), unescape(v)))
        .collect()
}

fn table(l: Lang) -> Option<&'static Table> {
    let i = match l {
        Lang::Es => 0,
        Lang::De => 1,
        Lang::It => 2,
        Lang::Pt => 3,
        _ => return None,
    };
    Some(TABLES[i].get_or_init(|| {
        parse_table(FILES[i])
            .into_iter()
            .map(|(k, v)| (&*Box::leak(k.into_boxed_str()), &*Box::leak(v.into_boxed_str())))
            .collect()
    }))
}

fn lookup(l: Lang, en: &str) -> Option<&'static str> {
    table(l)?.get(en).copied()
}

/// Texte fixe dans la langue choisie.
pub fn t(fr: &'static str, en: &'static str) -> &'static str {
    match lang() {
        Lang::Fr => fr,
        Lang::En => en,
        other => lookup(other, en).unwrap_or(en),
    }
}

// ---------------------------------------------------------------- textes avec valeurs

#[derive(Debug, PartialEq)]
enum Piece {
    Lit(String),
    /// Nom du trou : « {} » donne "", « {h} » donne "h".
    Hole(String),
}

fn pieces(tpl: &str) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut it = tpl.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '{' if it.peek() == Some(&'{') => {
                it.next();
                lit.push('{');
            }
            '}' if it.peek() == Some(&'}') => {
                it.next();
                lit.push('}');
            }
            '{' => {
                let mut name = String::new();
                for d in it.by_ref() {
                    if d == '}' {
                        break;
                    }
                    name.push(d);
                }
                if !lit.is_empty() {
                    out.push(Piece::Lit(std::mem::take(&mut lit)));
                }
                out.push(Piece::Hole(name));
            }
            _ => lit.push(c),
        }
    }
    if !lit.is_empty() {
        out.push(Piece::Lit(lit));
    }
    out
}

/// Retrouve les valeurs insérées dans `rendered` (le texte anglais déjà formaté) à partir du
/// modèle anglais. None si le texte ne correspond pas (valeur qui contient un séparateur…).
fn extract(tpl: &[Piece], rendered: &str) -> Option<Vec<String>> {
    let mut pos = 0usize;
    let mut vals = Vec::new();
    let mut i = 0;
    while i < tpl.len() {
        match &tpl[i] {
            Piece::Lit(l) => {
                if !rendered[pos..].starts_with(l.as_str()) {
                    return None;
                }
                pos += l.len();
            }
            Piece::Hole(_) => match tpl.get(i + 1) {
                None => {
                    vals.push(rendered[pos..].to_string());
                    pos = rendered.len();
                }
                Some(Piece::Lit(next)) => {
                    let last = i + 2 >= tpl.len();
                    let at = if last { rendered[pos..].ends_with(next.as_str()).then(|| rendered.len() - next.len() - pos) } else { rendered[pos..].find(next.as_str()) }?;
                    vals.push(rendered[pos..pos + at].to_string());
                    pos += at;
                }
                Some(Piece::Hole(_)) => return None,
            },
        }
        i += 1;
    }
    (pos == rendered.len()).then_some(vals)
}

/// Remplit la traduction `tr` : « {} » = valeur anonyme suivante, « {2} » = 2e valeur anonyme (à partir
/// de 1), « {nom} » = valeur du trou de ce nom dans le modèle anglais. Comme `format!` : les trous
/// nommés et les trous anonymes se comptent séparément.
fn fill(tr: &str, names: &[String], vals: &[String]) -> Option<String> {
    let anon: Vec<&String> = names.iter().zip(vals).filter(|(n, _)| n.is_empty()).map(|(_, v)| v).collect();
    let mut out = String::new();
    let mut next = 0usize;
    for p in pieces(tr) {
        match p {
            Piece::Lit(l) => out.push_str(&l),
            Piece::Hole(n) => {
                let v = if n.is_empty() {
                    next += 1;
                    *anon.get(next - 1)?
                } else if let Ok(k) = n.parse::<usize>() {
                    *anon.get(k.checked_sub(1)?)?
                } else {
                    vals.get(names.iter().position(|x| *x == n)?)?
                };
                out.push_str(v);
            }
        }
    }
    Some(out)
}

fn translate_with(tr: &str, en_tpl: &str, rendered: &str) -> Option<String> {
    let tpl = pieces(en_tpl);
    let names: Vec<String> = tpl.iter().filter_map(|p| if let Piece::Hole(n) = p { Some(n.clone()) } else { None }).collect();
    let vals = extract(&tpl, rendered)?;
    fill(tr, &names, &vals)
}

/// Traduit un texte à valeurs : `en_tpl` est le modèle anglais (avec ses trous), `rendered` le
/// même texte une fois les valeurs insérées. None → on garde l'anglais.
pub fn translate_fmt(en_tpl: &str, rendered: &str) -> Option<String> {
    let l = lang();
    let tr = table(l)?.get(en_tpl).copied()?;
    translate_with(tr, en_tpl, rendered)
}

/// Texte avec des valeurs : `tf!("bloc {h}", "block {h}")`.
#[macro_export]
macro_rules! tf {
    ($fr:literal, $en:literal $(,)?) => {
        match $crate::i18n::lang() {
            $crate::i18n::Lang::Fr => format!($fr),
            $crate::i18n::Lang::En => format!($en),
            _ => {
                let s = format!($en);
                $crate::i18n::translate_fmt($en, &s).unwrap_or(s)
            }
        }
    };
    ($fr:literal, $en:literal, $($arg:tt)*) => {
        match $crate::i18n::lang() {
            $crate::i18n::Lang::Fr => format!($fr, $($arg)*),
            $crate::i18n::Lang::En => format!($en, $($arg)*),
            _ => {
                let s = format!($en, $($arg)*);
                $crate::i18n::translate_fmt($en, &s).unwrap_or(s)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_de_langue() {
        assert_eq!(Lang::from_code("fr_FR.UTF-8"), Some(Lang::Fr));
        assert_eq!(Lang::from_code("de-DE"), Some(Lang::De));
        assert_eq!(Lang::from_code("pt_BR"), Some(Lang::Pt));
        assert_eq!(Lang::from_code("zh_CN"), None);
        assert_eq!(Lang::from_code("C"), None);
    }

    #[test]
    fn trous_et_traduction() {
        let r = translate_with("bloque {2} sobre {}", "block {} on {}", "block 12 on main");
        assert_eq!(r.as_deref(), Some("bloque main sobre 12"));
        // Trous nommés et anonymes mélangés : comme format!, ils se comptent séparément.
        let r = translate_with("{label}: {} ({count} bloques)", "{label}: {} ({count} blocks)", "main: 5 (3 blocks)");
        assert_eq!(r.as_deref(), Some("main: 5 (3 bloques)"));
        let r = translate_with("altura {name}", "height {name}", "height 7");
        assert_eq!(r.as_deref(), Some("altura 7"));
        // Le texte ne correspond pas au modèle : on garde l'anglais.
        assert_eq!(translate_with("x", "a {} b", "zzz"), None);
        // Accolades doublées.
        assert_eq!(translate_with("{{ok}} {}", "{{ok}} {}", "{ok} 3").as_deref(), Some("{ok} 3"));
    }

    /// Chaque ligne de chaque table a les mêmes trous que sa clé anglaise.
    #[test]
    fn tables_coherentes() {
        for (i, f) in FILES.iter().enumerate() {
            let rows = parse_table(f);
            assert!(!rows.is_empty(), "table {i} vide");
            for (k, v) in rows {
                let kn = pieces(&k).iter().filter(|p| matches!(p, Piece::Hole(_))).count();
                let vals: Vec<String> = (0..kn).map(|n| format!("<{n}>")).collect();
                let names: Vec<String> = pieces(&k).iter().filter_map(|p| if let Piece::Hole(n) = p { Some(n.clone()) } else { None }).collect();
                let out = fill(&v, &names, &vals).unwrap_or_else(|| panic!("trou inconnu dans la table {i} : {v}"));
                for (n, name) in names.iter().enumerate() {
                    // Un trou nommé qui revient deux fois dans la clé n'a qu'une valeur utile.
                    if names.iter().position(|x| x == name && !name.is_empty()) == Some(n) || name.is_empty() {
                        assert!(out.contains(&format!("<{n}>")), "valeur {n} perdue dans la table {i} : {v}");
                    }
                }
            }
        }
    }
}
