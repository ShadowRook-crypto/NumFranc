//! Sécurité du portefeuille :
//! - dérivation de clé Argon2id (lente et gourmande en mémoire : deviner un mot de passe coûte cher) ;
//! - double chiffrement authentifié AES-256-GCM puis XChaCha20-Poly1305, avec deux clés
//!   indépendantes de 256 bits (512 bits au total) : si un algorithme est un jour cassé, l'autre protège encore ;
//! - partage de Shamir 2 sur 3 du code de secours ;
//! - empreinte visuelle des adresses (4 mots + une couleur).
//!
//! Aucune cryptographie maison : AES-GCM, XChaCha20-Poly1305 et Argon2 viennent du projet RustCrypto.
//! Seul le partage de Shamir est écrit ici (arithmétique de GF(256), testée ci-dessous).

use crate::hashing::{hash512, sha3_512};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Réglages Argon2id d'un coffre (enregistrés dans le fichier, donc modifiables plus tard).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

/// Mot de passe d'ouverture : 256 Mio de mémoire, 3 passes (environ 1 s par essai sur un PC).
pub const STRONG: KdfParams = KdfParams { mem_kib: 256 * 1024, passes: 3, lanes: 1 };
/// Code de dépense (protège la clé secrète) : 1 Gio de mémoire, 4 passes (environ 3 à 5 s par essai).
/// Il ne sert qu'au moment d'envoyer : on peut se permettre d'attendre, un voleur aussi… des milliards de fois.
pub const VAULT_STRONG: KdfParams = KdfParams { mem_kib: 1024 * 1024, passes: 4, lanes: 1 };

/// Réglages du coffre correspondant aux réglages de la vue (tests : réglage léger partout).
pub fn vault_params(view: KdfParams) -> KdfParams {
    if view == STRONG { VAULT_STRONG } else { view }
}
/// Réglage léger réservé aux tests automatiques.
pub const TEST: KdfParams = KdfParams { mem_kib: 1024, passes: 1, lanes: 1 };

/// Longueurs minimales imposées.
pub const MIN_OPEN_PASSWORD: usize = 12;
pub const MIN_SPEND_CODE: usize = 16;

/// Clé de 512 bits dérivée d'un mot de passe : 256 bits pour AES, 256 bits pour XChaCha20.
pub fn derive_key(password: &str, salt: &[u8; 32], p: KdfParams) -> Result<Zeroizing<[u8; 64]>, String> {
    let params = Params::new(p.mem_kib, p.passes, p.lanes, Some(64)).map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 64]);
    a.hash_password_into(password.as_bytes(), salt, key.as_mut()).map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

/// Une section chiffrée du fichier portefeuille.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub params: KdfParams,
    pub salt: [u8; 32],
    pub nonce_aes: [u8; 12],
    pub nonce_xchacha: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Chiffre deux fois : AES-256-GCM, puis XChaCha20-Poly1305 sur le résultat.
/// `label` (ex. "vue" ou "coffre") est authentifié : on ne peut pas intervertir les sections.
pub fn seal(key: &[u8; 64], params: KdfParams, salt: [u8; 32], label: &[u8], plaintext: &[u8]) -> Result<Sealed, String> {
    let nonce_aes: [u8; 12] = random()?;
    let nonce_xchacha: [u8; 24] = random()?;
    let aad = [b"NumFranc-portefeuille-v3/".as_slice(), label].concat();
    let aes = Aes256Gcm::new_from_slice(&key[..32]).map_err(|e| e.to_string())?;
    let inner = aes
        .encrypt(Nonce::from_slice(&nonce_aes), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| "chiffrement AES impossible".to_string())?;
    let xc = XChaCha20Poly1305::new_from_slice(&key[32..]).map_err(|e| e.to_string())?;
    let ciphertext = xc
        .encrypt(XNonce::from_slice(&nonce_xchacha), Payload { msg: &inner, aad: &aad })
        .map_err(|_| "chiffrement XChaCha20 impossible".to_string())?;
    Ok(Sealed { params, salt, nonce_aes, nonce_xchacha, ciphertext })
}

/// Déchiffre une section. Un mauvais mot de passe ou un fichier modifié donnent la même erreur.
pub fn open(key: &[u8; 64], label: &[u8], s: &Sealed) -> Result<Zeroizing<Vec<u8>>, String> {
    let bad = || crate::i18n::t("mot de passe incorrect (ou fichier modifié)", "wrong password (or modified file)").to_string();
    let aad = [b"NumFranc-portefeuille-v3/".as_slice(), label].concat();
    let xc = XChaCha20Poly1305::new_from_slice(&key[32..]).map_err(|e| e.to_string())?;
    let inner = Zeroizing::new(
        xc.decrypt(XNonce::from_slice(&s.nonce_xchacha), Payload { msg: &s.ciphertext, aad: &aad }).map_err(|_| bad())?,
    );
    let aes = Aes256Gcm::new_from_slice(&key[..32]).map_err(|e| e.to_string())?;
    let plain = aes.decrypt(Nonce::from_slice(&s.nonce_aes), Payload { msg: &inner, aad: &aad }).map_err(|_| bad())?;
    Ok(Zeroizing::new(plain))
}

impl Sealed {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.params.mem_kib.to_be_bytes());
        out.extend_from_slice(&self.params.passes.to_be_bytes());
        out.extend_from_slice(&self.params.lanes.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce_aes);
        out.extend_from_slice(&self.nonce_xchacha);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
    }

    pub fn decode(r: &mut crate::encoding::Reader) -> Result<Self, String> {
        let e = |_| "fichier portefeuille corrompu".to_string();
        let params = KdfParams { mem_kib: r.u32().map_err(e)?, passes: r.u32().map_err(e)?, lanes: r.u32().map_err(e)? };
        // Garde-fous contre un fichier piégé qui demanderait une mémoire démesurée.
        if params.mem_kib > 4 * 1024 * 1024 || params.passes == 0 || params.passes > 64 || params.lanes == 0 || params.lanes > 16 {
            return Err("réglages de chiffrement invalides dans le fichier".into());
        }
        let salt = r.array().map_err(e)?;
        let nonce_aes = r.array().map_err(e)?;
        let nonce_xchacha = r.array().map_err(e)?;
        let len = r.u32().map_err(e)? as usize;
        let ciphertext = r.bytes(len).map_err(e)?.to_vec();
        Ok(Self { params, salt, nonce_aes, nonce_xchacha, ciphertext })
    }
}

/// Règles des mots de passe : longueur minimale, et au moins trois sortes de caractères
/// (minuscules, majuscules, chiffres, symboles) — ou une phrase longue de 20 caractères et plus.
pub fn check_password(pw: &str, min_len: usize, what: &str) -> Result<(), String> {
    let n = pw.chars().count();
    if n < min_len {
        return Err(crate::tf!("{what} : au moins {min_len} caractères ({n} pour l'instant)", "{what}: at least {min_len} characters ({n} so far)"));
    }
    let distinct = pw.chars().collect::<std::collections::HashSet<_>>().len();
    if distinct < min_len / 2 {
        return Err(crate::tf!("{what} : trop de caractères répétés (au moins {} caractères différents)", "{what}: too many repeated characters (at least {} different characters)", min_len / 2));
    }
    let kinds = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    if kinds < 3 && n < 20 {
        return Err(crate::tf!(
            "{what} : mélangez au moins 3 sortes de caractères (minuscules, majuscules, chiffres, symboles), ou utilisez une phrase de 20 caractères et plus",
            "{what}: mix at least 3 kinds of characters (lowercase, uppercase, digits, symbols), or use a phrase of 20 characters or more"
        ));
    }
    let lower = pw.to_lowercase();
    for weak in ["numfranc", "password", "motdepasse", "azerty", "qwerty", "123456", "000000"] {
        if lower.contains(weak) {
            return Err(crate::tf!("{what} : trop facile à deviner (contient « {weak} »)", "{what}: too easy to guess (contains “{weak}”)"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Partage de Shamir 2 sur 3 sur GF(256) (polynôme 0x11B, celui d'AES).
// ---------------------------------------------------------------------------

pub(crate) fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

pub(crate) fn gf_inv(a: u8) -> u8 {
    // a^254 = a^-1 dans GF(256)
    let mut r = 1u8;
    let mut x = a;
    let mut e = 254u32;
    while e > 0 {
        if e & 1 == 1 {
            r = gf_mul(r, x);
        }
        x = gf_mul(x, x);
        e >>= 1;
    }
    r
}

/// Identifiant du portefeuille inscrit dans chaque morceau (pour ne pas mélanger deux portefeuilles).
fn wallet_id(seed: &[u8; 32]) -> [u8; 4] {
    hash512(&[b"NFR-id".as_slice(), seed].concat())[..4].try_into().unwrap()
}

const SHARE_PREFIX: &str = "NFRS";

/// Découpe la graine en 3 morceaux ; 2 suffisent pour la reconstituer.
/// Le coefficient secret est tiré de la graine elle-même : le découpage est toujours le même,
/// donc réafficher les morceaux redonne exactement les mêmes, et on peut combiner n'importe
/// quels 2 morceaux notés à des moments différents. Un seul morceau ne permet pas de retrouver
/// la graine (il faudrait essayer 2^256 graines).
pub fn split_seed(seed: &[u8; 32]) -> Result<[String; 3], String> {
    let coeffs: Zeroizing<[u8; 32]> =
        Zeroizing::new(hash512(&[b"NFR-shamir-coefficients".as_slice(), seed].concat())[..32].try_into().unwrap());
    let id = wallet_id(seed);
    let mut out: [String; 3] = Default::default();
    for (k, x) in [1u8, 2, 3].iter().enumerate() {
        let mut raw = Zeroizing::new(vec![*x]);
        raw.extend_from_slice(&id);
        for i in 0..32 {
            raw.push(seed[i] ^ gf_mul(coeffs[i], *x));
        }
        let check = sha3_512(&raw);
        raw.extend_from_slice(&check[..4]);
        out[k] = format_share(&raw);
    }
    Ok(out)
}

fn format_share(raw: &[u8]) -> String {
    let body = crate::wallet::b32_encode(raw);
    let groups: Vec<&str> = body.as_bytes().chunks(6).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("{SHARE_PREFIX}-{}", groups.join("-"))
}

fn parse_share(s: &str) -> Result<(u8, [u8; 4], Zeroizing<[u8; 32]>), String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    let body = clean
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case(SHARE_PREFIX))
        .map(|_| &clean[4..])
        .ok_or(crate::i18n::t("un morceau de secours commence par NFRS", "a recovery piece starts with NFRS"))?;
    let raw = Zeroizing::new(crate::wallet::b32_decode(body).ok_or(crate::i18n::t("caractères invalides dans le morceau", "invalid characters in the piece"))?);
    if raw.len() != 41 {
        return Err(crate::i18n::t("longueur de morceau incorrecte (morceau coupé ?)", "wrong piece length (piece cut off?)").into());
    }
    if sha3_512(&raw[..37])[..4] != raw[37..41] {
        return Err(crate::i18n::t("somme de contrôle du morceau incorrecte (faute de frappe ?)", "wrong piece checksum (typo?)").into());
    }
    let x = raw[0];
    if !(1..=3).contains(&x) {
        return Err(crate::i18n::t("numéro de morceau invalide", "invalid piece number").into());
    }
    let id: [u8; 4] = raw[1..5].try_into().unwrap();
    let mut y = Zeroizing::new([0u8; 32]);
    y.copy_from_slice(&raw[5..37]);
    Ok((x, id, y))
}

/// Numéro (1, 2 ou 3) d'un morceau, s'il est bien formé.
pub fn share_number(s: &str) -> Option<u8> {
    parse_share(s).ok().map(|p| p.0)
}

/// Reconstitue la graine à partir de deux morceaux différents du même portefeuille.
pub fn join_shares(a: &str, b: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let (xa, ida, ya) = parse_share(a)?;
    let (xb, idb, yb) = parse_share(b)?;
    if xa == xb {
        return Err(crate::tf!("il faut deux morceaux DIFFÉRENTS (ici deux fois le n° {xa})", "you need two DIFFERENT pieces (here twice piece no. {xa})"));
    }
    if ida != idb {
        return Err(crate::i18n::t("ces deux morceaux ne viennent pas du même portefeuille", "these two pieces do not come from the same wallet").into());
    }
    // Interpolation de Lagrange en 0 : s = (ya*xb + yb*xa) / (xa + xb)   (+ = XOR dans GF(256))
    let inv = gf_inv(xa ^ xb);
    let mut seed = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        seed[i] = gf_mul(gf_mul(ya[i], xb) ^ gf_mul(yb[i], xa), inv);
    }
    if wallet_id(&seed) != ida {
        return Err("reconstitution incohérente".into());
    }
    Ok(seed)
}

// ---------------------------------------------------------------------------
// Empreinte visuelle d'une adresse : 4 mots + une couleur.
// ---------------------------------------------------------------------------

/// 256 mots simples, tous différents, sans accent, faciles à lire à voix haute.
const WORDS: [&str; 256] = [
    "abeille", "abricot", "agneau", "aigle", "algue", "amande", "ananas", "ancre", "anneau", "arbre", "arche", "argent",
    "asperge", "atlas", "aurore", "avion", "badge", "baleine", "balle", "banane", "barque", "bateau", "bambou", "bougie",
    "berger", "biche", "bison", "blason", "boussole", "bouton", "brebis", "brique", "bulle", "cactus", "cadran", "camion",
    "canard", "canne", "canot", "carotte", "castor", "cerise", "chameau", "chapeau", "chat", "cheval", "chevre", "chien",
    "cigale", "citron", "clairon", "cloche", "cobra", "coffre", "colibri", "comete", "corail", "corde", "coton", "crabe",
    "crayon", "cygne", "dauphin", "delta", "desert", "diamant", "domino", "dragon", "drapeau", "dune", "ecureuil", "eclair",
    "ecorce", "epice", "etoile", "falaise", "faucon", "fenouil", "figue", "flamant", "fleur", "flute", "fontaine", "foret",
    "fourmi", "fraise", "frelon", "fusee", "gazelle", "girafe", "glacier", "gland", "gorille", "grenade", "grillon", "guitare",
    "hamac", "harpe", "herisson", "hibou", "homard", "horloge", "iguane", "igloo", "jaguar", "jardin", "jasmin", "jonque",
    "kayak", "kiwi", "koala", "lagon", "lama", "lampe", "lapin", "laurier", "lavande", "lemur", "leopard", "lezard",
    "licorne", "lilas", "limace", "lion", "loutre", "loup", "lune", "lynx", "manchot", "mangue", "marmotte", "marteau",
    "melon", "menthe", "merle", "meteore", "miel", "moineau", "montagne", "mouette", "mouton", "muguet", "myrtille", "narval",
    "navire", "neige", "noisette", "nuage", "oasis", "ocean", "olive", "orange", "orchidee", "ours", "palmier", "panda",
    "panthere", "papillon", "pastel", "paon", "pelican", "pepite", "perle", "phare", "piano", "pigeon", "pinson", "pirogue",
    "planete", "plume", "poire", "pomme", "poney", "prairie", "puma", "pyramide", "quartz", "radar", "radis", "raisin",
    "renard", "requin", "riviere", "robot", "rocher", "rose", "rubis", "sable", "safran", "salade", "sapin", "sardine",
    "saturne", "saule", "serpent", "silex", "singe", "soleil", "source", "sphinx", "tambour", "tapir", "taureau", "tigre",
    "tomate", "tortue", "toucan", "tulipe", "turbo", "vague", "valise", "vanille", "violon", "volcan", "voilier", "zebre",
    "ardoise", "boulet", "bonsai", "cabane", "calcul", "canyon", "cedre", "chalet", "chene", "citadelle", "cristal", "cypres",
    "flocon", "galet", "geyser", "granit", "hublot", "iris", "lotus", "marais", "mimosa", "nectar", "obsidienne", "opale",
    "pivoine", "prisme", "quasar", "roseau", "saphir", "tonnerre", "topaze", "zephyr",
    "colline", "dahlia", "emeraude", "fjord", "grotte", "jungle", "lanterne", "mammouth",
];

/// Couleurs nommées (teinte bien distincte).
pub const COLORS: [(&str, [u8; 3]); 8] = [
    ("rouge", [214, 48, 49]),
    ("orange", [230, 126, 34]),
    ("jaune", [241, 196, 15]),
    ("vert", [39, 174, 96]),
    ("turquoise", [26, 188, 156]),
    ("bleu", [41, 128, 185]),
    ("violet", [142, 68, 173]),
    ("rose", [232, 67, 147]),
];

/// Empreinte visuelle : 4 mots (32 bits) + une couleur parmi 8 (3 bits).
/// Elle sert à vérifier d'un coup d'œil qu'une adresse collée est bien la bonne
/// (protection contre les virus qui remplacent une adresse copiée). L'adresse complète
/// reste la référence : sa somme de contrôle est toujours vérifiée.
pub fn fingerprint(addr: &[u8; 32]) -> (String, usize) {
    let h = hash512(&[b"NFR-empreinte".as_slice(), addr].concat());
    let words: Vec<&str> = h[..4].iter().map(|&b| WORDS[b as usize]).collect();
    (words.join(" "), (h[4] % 8) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_chiffrement_aller_retour_et_mauvais_mot_de_passe() {
        let salt = random::<32>().unwrap();
        let k = derive_key("Correct-Horse-42", &salt, TEST).unwrap();
        let s = seal(&k, TEST, salt, b"coffre", b"secret de 32 octets..............").unwrap();
        assert_eq!(&open(&k, b"coffre", &s).unwrap()[..], b"secret de 32 octets..............");
        let bad = derive_key("Correct-Horse-43", &salt, TEST).unwrap();
        assert!(open(&bad, b"coffre", &s).is_err());
        // Section interchangée : refusée grâce à l'étiquette authentifiée.
        assert!(open(&k, b"vue", &s).is_err());
        // Un seul bit modifié : refusé.
        let mut t = s.clone();
        t.ciphertext[3] ^= 1;
        assert!(open(&k, b"coffre", &t).is_err());
        // Aller-retour binaire.
        let mut buf = Vec::new();
        s.encode(&mut buf);
        let mut r = crate::encoding::Reader::new(&buf);
        assert_eq!(Sealed::decode(&mut r).unwrap(), s);
    }

    #[test]
    fn deux_couches_independantes() {
        // Les deux moitiés de la clé de 512 bits sont différentes et toutes deux nécessaires.
        let salt = random::<32>().unwrap();
        let k = derive_key("Correct-Horse-42", &salt, TEST).unwrap();
        assert_ne!(k[..32], k[32..]);
        let s = seal(&k, TEST, salt, b"x", b"abc").unwrap();
        let mut k2 = *k;
        k2[40] ^= 1; // couche XChaCha20 fausse
        assert!(open(&k2, b"x", &s).is_err());
        let mut k3 = *k;
        k3[5] ^= 1; // couche AES fausse
        assert!(open(&k3, b"x", &s).is_err());
    }

    #[test]
    fn galois_inverse() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }

    #[test]
    fn shamir_deux_morceaux_sur_trois() {
        let seed: [u8; 32] = random().unwrap();
        let p = split_seed(&seed).unwrap();
        for (a, b) in [(0, 1), (0, 2), (1, 2), (2, 0)] {
            assert_eq!(*join_shares(&p[a], &p[b]).unwrap(), seed);
        }
        assert!(join_shares(&p[0], &p[0]).is_err());
        // Insensible aux tirets, espaces et minuscules.
        let messy = p[1].to_lowercase().replace('-', " ");
        assert_eq!(*join_shares(&p[0], &messy).unwrap(), seed);
        // Faute de frappe détectée.
        let mut typo = p[2].clone();
        let pos = typo.len() - 3;
        let c = if &typo[pos..pos + 1] == "2" { "3" } else { "2" };
        typo.replace_range(pos..pos + 1, c);
        assert!(join_shares(&p[0], &typo).is_err());
        // Morceaux de deux portefeuilles différents : refusés.
        let other = split_seed(&random().unwrap()).unwrap();
        assert!(join_shares(&p[0], &other[1]).is_err());
        assert_eq!(share_number(&p[2]), Some(3));
    }

    #[test]
    fn decoupage_stable_et_morceaux_differents_de_la_graine() {
        let seed = [7u8; 32];
        let a = split_seed(&seed).unwrap();
        assert_eq!(a, split_seed(&seed).unwrap());
        assert_ne!(a[0], a[1]);
        // Un morceau ne contient pas la graine telle quelle.
        let (_, _, y) = parse_share(&a[0]).unwrap();
        assert_ne!(*y, seed);
    }

    #[test]
    fn regles_des_mots_de_passe() {
        assert!(check_password("court", 12, "x").is_err());
        assert!(check_password("toutenminuscules", 12, "x").is_err());
        assert!(check_password("Soleil-Plage-2026", 12, "x").is_ok());
        assert!(check_password("une phrase assez longue pour passer", 12, "x").is_ok());
        assert!(check_password("MonNumFranc-2026!", 12, "x").is_err());
        assert!(check_password("Aa1-Aa1-Aa1-Aa1-", 16, "x").is_err()); // répétitions
        assert!(check_password("Girafe#Tambour-Nuage7", 16, "x").is_ok());
        assert_eq!(vault_params(STRONG), VAULT_STRONG);
        assert_eq!(vault_params(TEST), TEST);
    }

    #[test]
    fn empreinte_stable_et_mots_uniques() {
        let mut seen = std::collections::HashSet::new();
        for w in WORDS {
            assert!(seen.insert(w), "mot en double : {w}");
        }
        let (w, c) = fingerprint(&[1; 32]);
        assert_eq!(fingerprint(&[1; 32]), (w.clone(), c));
        assert_ne!(fingerprint(&[2; 32]).0, w);
        assert_eq!(w.split(' ').count(), 4);
    }
}
