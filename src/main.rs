//! Programme NumFranc : un double-clic lance le nœud, le minage et le portefeuille.

use numfranc::config::*;
use numfranc::emission::total_before;
use numfranc::encoding::hex;
use numfranc::node::{Node, Options};
use numfranc::vault;
use numfranc::wallet::{
    address_to_string, file_status, format_amount, parse_amount, parse_lock_duration, HistoryKind, PaymentOptions, Wallet,
    WalletFile,
};
use zeroize::Zeroizing;

mod cli_plus;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("NUMFRANC_DATA") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    if cfg!(target_os = "windows") {
        let base = std::env::var("APPDATA").unwrap_or(home);
        PathBuf::from(base).join("NumFranc")
    } else if cfg!(target_os = "macos") {
        PathBuf::from(home).join("Library/Application Support/NumFranc")
    } else {
        PathBuf::from(home).join(".numfranc")
    }
}

const HELP: &str = "\
Options de lancement :
  --pair HÔTE:PORT    se connecter à ce nœud (répétable)
  --port N            port réseau (défaut 6910)
  --coeurs N          nombre de cœurs pour le minage (défaut : la moitié)
  --sans-minage       ne pas miner
  --dossier CHEMIN    dossier des données
  --console           mode texte (sans fenêtre)
  --serveur           nœud permanent : sans portefeuille, sans fenêtre, sans minage
  --reduit            démarrer la fenêtre réduite (utilisé par le démarrage automatique)
  --menu              ajouter NumFranc au menu des applications, puis quitter";

const COMMANDS: &str = "\
Commandes :
  statut                      état du nœud
  solde                       votre solde
  adresse                     votre adresse permanente pour recevoir des NFR
  adresse neuve               une adresse à usage unique (plus de discrétion)
  envoyer DEST MONTANT        envoyer des NFR ; DEST = adresse NFR1-... ou nom du carnet
                              (le code de dépense est demandé pour signer)
      options : verrou DURÉE      fonds bloqués pour le destinataire (30min, 12h, 3j, 2sem, 1mois, 1an)
                message TEXTE     message public joint au paiement (140 octets max, à la fin)
      ex. : envoyer NFR1-... 5 verrou 30j message Bon anniversaire !
  historique                  paiements reçus et envoyés, avec leurs messages
  pairs                       nœuds connectés
  connecter HÔTE:PORT         se connecter à un nœud
  minage on | minage off      démarrer / arrêter le minage
  coeurs N                    nombre de cœurs utilisés pour miner
  carnet                      afficher le carnet d'adresses
  carnet ajouter NOM ADRESSE  ajouter un contact (ex. : carnet ajouter Maman NFR1-...)
  carnet retirer NOM          retirer un contact
  secours                     afficher les 3 morceaux du code de secours (code de dépense)
  motdepasse                  changer le mot de passe d'ouverture et le code de dépense
  quitter                     arrêter NumFranc";

fn parse_args() -> Result<Options, String> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    let mut o = Options {
        data_dir: default_data_dir(),
        port: P2P_PORT,
        peers: Vec::new(),
        threads: (cores / 2).max(1),
        mine: true,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or(format!("valeur manquante après {a}"));
        match a.as_str() {
            "--pair" | "--peer" => o.peers.push(val()?),
            "--port" => o.port = val()?.parse().map_err(|_| "port invalide")?,
            "--coeurs" | "--threads" => o.threads = val()?.parse().map_err(|_| "nombre de cœurs invalide")?,
            "--sans-minage" | "--no-mine" => o.mine = false,
            "--dossier" | "--datadir" => o.data_dir = PathBuf::from(val()?),
            "--console" | "--serveur" | "--server" | "--menu" | "--reduit" => {}
            // Ancien macOS : numéro de processus ajouté par le Finder au lancement d'une app.
            l if l.starts_with("-psn_") => {}
            // Lien de paiement cliqué (nfr:…) : transmis à la fenêtre, voir numfranc::install::hand_over_link.
            l if l.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("nfr:")) => {
                // Le lien est toujours le dernier argument : rien ne doit pouvoir s'y ajouter
                // (un lien piégé contenant des guillemets ne peut pas glisser d'options).
                if args.next().is_some() {
                    return Err("rien n'est accepté après un lien nfr:".into());
                }
            }
            "--aide" | "--help" | "-h" => {
                println!("{HELP}");
                std::process::exit(0);
            }
            _ => return Err(format!("option inconnue : {a}\n{HELP}")),
        }
    }
    Ok(o)
}

/// Saisie masquée (rien ne s'affiche). Sans terminal, lit simplement une ligne.
fn ask_secret(question: &str) -> Zeroizing<String> {
    match rpassword::prompt_password(question) {
        Ok(s) => Zeroizing::new(s),
        Err(_) => {
            print!("{question}");
            let _ = std::io::stdout().flush();
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
            Zeroizing::new(s.trim_end_matches(['\r', '\n']).to_string())
        }
    }
}

/// Demande les deux mots de passe d'un nouveau portefeuille, jusqu'à ce qu'ils soient valables.
fn ask_new_passwords() -> (Zeroizing<String>, Zeroizing<String>) {
    println!();
    println!("Choisissez DEUX secrets différents :");
    println!(" 1. le MOT DE PASSE D'OUVERTURE, demandé à chaque démarrage (voir le solde, miner, recevoir) :");
    println!("    au moins {} caractères, avec 3 sortes de caractères (minuscules, majuscules, chiffres, symboles) ;", vault::MIN_OPEN_PASSWORD);
    println!(" 2. le CODE DE DÉPENSE, demandé à chaque envoi : il protège la clé secrète ({} caractères minimum ;", vault::MIN_SPEND_CODE);
    println!("    le plus sûr : 4 ou 5 mots au hasard avec un chiffre et un symbole, ex. Girafe#Tambour-Nuage7).");
    println!("Rien ne s'affiche quand vous tapez : c'est normal.");
    loop {
        let o1 = ask_secret("Mot de passe d'ouverture : ");
        if let Err(e) = vault::check_password(&o1, vault::MIN_OPEN_PASSWORD, "Mot de passe d'ouverture") {
            println!("  {e}");
            continue;
        }
        if *ask_secret("Retapez-le : ") != *o1 {
            println!("  Les deux saisies sont différentes.");
            continue;
        }
        let s1 = ask_secret("Code de dépense : ");
        if let Err(e) = vault::check_password(&s1, vault::MIN_SPEND_CODE, "Code de dépense") {
            println!("  {e}");
            continue;
        }
        if *s1 == *o1 {
            println!("  Le code de dépense doit être différent du mot de passe d'ouverture.");
            continue;
        }
        if *ask_secret("Retapez-le : ") != *s1 {
            println!("  Les deux saisies sont différentes.");
            continue;
        }
        return (o1, s1);
    }
}

fn show_shares(shares: &[String; 3]) {
    println!();
    println!("=== VOTRE CODE DE SECOURS, EN 3 MORCEAUX ===");
    println!("Recopiez chaque morceau sur un papier DIFFÉRENT, rangé dans un endroit différent.");
    println!("2 morceaux sur 3 suffisent pour tout récupérer, même si vous oubliez vos mots de passe.");
    println!("Un seul morceau ne sert à rien à un voleur. Ne les photographiez pas, ne les envoyez à personne.");
    for (i, s) in shares.iter().enumerate() {
        println!();
        println!("  Morceau {} : {s}", i + 1);
    }
    println!();
    println!("============================================");
    while ask("Tapez « ok » quand les 3 morceaux sont recopiés : ") != "ok" {}
    // Efface l'écran pour ne pas laisser les morceaux affichés.
    print!("\x1B[2J\x1B[H");
    let _ = std::io::stdout().flush();
}

/// Ouvre (ou crée, restaure, protège) le portefeuille en mode console.
fn open_wallet_console(opts: &Options) -> Result<Wallet, String> {
    std::fs::create_dir_all(&opts.data_dir).map_err(|e| format!("dossier de données : {e}"))?;
    let path = opts.data_dir.join("wallet.dat");
    match file_status(&path) {
        WalletFile::Encrypted => {
            for attempt in 1..=10u32 {
                let pw = ask_secret("Mot de passe d'ouverture : ");
                match Wallet::unlock(&path, &pw) {
                    Ok(w) => return Ok(w),
                    Err(e) => {
                        println!("  {e}");
                        if attempt >= 3 {
                            let wait = (1u64 << attempt.min(6)).min(60);
                            println!("  Attendez {wait} s avant le prochain essai.");
                            std::thread::sleep(std::time::Duration::from_secs(wait));
                        }
                    }
                }
            }
            Err("trop d'essais. Mot de passe oublié ? Relancez avec --console puis la commande « restaurer »… ou utilisez la fenêtre (« Mot de passe oublié »)".into())
        }
        WalletFile::Legacy => {
            println!("Votre portefeuille vient d'une ancienne version et n'est PAS chiffré.");
            println!("Il va être chiffré deux fois (AES-256-GCM + XChaCha20-Poly1305).");
            let (o, s) = ask_new_passwords();
            println!("Chiffrement (quelques secondes)...");
            let (w, shares) = Wallet::load_legacy(&path)?.protect(&path, &o, &s, vault::STRONG)?;
            show_shares(&shares);
            Ok(w)
        }
        WalletFile::Missing => {
            println!("Aucun portefeuille sur cet ordinateur.");
            let choice = ask("1 = créer un nouveau portefeuille, 2 = restaurer avec mon code de secours : ");
            let w = if choice == "2" { restore_seed_console()? } else { Wallet::create_encrypted_plain()? };
            let (o, s) = ask_new_passwords();
            println!("Chiffrement (quelques secondes)...");
            let (w, shares) = w.protect(&path, &o, &s, vault::STRONG)?;
            show_shares(&shares);
            Ok(w)
        }
        WalletFile::Unknown => Err(format!("{} n'est pas un portefeuille NumFranc", path.display())),
    }
}

/// Demande 2 morceaux (ou l'ancien code complet) et renvoie le portefeuille en clair, à protéger.
fn restore_seed_console() -> Result<Wallet, String> {
    println!("Tapez 2 des 3 morceaux (NFRS-...), ou l'ancien code complet de 64 caractères.");
    let a = ask_secret("Premier morceau (ou code complet) : ");
    let seed = if a.trim().len() == 64 && !a.trim().to_uppercase().starts_with("NFRS") {
        Wallet::parse_full_code(&a)?
    } else {
        let b = ask_secret("Deuxième morceau : ");
        vault::join_shares(&a, &b)?
    };
    Ok(Wallet::from_seed(*seed))
}

fn ask(question: &str) -> String {
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_lowercase()
}

fn status(node: &Arc<Node>) {
    let c = node.chain.lock().unwrap();
    let mp = node.mempool.lock().unwrap();
    let bal = node.wallet.lock().unwrap().balance(&c, &mp);
    let h = c.height();
    println!("Bloc actuel      : #{h}  ({}…)", &hex(&c.tip())[..16]);
    println!("NFR émis         : {} sur 69 100 000", format_amount(total_before(h + 1)));
    println!("En attente       : {} transaction(s)", mp.len());
    println!("Pairs connectés  : {}", node.peer_list().len());
    let mining = node.mining.load(Ordering::SeqCst);
    let rate = node.hashrate.load(Ordering::Relaxed);
    println!(
        "Minage           : {}",
        if !mining {
            "arrêté".into()
        } else if !node.ready_to_mine() {
            "en attente de synchronisation avec les autres nœuds".into()
        } else {
            format!("actif, {} cœur(s), {rate} essais/s", node.threads.load(Ordering::SeqCst))
        }
    );
    println!("Solde disponible : {}", format_amount(bal.available));
    println!("En maturation    : {}", format_amount(bal.immature));
}

/// Date UTC lisible (JJ/MM/AAAA HH:MM) à partir d'un horodatage Unix.
fn format_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let rem = ts % 86_400;
    // Conversion jours -> date civile (algorithme de Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{d:02}/{m:02}/{y} {:02}:{:02} UTC", rem / 3_600, rem % 3_600 / 60)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Description lisible d'un verrou : date (verrou par date) ou numéro de bloc.
fn describe_lock(lock: u32) -> String {
    if lock >= LOCK_TIME_THRESHOLD {
        format_utc(lock as u64)
    } else {
        format!("bloc #{lock}")
    }
}

/// « ADRESSE MONTANT [verrou DURÉE] [message TEXTE] » (le message va jusqu'à la fin de la ligne).
fn parse_send(rest: &str) -> Result<(String, String, PaymentOptions), String> {
    let usage = "usage : envoyer ADRESSE MONTANT [verrou DURÉE] [message TEXTE]";
    let rest = rest.trim();
    let (head, memo) = match rest.find(" message ") {
        Some(i) => (&rest[..i], rest[i + 9..].trim().to_string()),
        None if rest.ends_with(" message") => return Err("le message est vide".into()),
        None => (rest, String::new()),
    };
    let t: Vec<&str> = head.split_whitespace().collect();
    let (addr, amount, lock) = match t.as_slice() {
        [a, m] => (*a, *m, 0),
        [a, m, "verrou", d] => (*a, *m, parse_lock_duration(d)?),
        _ => return Err(usage.into()),
    };
    Ok((addr.to_string(), amount.to_string(), PaymentOptions { memo, lock_secs: lock, now: now_secs() }))
}

fn send(node: &Arc<Node>, rest: &str) -> Result<(), String> {
    let (dest, amount, opts) = parse_send(rest)?;
    let amount = parse_amount(&amount)?;
    let (to, name) = {
        let c = node.chain.lock().unwrap();
        let w = node.wallet.lock().unwrap();
        let to = w.resolve_recipient_with(&dest, &c)?;
        (to, w.contact_name(&to).map(str::to_string))
    };
    let (words, color) = vault::fingerprint(&to);
    println!("Envoi de {} vers {}", format_amount(amount), address_to_string(&to));
    println!("Empreinte : {words} ({})", vault::COLORS[color].0);
    match name {
        Some(n) => println!("Contact : {n} (dans votre carnet)"),
        None => {
            println!("ATTENTION : adresse absente de votre carnet. Vérifiez l'empreinte avec le destinataire");
            println!("(par téléphone par exemple) : un virus peut remplacer une adresse copiée.");
        }
    }
    if opts.lock_secs > 0 {
        let base = node.chain.lock().unwrap().next_mtp().max(opts.now);
        println!("Verrou : dépensable à partir du {} (environ 1 h de marge). Personne ne peut débloquer avant.", format_utc(base + opts.lock_secs));
    }
    if !opts.memo.is_empty() {
        println!("Message : « {} »  (PUBLIC et gravé à vie dans la chaîne)", opts.memo);
    }
    let code = ask_secret("Code de dépense pour signer (vide = annuler) : ");
    if code.is_empty() {
        return Err("envoi annulé".into());
    }
    println!("Ouverture du coffre (quelques secondes) et signature...");
    let fee = numfranc::gui::pay(node, to, amount, &opts, &code)?;
    println!("Transaction envoyée (frais : {}). Attendez {SAFE_CONFIRMATIONS} blocs pour qu'elle soit sûre.", format_amount(fee));
    Ok(())
}

fn history(node: &Arc<Node>) {
    let c = node.chain.lock().unwrap();
    let items = node.wallet.lock().unwrap().history(&c);
    if items.is_empty() {
        println!("Aucun paiement pour l'instant (les récompenses de minage ne sont pas listées).");
    }
    for it in items {
        let what = match it.kind {
            HistoryKind::Received => "Reçu    ",
            HistoryKind::Sent => "Envoyé  ",
            HistoryKind::Vault => "Coffre  ",
        };
        let mut line = format!("bloc #{:<7} {what} {}", it.height, format_amount(it.amount));
        if !numfranc::tx::is_unlocked(it.lock_until, c.height() + 1, c.next_mtp()) {
            line += &format!("  [verrouillé jusqu'au {}]", describe_lock(it.lock_until));
        }
        println!("{line}");
        if !it.memo.is_empty() {
            println!("                      message : « {} »", it.memo);
        }
    }
}

fn console(node: Arc<Node>) {
    println!("Tapez « aide » pour la liste des commandes.");
    loop {
        // Lecture ligne par ligne sans garder le clavier verrouillé (la confirmation en a besoin).
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let res: Result<(), String> = match parts.as_slice() {
            [] => Ok(()),
            ["aide"] | ["help"] => {
                println!("{COMMANDS}");
                println!("{}", cli_plus::COMMANDS_PLUS);
                Ok(())
            }
            ["statut"] => {
                status(&node);
                Ok(())
            }
            ["solde"] => {
                let c = node.chain.lock().unwrap();
                let mp = node.mempool.lock().unwrap();
                let b = node.wallet.lock().unwrap().balance(&c, &mp);
                println!("Disponible     : {}", format_amount(b.available));
                println!("En maturation  : {} (récompenses de minage, {COINBASE_MATURITY} blocs d'attente)", format_amount(b.immature));
                println!("En cours d'envoi : {}", format_amount(b.pending));
                if b.locked > 0 {
                    println!("Verrouillé     : {} (se débloque à une date fixée, voir « historique »)", format_amount(b.locked));
                }
                Ok(())
            }
            ["adresse"] => node.wallet.lock().unwrap().main_address().map(|a| {
                println!("Votre adresse permanente (la même pour toujours, à donner à tout le monde) :");
                println!("{}", address_to_string(&a));
            }),
            ["adresse", "neuve"] => node.wallet.lock().unwrap().new_address().map(|a| {
                println!("Adresse à usage unique (à donner à une seule personne, pour plus de discrétion) :");
                println!("{}", address_to_string(&a));
            }),
            ["historique"] => {
                history(&node);
                Ok(())
            }
            ["envoyer", ..] => send(&node, line.trim().strip_prefix("envoyer").unwrap_or("")),
            ["pairs"] => {
                let list = node.peer_list();
                if list.is_empty() {
                    println!("Aucun pair pour l'instant : la recherche automatique continue (réseau local et annuaire mondial).");
                }
                for (a, out, h) in list {
                    println!("{a}  {}  (bloc #{h})", if out { "sortant" } else { "entrant" });
                }
                Ok(())
            }
            ["connecter", target] => {
                let n = node.clone();
                let t = target.to_string();
                std::thread::spawn(move || n.connect_to(t));
                println!("Connexion en cours...");
                Ok(())
            }
            ["minage", "on"] => {
                node.mining.store(true, Ordering::SeqCst);
                println!("Minage démarré.");
                Ok(())
            }
            ["minage", "off"] => {
                node.mining.store(false, Ordering::SeqCst);
                println!("Minage arrêté.");
                Ok(())
            }
            ["coeurs", n] => match n.parse::<usize>() {
                Ok(n) if n >= 1 => {
                    node.threads.store(n, Ordering::SeqCst);
                    println!("Minage sur {n} cœur(s).");
                    Ok(())
                }
                _ => Err("nombre de cœurs invalide".into()),
            },
            ["carnet"] => {
                let w = node.wallet.lock().unwrap();
                if w.contacts().is_empty() {
                    println!("Carnet vide. Ajout : carnet ajouter NOM ADRESSE");
                }
                for c in w.contacts() {
                    let (words, color) = vault::fingerprint(&c.address);
                    println!("{:<16} {}  [{words} — {}]", c.name, address_to_string(&c.address), vault::COLORS[color].0);
                }
                Ok(())
            }
            ["carnet", "ajouter", name, addr @ ..] if !addr.is_empty() => (|| {
                let a = numfranc::wallet::parse_address(&addr.join(""))?;
                let (words, color) = vault::fingerprint(&a);
                println!("Empreinte : {words} ({}) — vérifiez-la avec la personne.", vault::COLORS[color].0);
                node.wallet.lock().unwrap().add_contact(name, a).map(|_| println!("« {name} » ajouté au carnet."))
            })(),
            ["carnet", "retirer", name] => node.wallet.lock().unwrap().remove_contact(name).map(|_| println!("« {name} » retiré.")),
            ["secours"] => (|| {
                let code = ask_secret("Code de dépense : ");
                let shares = node.recovery_shares(&code)?;
                for (i, s) in shares.iter().enumerate() {
                    println!("  Morceau {} : {s}", i + 1);
                }
                println!("2 morceaux sur 3 suffisent. Ne les partagez avec personne.");
                Ok(())
            })(),
            ["motdepasse"] => (|| {
                let old = ask_secret("Code de dépense ACTUEL : ");
                let (o, s) = ask_new_passwords();
                println!("Rechiffrement...");
                node.change_passwords(&old, &o, &s).map(|_| println!("Mots de passe changés."))
            })(),
            ["quitter"] | ["exit"] | ["quit"] => {
                println!("Au revoir.");
                std::process::exit(0);
            }
            other => cli_plus::run(&node, other).unwrap_or_else(|| Err("commande inconnue, tapez « aide »".into())),
        };
        if let Err(e) = res {
            println!("Erreur : {e}");
        }
    }
    // Pas de clavier (lancement en service) : le nœud continue de tourner.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn main() {
    println!("NumFranc (NFR) v{} — monnaie post-quantique (ML-DSA-87, SHA3-512, minage Argon2d)", env!("CARGO_PKG_VERSION"));
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let mut opts = opts;
    // macOS : lancé depuis l'app NumFranc.app (Launchpad, Spotlight, lien nfr:), sans --dossier.
    let explicit = std::env::args().any(|a| a == "--dossier" || a == "--datadir");
    if let Some(data) = numfranc::install::mac_bundle_launch()
        && !explicit
    {
        opts.data_dir = data;
    }
    // Fichier noeuds.txt (à côté du lanceur, ou dans le dossier des données) : un nœud par ligne, ex. 192.168.1.35:6910
    for file in [PathBuf::from("noeuds.txt"), opts.data_dir.join("noeuds.txt")] {
        if let Ok(list) = std::fs::read_to_string(file) {
            for l in list.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                if !opts.peers.iter().any(|p| p == l) {
                    opts.peers.push(l.to_string());
                }
            }
        }
    }
    println!("Données : {}", opts.data_dir.display());
    let has = |flag: &str| std::env::args().any(|a| a == flag);
    let settings = numfranc::settings::Settings::load(&opts.data_dir);
    numfranc::i18n::set_english(settings.english);

    if has("--menu") {
        match numfranc::install::add_to_menu(&opts.data_dir) {
            Ok(m) => println!("{m}"),
            Err(e) => eprintln!("Erreur : {e}"),
        }
        return;
    }
    if has("--serveur") || has("--server") {
        run_server(opts);
        return;
    }

    // Lien de paiement cliqué : on le dépose pour la fenêtre. Si NumFranc est déjà ouvert,
    // c'est la fenêtre déjà ouverte qui le prendra, et ce second lancement s'arrête ici.
    if let Some(link) = std::env::args().skip(1).find(|a| a.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("nfr:"))) {
        match numfranc::install::hand_over_link(&opts.data_dir, &link) {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => eprintln!("Lien de paiement ignoré : {e}"),
        }
    }

    // Fenêtre d'application par défaut ; mode texte avec --console (ou si l'affichage est impossible).
    let console_mode = has("--console");
    if !console_mode {
        numfranc::events::ECHO.store(true, Ordering::SeqCst);
        match numfranc::gui::run(opts.clone()) {
            Ok(()) => std::process::exit(0),
            Err(e) => println!("Fenêtre impossible à ouvrir ({e}) : passage en mode texte."),
        }
    }
    let wallet = match open_wallet_console(&opts) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Erreur : {e}");
            let _ = ask("Appuyez sur Entrée pour fermer.");
            std::process::exit(1);
        }
    };
    let node = match Node::start(opts, wallet) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Erreur au démarrage : {e}");
            let _ = ask("Appuyez sur Entrée pour fermer.");
            std::process::exit(1);
        }
    };
    let main = node.wallet.lock().unwrap().main_address().unwrap_or([0; 32]);
    println!("Réseau : port {} | minage : {}", node.opts.port, if node.opts.mine { "actif" } else { "arrêté" });
    println!("Votre adresse pour recevoir des NFR (permanente, à donner à tout le monde) :");
    println!("  {}", address_to_string(&main));
    println!("Les récompenses de minage arrivent dans votre portefeuille.");
    println!("Recherche automatique des autres nœuds NumFranc sur le réseau local...");
    if node.opts.mine {
        println!("Le minage démarre dans {STARTUP_SYNC_SECS} s, une fois la chaîne synchronisée.");
    }
    console(node);
}

/// Nœud permanent (serveur) : relaie les blocs et transactions, aide les nouveaux à trouver
/// le réseau. Aucun portefeuille enregistré, aucune fenêtre, aucun minage.
fn run_server(mut opts: Options) {
    opts.mine = false;
    println!("Mode serveur : nœud permanent sans portefeuille ni minage.");
    // Portefeuille jetable en mémoire (jamais écrit sur le disque, jamais utilisé).
    let seed = match numfranc::vault::random::<32>() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Erreur : {e}");
            std::process::exit(1);
        }
    };
    let node = match Node::start(opts, Wallet::from_seed(seed)) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Erreur au démarrage : {e}");
            std::process::exit(1);
        }
    };
    println!("Réseau : port {}. Le nœud tourne ; Ctrl+C pour l'arrêter.", node.opts.port);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(600));
        let (h, n) = (node.chain.lock().unwrap().height(), node.peer_list().len());
        let blocked = node.blocked_unknown.load(Ordering::Relaxed);
        println!("[serveur] bloc #{h} | {n} pair(s) | {blocked} connexion(s) inconnue(s) bloquée(s)");
    }
}
