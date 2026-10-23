//! Fenêtre d'application NumFranc (egui, pur Rust : rien à installer en plus).
//!
//! Déroulé : ouverture (ou création / restauration) du portefeuille, puis le nœud démarre
//! et la fenêtre affiche Accueil, Recevoir, Envoyer, Historique, Carnet, Explorateur,
//! Réseau, Sécurité et Réglages. Langue : français ou anglais. Thème clair ou sombre.
//! Les opérations lentes (Argon2 : 1 à 5 s) tournent dans un fil à part pour ne pas figer la fenêtre.

use crate::config::*;
use crate::emission::total_before;
use crate::encoding::hex;
use crate::events;
use crate::i18n::t;
use crate::node::{Node, Options};
use crate::settings::{Settings, ACCENTS};
use crate::tf;
use crate::tx::{address_of_pubkey, is_unlocked, Address, Transaction};
use crate::vault;
use crate::wallet::{
    address_to_string, file_status, format_amount, parse_amount, parse_lock_duration, Balance, HistoryItem, HistoryKind,
    PaymentOptions, Wallet, WalletFile,
};
use chrono::{Local, TimeZone, Timelike};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod plus;

/// Lance la fenêtre. Renvoie une erreur si l'affichage graphique est impossible
/// (pas d'écran, connexion à distance…) : le programme passe alors en mode console.
pub fn run(opts: Options) -> Result<(), String> {
    let settings = Settings::load(&opts.data_dir);
    crate::i18n::set_lang(settings.lang);
    #[cfg(target_os = "macos")]
    crate::mac_liens::installer(opts.data_dir.clone());
    // Premier lancement : rangement dans le menu des applications + liens nfr:, sans rien demander.
    {
        let dir = opts.data_dir.clone();
        std::thread::spawn(move || crate::install::premier_lancement(&dir));
    }
    let icon = egui::IconData { rgba: crate::install::ICON_RGBA_64.to_vec(), width: 64, height: 64 };
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NumFranc")
            .with_icon(Arc::new(icon))
            .with_app_id("numfranc")
            .with_inner_size([1060.0, 720.0])
            .with_min_inner_size([900.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "NumFranc",
        native,
        Box::new(move |cc| {
            // Windows : la fenêtre s'est ouverte, on enlève la fenêtre noire (console) qui était derrière.
            // Si la fenêtre n'avait pas pu s'ouvrir, la console serait restée pour le mode texte.
            #[cfg(windows)]
            {
                unsafe extern "system" {
                    fn FreeConsole() -> i32;
                }
                unsafe { FreeConsole() };
            }
            apply_style(&cc.egui_ctx, &settings);
            if std::env::args().any(|a| a == "--reduit") {
                cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
            Ok(Box::new(App::new(opts, settings)))
        }),
    )
    .map_err(|e| e.to_string())
}

/// Couleurs du moment (selon le thème et la couleur principale choisis).
#[derive(Clone, Copy)]
struct Pal {
    accent: Color32,
    green: Color32,
    red: Color32,
    orange: Color32,
    grey: Color32,
    card: Color32,
    toast: Color32,
}

/// Ligne d'état de l'ouverture du port ; avec `detail`, l'explication complète (pourquoi, quoi faire).
fn port_lines(ui: &mut egui::Ui, p: &Pal, etat: &Option<crate::portmap::PortState>, detail: bool) {
    let Some(etat) = etat else { return };
    let couleur = match etat.niveau() {
        1 => p.green,
        2 => p.red,
        _ => p.grey,
    };
    ui.label(RichText::new(etat.titre()).color(couleur));
    let texte = etat.explication();
    if texte.is_empty() {
        return;
    }
    if detail {
        ui.label(RichText::new(texte).small().color(p.grey));
    } else {
        ui.label(RichText::new(t("Détails : Réglages > Connexion.", "Details: Settings > Connection.")).small().color(p.grey));
    }
}

/// Guide de réglage manuel de la box : adresse de la box, bouton pour l'ouvrir, valeurs à recopier,
/// et la case « j'ai ouvert le port moi-même ». Renvoie vrai si la case a changé.
fn port_guide(ui: &mut egui::Ui, p: &Pal, etat: &crate::portmap::PortState, aide: &Option<crate::portmap::AideBox>, manuel: &mut bool) -> bool {
    use crate::portmap::PortState;
    let mut changed = false;
    if etat.guide_utile() || *manuel {
        ui.add_space(6.0);
        ui.label(RichText::new(t("Guide : ouvrir le port à la main", "Guide: open the port by hand")).strong());
        ui.label(RichText::new(PortState::etapes()).small().color(p.grey));
        if let Some(a) = aide {
            ui.horizontal_wrapped(|ui| {
                if let Some(b) = a.box_ip {
                    if ui.button(tf!("Ouvrir la page de ma box ({b})", "Open my router's page ({b})")).clicked() {
                        crate::maj::ouvrir_page_box(b);
                    }
                } else {
                    ui.label(RichText::new(t(
                        "Adresse de la box introuvable : elle est souvent écrite sous la box (par exemple 192.168.1.1).",
                        "Router address not found: it is often printed under the router (for example 192.168.1.1).",
                    ))
                    .small()
                    .color(p.grey));
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(t("Port à rediriger (TCP) :", "Port to forward (TCP):"));
                ui.monospace(a.port.to_string());
                if ui.small_button(t("Copier", "Copy")).clicked() {
                    ui.ctx().copy_text(a.port.to_string());
                }
            });
            if let Some(ip) = a.pc_ip {
                ui.horizontal_wrapped(|ui| {
                    ui.label(t("Adresse de cet ordinateur :", "This computer's address:"));
                    ui.monospace(ip.to_string());
                    if ui.small_button(t("Copier", "Copy")).clicked() {
                        ui.ctx().copy_text(ip.to_string());
                    }
                });
            }
        }
    }
    if etat.guide_utile() || *manuel || etat.niveau() == 1 {
        changed |= ui.checkbox(manuel, t("J'ai ouvert le port moi-même", "I opened the port myself")).changed();
    }
    changed
}

fn palette(s: &Settings) -> Pal {
    let (_, _, light, dark) = ACCENTS[s.accent.min(ACCENTS.len() - 1)];
    if s.dark {
        Pal {
            accent: Color32::from_rgb(dark[0], dark[1], dark[2]),
            green: Color32::from_rgb(100, 210, 140),
            red: Color32::from_rgb(255, 120, 120),
            orange: Color32::from_rgb(255, 175, 80),
            grey: Color32::from_rgb(160, 165, 178),
            card: Color32::from_rgb(34, 38, 47),
            toast: Color32::from_rgb(28, 60, 42),
        }
    } else {
        Pal {
            accent: Color32::from_rgb(light[0], light[1], light[2]),
            green: Color32::from_rgb(30, 140, 70),
            red: Color32::from_rgb(200, 40, 50),
            orange: Color32::from_rgb(200, 110, 0),
            grey: Color32::from_rgb(105, 108, 120),
            card: Color32::WHITE,
            toast: Color32::from_rgb(225, 245, 230),
        }
    }
}

fn apply_style(ctx: &egui::Context, s: &Settings) {
    let p = palette(s);
    ctx.set_theme(if s.dark { egui::Theme::Dark } else { egui::Theme::Light });
    ctx.all_styles_mut(|st| {
        use egui::{FontFamily, FontId, TextStyle};
        st.text_styles.insert(TextStyle::Heading, FontId::new(24.0, FontFamily::Proportional));
        st.text_styles.insert(TextStyle::Body, FontId::new(15.0, FontFamily::Proportional));
        st.text_styles.insert(TextStyle::Button, FontId::new(15.0, FontFamily::Proportional));
        st.text_styles.insert(TextStyle::Monospace, FontId::new(14.0, FontFamily::Monospace));
        st.text_styles.insert(TextStyle::Small, FontId::new(12.0, FontFamily::Proportional));
        st.spacing.item_spacing = Vec2::new(10.0, 8.0);
        st.spacing.button_padding = Vec2::new(12.0, 6.0);
        st.spacing.interact_size.y = 28.0;
        st.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, p.accent);
        st.visuals.selection.stroke = egui::Stroke::new(1.5, p.accent);
        st.visuals.selection.bg_fill = p.accent.gamma_multiply(0.35);
        st.visuals.hyperlink_color = p.accent;
    });
    if s.dark {
        ctx.style_mut_of(egui::Theme::Dark, |st| {
            st.visuals.panel_fill = Color32::from_rgb(22, 25, 31);
            st.visuals.extreme_bg_color = Color32::from_rgb(18, 20, 25);
            st.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(70, 76, 90));
        });
    } else {
        ctx.style_mut_of(egui::Theme::Light, |st| {
            st.visuals.panel_fill = Color32::from_rgb(238, 241, 246);
            st.visuals.extreme_bg_color = Color32::from_rgb(243, 245, 249);
            st.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(180, 186, 198));
        });
    }
}

// ---------------------------------------------------------------------------

/// Résultat d'une opération lancée dans un fil à part.
enum JobResult {
    /// Portefeuille ouvert/créé, nœud démarré ; morceaux de secours à montrer (création/migration/restauration).
    Started(Arc<Node>, Option<[String; 3]>),
    Shares([String; 3]),
    Sent(String),
    Info(String),
    /// Texte produit par une opération avancée : (nature, contenu).
    Text(String, String),
    WrongPassword(String),
    Err(String),
    /// Mise à jour installée : NumFranc se ferme, la nouvelle version se lance d'elle-même.
    Quitter,
}

/// État de la mise à jour automatique (vérifiée au démarrage puis toutes les 6 heures).
#[derive(Clone, Debug, Default)]
enum EtatMaj {
    #[default]
    Rien,
    Telechargement(String),
    /// Installeur téléchargé ET vérifié (signature de la liste + empreinte du fichier).
    Prete(String, PathBuf),
    /// Version plus récente, mais NumFranc ne peut pas s'installer tout seul ici (lancé depuis le dossier téléchargé).
    Disponible(String),
    Erreur(String),
}

/// Un tour de mise à jour automatique : vérifier, puis télécharger et vérifier l'installeur.
fn maj_tour(dir: &std::path::Path, etat: &Arc<std::sync::Mutex<EtatMaj>>) {
    // Une seule vérification à la fois (bouton « Vérifier » et vérification automatique).
    let Ok(_verrou) = crate::maj::VERROU_MAJ.try_lock() else { return };
    let Ok(info) = crate::maj::verifier_tout(dir) else { return };
    if !info.nouvelle {
        *etat.lock().unwrap() = EtatMaj::Rien;
        return;
    }
    if !crate::maj::peut_installer() {
        *etat.lock().unwrap() = EtatMaj::Disponible(info.version.clone());
        return;
    }
    if matches!(&*etat.lock().unwrap(), EtatMaj::Prete(v, f) if *v == info.version && f.exists()) {
        return;
    }
    *etat.lock().unwrap() = EtatMaj::Telechargement(info.version.clone());
    let r = match crate::maj::telecharger_installeur(dir, &info) {
        Ok(f) => EtatMaj::Prete(info.version.clone(), f),
        Err(e) => EtatMaj::Erreur(e),
    };
    *etat.lock().unwrap() = r;
}

struct Job {
    label: String,
    rx: Receiver<JobResult>,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Accueil,
    Recevoir,
    Envoyer,
    Historique,
    Carnet,
    Explorateur,
    Emission,
    Explications,
    Avance,
    Reseau,
    Securite,
    Reglages,
}

#[derive(PartialEq, Clone, Copy)]
enum Start {
    /// Pas encore de portefeuille : créer ou restaurer.
    Choice,
    Create,
    Restore,
    /// Ancien portefeuille non chiffré à protéger.
    Legacy,
    Unlock,
}

#[derive(Default)]
struct Passwords {
    open1: String,
    open2: String,
    spend1: String,
    spend2: String,
}

fn open_label() -> &'static str {
    t("Mot de passe d'ouverture", "Opening password")
}
fn spend_label() -> &'static str {
    t("Code de dépense", "Spending code")
}

impl Passwords {
    fn check(&self) -> Result<(), String> {
        vault::check_password(&self.open1, vault::MIN_OPEN_PASSWORD, open_label())?;
        if self.open1 != self.open2 {
            return Err(t("les deux mots de passe d'ouverture sont différents", "the two opening passwords differ").into());
        }
        vault::check_password(&self.spend1, vault::MIN_SPEND_CODE, spend_label())?;
        if self.spend1 != self.spend2 {
            return Err(t("les deux codes de dépense sont différents", "the two spending codes differ").into());
        }
        if self.open1 == self.spend1 {
            return Err(t(
                "le code de dépense doit être différent du mot de passe d'ouverture",
                "the spending code must differ from the opening password",
            )
            .into());
        }
        Ok(())
    }
    fn clear(&mut self) {
        use zeroize::Zeroize;
        self.open1.zeroize();
        self.open2.zeroize();
        self.spend1.zeroize();
        self.spend2.zeroize();
    }
}

#[derive(Default)]
struct SendForm {
    to: String,
    amount: String,
    memo: String,
    lock: bool,
    lock_text: String,
    code: String,
}

#[derive(Default)]
struct Snapshot {
    balance: Balance,
    height: u64,
    tip: String,
    pairs: usize,
    mining: bool,
    ready: bool,
    rate: u64,
    threads: usize,
    mtp: u64,
    blocked: u64,
}

/// Gains de minage par jour (heure locale), du plus ancien au plus récent.
#[derive(Default, Clone)]
struct MiningStats {
    days: Vec<(String, u64, u32)>, // (date, montant, nombre de blocs)
    total: u64,
    blocks: u32,
}

struct App {
    opts: Options,
    settings: Settings,
    path: PathBuf,
    start: Start,
    pw: Passwords,
    unlock_pw: String,
    unlock_failures: u32,
    unlock_wait: Option<Instant>,
    restore_a: String,
    restore_b: String,
    restore_full: String,
    error: Option<String>,
    info: Option<String>,
    job: Option<Job>,
    node: Option<Arc<Node>>,
    shares_to_show: Option<[String; 3]>,
    shares_confirmed: bool,
    tab: Tab,
    snap: Snapshot,
    snap_at: Option<Instant>,
    history: Vec<(HistoryItem, u64)>, // (paiement, date du bloc)
    history_at: Option<Instant>,
    send: SendForm,
    contact_name: String,
    contact_addr: String,
    show_qr: bool,
    shown_address: Option<Address>,
    connect_to: String,
    sec_code: String,
    sec_shares: Option<[String; 3]>,
    chg_old: String,
    chg: Passwords,
    last_event: u64,
    toasts: Vec<(Instant, String)>,
    cores: usize,
    stats_days: usize,
    stats: MiningStats,
    stats_at: Option<Instant>,
    explorer_top: Option<u64>,
    explorer_sel: Option<u64>,
    explorer_go: String,
    schedule_night: Option<bool>,
    plus: plus::PlusState,
    /// Vérification des mises à jour en cours (réponse attendue du fil de travail) et dernier résultat.
    maj_attente: Option<std::sync::mpsc::Receiver<Result<crate::maj::Resultat, String>>>,
    maj: Option<Result<crate::maj::Resultat, String>>,
    maj_auto: Arc<std::sync::Mutex<EtatMaj>>,
    maj_lancee: bool,
    /// Écran « Bienvenue » à montrer (jusqu'à ce qu'il soit fermé une fois).
    bienvenue: bool,
}

impl App {
    fn new(opts: Options, settings: Settings) -> Self {
        let path = opts.data_dir.join("wallet.dat");
        let opts_dir = opts.data_dir.clone();
        let _ = std::fs::create_dir_all(&opts.data_dir);
        let start = match file_status(&path) {
            WalletFile::Missing => Start::Choice,
            WalletFile::Encrypted => Start::Unlock,
            WalletFile::Legacy => Start::Legacy,
            WalletFile::Unknown => Start::Unlock,
        };
        Self {
            path,
            start,
            settings,
            pw: Passwords::default(),
            unlock_pw: String::new(),
            unlock_failures: 0,
            unlock_wait: None,
            restore_a: String::new(),
            restore_b: String::new(),
            restore_full: String::new(),
            error: None,
            info: None,
            job: None,
            node: None,
            shares_to_show: None,
            shares_confirmed: false,
            tab: Tab::Accueil,
            snap: Snapshot::default(),
            snap_at: None,
            history: Vec::new(),
            history_at: None,
            send: SendForm { lock_text: "1j".into(), ..Default::default() },
            contact_name: String::new(),
            contact_addr: String::new(),
            show_qr: false,
            shown_address: None,
            connect_to: String::new(),
            sec_code: String::new(),
            sec_shares: None,
            chg_old: String::new(),
            chg: Passwords::default(),
            last_event: events::last_seq(),
            toasts: Vec::new(),
            cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2),
            stats_days: 7,
            stats: MiningStats::default(),
            stats_at: None,
            explorer_top: None,
            explorer_sel: None,
            explorer_go: String::new(),
            schedule_night: None,
            plus: Default::default(),
            maj_attente: None,
            maj: None,
            maj_auto: Arc::new(std::sync::Mutex::new(EtatMaj::Rien)),
            maj_lancee: false,
            bienvenue: crate::install::bienvenue_a_montrer(&opts_dir),
            opts,
        }
    }

    fn pal(&self) -> Pal {
        palette(&self.settings)
    }

    /// Bandeau en haut de la fenêtre : mise à jour prête (un clic) ou alerte de sécurité.
    fn maj_bandeau(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let etat = self.maj_auto.lock().unwrap().clone();
        let danger = crate::maj::version_dangereuse();
        if !danger && matches!(etat, EtatMaj::Rien | EtatMaj::Telechargement(_) | EtatMaj::Erreur(_)) {
            return;
        }
        let p = self.pal();
        let mut installer = None;
        egui::Panel::top("mise-a-jour").show(ui, |ui| {
            ui.add_space(4.0);
            egui::Frame::default().fill(if danger { p.red.gamma_multiply(0.25) } else { p.accent.gamma_multiply(0.18) }).corner_radius(6.0).inner_margin(8.0).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if danger {
                        ui.label(RichText::new(t(
                            "Mise à jour de sécurité urgente : cette version a une faille connue. Les envois de NFR sont bloqués jusqu'à la mise à jour (recevoir et miner continuent).",
                            "Urgent security update: this version has a known flaw. Sending NFR is blocked until you update (receiving and mining continue).",
                        ))
                        .strong()
                        .color(p.red));
                    }
                    match &etat {
                        EtatMaj::Prete(v, f) => {
                            ui.label(tf!("NumFranc {v} est prêt : signature de l'auteur et fichier vérifiés.", "NumFranc {v} is ready: author's signature and file verified."));
                            if ui.button(RichText::new(t("Installer et relancer", "Install and restart")).strong()).clicked() {
                                installer = Some(f.clone());
                            }
                        }
                        EtatMaj::Disponible(v) => {
                            ui.label(tf!("NumFranc {v} est disponible.", "NumFranc {v} is available."));
                            if ui.button(t("Ouvrir la page de téléchargement", "Open the download page")).clicked() {
                                crate::maj::ouvrir_page();
                            }
                        }
                        EtatMaj::Telechargement(v) => {
                            ui.spinner();
                            ui.label(tf!("Téléchargement de NumFranc {v}…", "Downloading NumFranc {v}…"));
                        }
                        _ => {}
                    }
                });
            });
            ui.add_space(2.0);
        });
        if let Some(f) = installer {
            self.spawn(t("Installation de la mise à jour…", "Installing the update…"), ctx, move || match crate::maj::installer(&f) {
                Ok(()) => JobResult::Quitter,
                Err(e) => JobResult::Err(e),
            });
        }
    }

    /// Active ou coupe « Toujours allumé » : réglage enregistré, puis gardien installé ou retiré.
    fn set_permanent(&mut self, on: bool, ctx: &egui::Context) {
        self.settings.permanent = on;
        self.save_settings(ctx);
        match crate::install::set_permanent(on, &self.opts.data_dir) {
            Ok(m) => self.info = Some(m),
            Err(e) => {
                self.error = Some(tf!("« Toujours allumé » impossible à installer : {e}", "« Always on » could not be installed: {e}"));
                self.settings.permanent = false;
                self.save_settings(ctx);
            }
        }
    }

    fn save_settings(&mut self, ctx: &egui::Context) {
        self.settings.save(&self.opts.data_dir);
        crate::i18n::set_lang(self.settings.lang);
        apply_style(ctx, &self.settings);
        self.history_at = None;
        self.stats_at = None;
    }

    fn spawn(&mut self, label: &str, ctx: &egui::Context, f: impl FnOnce() -> JobResult + Send + 'static) {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = f();
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.error = None;
        self.info = None;
        self.job = Some(Job { label: label.to_string(), rx });
    }

    fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let Ok(r) = job.rx.try_recv() else { return };
        self.job = None;
        match r {
            JobResult::Started(node, shares) => {
                node.set_manual_port(self.settings.manual_port);
                node.mining.store(self.settings.mine && node.opts.mine, Ordering::SeqCst);
                // Adresse de réception (publique) pour le nœud d'arrière-plan.
                let adresse = node.wallet.lock().unwrap().main_address().map(|a| crate::wallet::address_to_string(&a)).unwrap_or_default();
                if !adresse.is_empty() && self.settings.reward_address != adresse {
                    // Adresse de minage d'arrière-plan différente de la tienne : on prévient (un programme
                    // malveillant aurait pu la changer pour détourner tes récompenses), puis on la remet.
                    if !self.settings.reward_address.is_empty() {
                        events::log(t(
                            "[!] L'adresse de minage en arrière-plan n'était pas la tienne : elle a été remise. Si tu ne l'as pas changée toi-même, fais vérifier cet ordinateur.",
                            "[!] The background mining address was not yours: it has been reset. If you did not change it yourself, have this computer checked.",
                        ));
                    }
                    self.settings.reward_address = adresse;
                    self.settings.save(&self.opts.data_dir);
                }
                self.node = Some(node);
                self.shares_to_show = shares;
                self.shares_confirmed = false;
                self.pw.clear();
                self.unlock_pw.clear();
                self.restore_a.clear();
                self.restore_b.clear();
                self.restore_full.clear();
            }
            JobResult::Shares(s) => {
                self.sec_shares = Some(s);
                self.sec_code.clear();
            }
            JobResult::Sent(msg) => {
                self.info = Some(msg);
                let lock_text = self.send.lock_text.clone();
                self.send = SendForm { lock_text, ..Default::default() };
                self.history_at = None;
                self.snap_at = None;
            }
            JobResult::Text(kind, text) => self.plus_output(kind, text),
            JobResult::Info(msg) => {
                self.info = Some(msg);
                self.chg_old.clear();
                self.chg.clear();
            }
            JobResult::WrongPassword(e) => {
                self.unlock_failures += 1;
                if self.unlock_failures >= 3 {
                    // Délai croissant après plusieurs erreurs : 8 s, 16 s, 32 s… (60 s au plus).
                    let secs = (1u64 << self.unlock_failures.min(6)).min(60);
                    self.unlock_wait = Some(Instant::now() + Duration::from_secs(secs));
                }
                self.error = Some(e);
            }
            JobResult::Err(e) => self.error = Some(e),
            JobResult::Quitter => std::process::exit(0),
        }
    }

    fn refresh(&mut self) {
        let Some(node) = self.node.clone() else { return };
        if self.snap_at.is_some_and(|t| t.elapsed() < Duration::from_millis(900)) {
            return;
        }
        self.snap_at = Some(Instant::now());
        {
            let c = node.chain.lock().unwrap();
            let mp = node.mempool.lock().unwrap();
            let balance = node.wallet.lock().unwrap().balance(&c, &mp);
            self.snap = Snapshot {
                balance,
                height: c.height(),
                tip: hex(&c.tip())[..16].to_string(),
                pairs: 0,
                mining: node.mining.load(Ordering::SeqCst),
                ready: true,
                rate: node.hashrate.load(Ordering::Relaxed),
                threads: node.threads.load(Ordering::SeqCst),
                mtp: c.next_mtp(),
                blocked: node.blocked_unknown.load(Ordering::Relaxed),
            };
        }
        self.snap.pairs = node.peer_list().len();
        self.snap.ready = node.ready_to_mine();
        self.apply_schedule(&node);
        // Notifications : paiements reçus et blocs trouvés.
        for (n, msg) in events::since(self.last_event) {
            self.last_event = n;
            if msg.starts_with("[€]") || msg.starts_with("[+]") {
                self.toasts.push((Instant::now(), msg.trim_start_matches(['[', '€', '+', ']', ' ']).to_string()));
            }
        }
        self.toasts.retain(|(t, _)| t.elapsed() < Duration::from_secs(10));
        let extra = self.toasts.len().saturating_sub(3);
        self.toasts.drain(..extra);
    }

    /// Minage selon l'horaire : appliqué à chaque passage jour → nuit ou nuit → jour.
    fn apply_schedule(&mut self, node: &Arc<Node>) {
        if !self.settings.schedule {
            self.schedule_night = None;
            return;
        }
        let hour = Local::now().hour() as u8;
        let night = self.settings.is_night(hour);
        if self.schedule_night == Some(night) {
            return;
        }
        self.schedule_night = Some(night);
        let cores = self.settings.scheduled_cores(hour).unwrap_or(1);
        if cores == 0 {
            node.mining.store(false, Ordering::SeqCst);
        } else {
            node.threads.store(cores, Ordering::SeqCst);
            node.mining.store(true, Ordering::SeqCst);
        }
        events::log(&if night {
            tf!("Horaire : minage de nuit ({cores} cœur(s)).", "Schedule: night mining ({cores} core(s)).")
        } else {
            tf!("Horaire : minage de jour ({cores} cœur(s)).", "Schedule: day mining ({cores} core(s)).")
        });
        self.snap_at = None;
    }

    /// Gains de minage des `days` derniers jours (recalculés au plus une fois par minute).
    fn refresh_stats(&mut self) {
        if self.stats_at.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return;
        }
        let Some(node) = self.node.clone() else { return };
        self.stats_at = Some(Instant::now());
        let days = self.stats_days as i64;
        let today = Local::now().date_naive();
        let first = today - chrono::Duration::days(days - 1);
        let mut buckets: Vec<(chrono::NaiveDate, u64, u32)> =
            (0..days).map(|i| (first + chrono::Duration::days(i), 0, 0)).collect();
        let c = node.chain.lock().unwrap();
        let w = node.wallet.lock().unwrap();
        let mut h = c.height();
        while h > 0 {
            let Some(hash) = c.hash_at(h) else { break };
            let Some(hdr) = c.header(&hash) else { break };
            let Some(date) = Local.timestamp_opt(hdr.timestamp as i64, 0).single().map(|d| d.date_naive()) else { break };
            if date < first {
                break;
            }
            if let Some(b) = c.get_block(&hash) {
                let mine: u64 = b.txs[0].outputs.iter().filter(|o| w.is_mine(&o.address)).map(|o| o.amount).sum();
                if mine > 0 {
                    if let Some(slot) = buckets.iter_mut().find(|x| x.0 == date) {
                        slot.1 += mine;
                        slot.2 += 1;
                    }
                }
            }
            h -= 1;
        }
        let total = buckets.iter().map(|x| x.1).sum();
        let blocks = buckets.iter().map(|x| x.2).sum();
        self.stats = MiningStats { days: buckets.into_iter().map(|(d, a, n)| (d.format("%d/%m").to_string(), a, n)).collect(), total, blocks };
    }
}

impl App {
    /// Un lien de paiement nfr:… a été cliqué : il remplit le formulaire « Envoyer » (rien n'est envoyé
    /// sans vérification et sans le code de dépense) et la fenêtre passe au premier plan.
    fn take_payment_link(&mut self, ctx: &egui::Context) {
        let Some(link) = crate::install::take_link(&self.opts.data_dir) else { return };
        self.send.to = link;
        self.send.amount.clear();
        self.send.memo.clear();
        self.send.code.clear();
        self.tab = Tab::Envoyer;
        self.toasts.push((Instant::now(), t("Lien de paiement reçu : vérifie avant d'envoyer.", "Payment link received: check before sending.").to_string()));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_job();
        let ctx = ui.ctx().clone();
        if self.node.is_some() && self.shares_to_show.is_none() {
            self.take_payment_link(&ctx);
            self.refresh();
            self.main_screen(ui, &ctx);
            ctx.request_repaint_after(Duration::from_secs(1));
        } else if self.node.is_some() {
            self.shares_screen(ui);
        } else {
            self.start_screen(ui, &ctx);
            if self.job.is_some() || self.unlock_wait.is_some() {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Petites aides d'affichage
// ---------------------------------------------------------------------------

fn card<R>(ui: &mut egui::Ui, p: &Pal, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::group(ui.style())
        .fill(p.card)
        .corner_radius(8.0)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(add).inner
        })
        .inner
}

fn password_field(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).password(true).desired_width(320.0))
}

fn error_line(ui: &mut egui::Ui, p: &Pal, e: &Option<String>) {
    if let Some(e) = e {
        ui.colored_label(p.red, tf!("Erreur : {e}", "Error: {e}"));
    }
}

fn info_line(ui: &mut egui::Ui, p: &Pal, i: &Option<String>) {
    if let Some(i) = i {
        ui.colored_label(p.green, i.as_str());
    }
}

/// Empreinte visuelle d'une adresse : pastille de couleur + 4 mots.
fn fingerprint_ui(ui: &mut egui::Ui, a: &Address) {
    let (words, color) = vault::fingerprint(a);
    let (name, rgb) = vault::COLORS[color];
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 9.0, Color32::from_rgb(rgb[0], rgb[1], rgb[2]));
        ui.label(RichText::new(format!("{words}  ({name})")).strong());
    });
}

fn short_addr(a: &Address) -> String {
    let s = address_to_string(a);
    format!("{}…{}", &s[..14], &s[s.len() - 4..])
}

fn qr_ui(ui: &mut egui::Ui, text: &str) {
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else { return };
    let w = code.width();
    let colors = code.to_colors();
    let module = 5.0;
    let quiet = 4.0 * module;
    let size = w as f32 * module + 2.0 * quiet;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 0.0, Color32::WHITE);
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                let min = rect.min + Vec2::new(quiet + x as f32 * module, quiet + y as f32 * module);
                p.rect_filled(egui::Rect::from_min_size(min, Vec2::splat(module)), 0.0, Color32::BLACK);
            }
        }
    }
}

/// Date et heure locales : 17/10/2026 18:42.
fn local_time(ts: u64) -> String {
    Local
        .timestamp_opt(ts as i64, 0)
        .single()
        .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
        .unwrap_or_else(|| "?".into())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn describe_lock(lock: u32) -> String {
    if lock >= LOCK_TIME_THRESHOLD {
        local_time(lock as u64)
    } else {
        tf!("bloc #{lock}", "block #{lock}")
    }
}

/// Montant pour un tableur : virgule décimale, sans « NFR ».
fn csv_amount(units: u64) -> String {
    let sep = crate::i18n::decimal_sep();
    format!("{}{sep}{:08}", units / crate::config::MIN_UNIT, units % crate::config::MIN_UNIT)
}

/// Dossier des téléchargements (ou dossier personnel).
fn downloads_dir() -> PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    for d in ["Downloads", "Téléchargements"] {
        if home.join(d).is_dir() {
            return home.join(d);
        }
    }
    home
}

// ---------------------------------------------------------------------------
// Écrans de démarrage : ouvrir, créer, restaurer, protéger un ancien portefeuille
// ---------------------------------------------------------------------------

impl App {
    fn start_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(24.0);
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(96.0), egui::Sense::hover());
                    draw_logo(ui.painter(), r);
                    ui.label(RichText::new("NumFranc").size(40.0).strong().color(p.accent));
                    ui.label(RichText::new(t("Monnaie numérique post-quantique", "Post-quantum digital currency")).color(p.grey));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.add_space(((ui.available_width() - 500.0) / 2.0).max(0.0));
                        for l in crate::i18n::Lang::ALL {
                            if ui.selectable_label(self.settings.lang == l, l.name()).clicked() {
                                self.settings.lang = l;
                                self.save_settings(ctx);
                            }
                        }
                    });
                    ui.add_space(14.0);
                });
                ui.vertical_centered(|ui| {
                    ui.set_max_width(580.0);
                    if let Some(job) = &self.job {
                        card(ui, &p, |ui| {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(&job.label);
                            });
                        });
                        return;
                    }
                    match self.start {
                        Start::Choice => self.choice_ui(ui),
                        Start::Create => self.create_ui(ui, ctx),
                        Start::Restore => self.restore_ui(ui, ctx),
                        Start::Legacy => self.legacy_ui(ui, ctx),
                        Start::Unlock => self.unlock_ui(ui, ctx),
                    }
                });
            });
        });
    }

    fn choice_ui(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        card(ui, &p, |ui| {
            ui.heading(t("Bienvenue", "Welcome"));
            ui.label(t("Aucun portefeuille sur cet ordinateur.", "No wallet on this computer."));
            ui.add_space(8.0);
            if ui.button(RichText::new(t("Créer un nouveau portefeuille", "Create a new wallet")).strong()).clicked() {
                self.start = Start::Create;
            }
            if ui.button(t("Restaurer un portefeuille avec mon code de secours", "Restore a wallet with my recovery code")).clicked() {
                self.start = Start::Restore;
            }
        });
    }

    fn passwords_form(ui: &mut egui::Ui, p: &Pal, pw: &mut Passwords) {
        ui.label(RichText::new(t("1. Mot de passe d'ouverture", "1. Opening password")).strong());
        ui.label(
            RichText::new(t(
                "Demandé à chaque démarrage. Il permet de voir ton solde, de miner et de recevoir. Au moins 12 caractères, avec 3 sortes de caractères (minuscules, majuscules, chiffres, symboles).",
                "Asked at every start. It lets you see your balance, mine and receive. At least 12 characters, with 3 kinds of characters (lowercase, uppercase, digits, symbols).",
            ))
            .small()
            .color(p.grey),
        );
        password_field(ui, open_label(), &mut pw.open1);
        password_field(ui, t("Retape-le", "Type it again"), &mut pw.open2);
        ui.add_space(8.0);
        ui.label(RichText::new(t("2. Code de dépense (différent !)", "2. Spending code (different!)")).strong());
        ui.label(
            RichText::new(t(
                "Demandé à chaque envoi de NFR. Il protège la clé secrète : sans lui, personne ne peut dépenser, même avec ton ordinateur ouvert. Au moins 16 caractères. Le plus sûr : une phrase de 4 ou 5 mots au hasard, avec un chiffre et un symbole (ex. Girafe#Tambour-Nuage7).",
                "Asked for every NFR payment. It protects the secret key: without it nobody can spend, even with your computer unlocked. At least 16 characters. Safest: 4 or 5 random words with a digit and a symbol (e.g. Giraffe#Drum-Cloud7).",
            ))
            .small()
            .color(p.grey),
        );
        password_field(ui, spend_label(), &mut pw.spend1);
        password_field(ui, t("Retape-le", "Type it again"), &mut pw.spend2);
        match pw.check() {
            Ok(()) => {
                ui.colored_label(p.green, t("Mots de passe valables.", "Passwords accepted."));
            }
            Err(e) if !pw.open1.is_empty() => {
                ui.colored_label(p.orange, e);
            }
            Err(_) => {}
        }
    }

    fn create_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        card(ui, &p, |ui| {
            ui.heading(t("Nouveau portefeuille", "New wallet"));
            Self::passwords_form(ui, &p, &mut self.pw);
            error_line(ui, &p, &self.error);
            ui.horizontal(|ui| {
                if ui.button(t("Retour", "Back")).clicked() {
                    self.start = Start::Choice;
                }
                if ui.add_enabled(self.pw.check().is_ok(), egui::Button::new(RichText::new(t("Créer le portefeuille", "Create the wallet")).strong())).clicked() {
                    let (path, open, spend, opts) = (self.path.clone(), self.pw.open1.clone(), self.pw.spend1.clone(), self.opts.clone());
                    self.spawn(t("Création du portefeuille et chiffrement (quelques secondes)…", "Creating and encrypting the wallet (a few seconds)…"), ctx, move || {
                        let open = Zeroizing::new(open);
                        let spend = Zeroizing::new(spend);
                        match Wallet::create_encrypted(&path, &open, &spend, vault::STRONG) {
                            Ok((w, shares)) => start_node(opts, w, Some(shares)),
                            Err(e) => JobResult::Err(e),
                        }
                    });
                }
            });
        });
    }

    fn legacy_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        card(ui, &p, |ui| {
            ui.heading(t("Protège ton portefeuille", "Protect your wallet"));
            ui.label(t(
                "Ton portefeuille vient d'une ancienne version : il n'est pas encore chiffré. Choisis tes deux mots de passe : il sera chiffré deux fois (AES-256 + XChaCha20), puis tu recevras ton code de secours en 3 morceaux.",
                "Your wallet comes from an older version: it is not encrypted yet. Choose your two passwords: it will be encrypted twice (AES-256 + XChaCha20), then you will get your recovery code in 3 pieces.",
            ));
            ui.add_space(6.0);
            Self::passwords_form(ui, &p, &mut self.pw);
            error_line(ui, &p, &self.error);
            if ui.add_enabled(self.pw.check().is_ok(), egui::Button::new(RichText::new(t("Chiffrer mon portefeuille", "Encrypt my wallet")).strong())).clicked() {
                let (path, open, spend, opts) = (self.path.clone(), self.pw.open1.clone(), self.pw.spend1.clone(), self.opts.clone());
                self.spawn(t("Chiffrement du portefeuille (quelques secondes)…", "Encrypting the wallet (a few seconds)…"), ctx, move || {
                    let open = Zeroizing::new(open);
                    let spend = Zeroizing::new(spend);
                    let r = Wallet::load_legacy(&path).and_then(|w| w.protect(&path, &open, &spend, vault::STRONG));
                    match r {
                        Ok((w, shares)) => start_node(opts, w, Some(shares)),
                        Err(e) => JobResult::Err(e),
                    }
                });
            }
        });
    }

    fn restore_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        card(ui, &p, |ui| {
            ui.heading(t("Restaurer un portefeuille", "Restore a wallet"));
            ui.label(t(
                "Tape 2 des 3 morceaux de ton code de secours (NFRS-…), dans n'importe quel ordre.",
                "Type 2 of the 3 pieces of your recovery code (NFRS-…), in any order.",
            ));
            ui.label(t("Morceau A", "Piece A"));
            ui.add(egui::TextEdit::singleline(&mut self.restore_a).desired_width(f32::INFINITY));
            ui.label(t("Morceau B", "Piece B"));
            ui.add(egui::TextEdit::singleline(&mut self.restore_b).desired_width(f32::INFINITY));
            ui.label(RichText::new(t("Ou bien l'ancien code complet de 64 caractères (versions 0.1 à 0.3) :", "Or the old full 64-character code (versions 0.1 to 0.3):")).small().color(p.grey));
            ui.add(egui::TextEdit::singleline(&mut self.restore_full).password(true).desired_width(f32::INFINITY));
            ui.add_space(8.0);
            Self::passwords_form(ui, &p, &mut self.pw);
            error_line(ui, &p, &self.error);
            ui.horizontal(|ui| {
                if ui.button(t("Retour", "Back")).clicked() {
                    self.start = if self.path.exists() { Start::Unlock } else { Start::Choice };
                }
                let ready = self.pw.check().is_ok() && (!self.restore_full.trim().is_empty() || (!self.restore_a.trim().is_empty() && !self.restore_b.trim().is_empty()));
                if ui.add_enabled(ready, egui::Button::new(RichText::new(t("Restaurer", "Restore")).strong())).clicked() {
                    let (a, b, full) = (self.restore_a.clone(), self.restore_b.clone(), self.restore_full.clone());
                    let (path, open, spend, opts) = (self.path.clone(), self.pw.open1.clone(), self.pw.spend1.clone(), self.opts.clone());
                    self.spawn(t("Restauration et chiffrement (quelques secondes)…", "Restoring and encrypting (a few seconds)…"), ctx, move || {
                        let seed = if full.trim().is_empty() { vault::join_shares(&a, &b) } else { Wallet::parse_full_code(&full) };
                        let seed = match seed {
                            Ok(s) => s,
                            Err(e) => return JobResult::Err(e),
                        };
                        if path.exists() {
                            let _ = std::fs::rename(&path, path.with_file_name("wallet.ancien.dat"));
                        }
                        let open = Zeroizing::new(open);
                        let spend = Zeroizing::new(spend);
                        match Wallet::from_seed(*seed).protect(&path, &open, &spend, vault::STRONG) {
                            Ok((w, shares)) => start_node(opts, w, Some(shares)),
                            Err(e) => JobResult::Err(e),
                        }
                    });
                }
            });
        });
    }

    fn unlock_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        card(ui, &p, |ui| {
            ui.heading(t("Ouvrir mon portefeuille", "Open my wallet"));
            let waiting = self.unlock_wait.filter(|t| *t > Instant::now());
            if waiting.is_none() {
                self.unlock_wait = None;
            }
            ui.label(open_label());
            let r = ui.add(egui::TextEdit::singleline(&mut self.unlock_pw).password(true).desired_width(320.0));
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            error_line(ui, &p, &self.error);
            if let Some(w) = waiting {
                let s = (w - Instant::now()).as_secs() + 1;
                ui.colored_label(p.orange, tf!("Trop d'essais : attends {s} s.", "Too many attempts: wait {s} s."));
            }
            let can = waiting.is_none() && !self.unlock_pw.is_empty();
            if (ui.add_enabled(can, egui::Button::new(RichText::new(t("Ouvrir", "Open")).strong())).clicked() || (enter && can)) && self.job.is_none() {
                let (path, pw, opts) = (self.path.clone(), Zeroizing::new(self.unlock_pw.clone()), self.opts.clone());
                self.unlock_pw.clear();
                self.spawn(t("Vérification du mot de passe…", "Checking the password…"), ctx, move || match Wallet::unlock(&path, &pw) {
                    Ok(w) => start_node(opts, w, None),
                    Err(e) => JobResult::WrongPassword(e),
                });
            }
            ui.add_space(10.0);
            if ui.small_button(t("Mot de passe oublié ? Restaurer avec 2 morceaux du code de secours", "Forgot the password? Restore with 2 pieces of the recovery code")).clicked() {
                self.error = None;
                self.start = Start::Restore;
            }
        });
    }

    fn shares_screen(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        let shares = self.shares_to_show.clone().unwrap_or_default();
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.set_max_width(760.0);
                    ui.add_space(16.0);
                    ui.heading(RichText::new(t("Ton code de secours, en 3 morceaux", "Your recovery code, in 3 pieces")).color(p.accent));
                    ui.add_space(6.0);
                    card(ui, &p, |ui| {
                        ui.label(t(
                            "Recopie chaque morceau sur un papier DIFFÉRENT et range-les dans 3 endroits différents (chez toi, chez tes parents, dans un autre lieu sûr).",
                            "Copy each piece onto a DIFFERENT sheet of paper and keep them in 3 different places (at home, at your parents', in another safe place).",
                        ));
                        ui.label(RichText::new(t(
                            "• 2 morceaux sur 3 suffisent pour tout récupérer, même si tu oublies tes mots de passe.",
                            "• 2 pieces out of 3 are enough to recover everything, even if you forget your passwords.",
                        )).strong());
                        ui.label(t(
                            "• Un seul morceau ne sert à rien à un voleur. Perdre un morceau ne fait rien perdre.",
                            "• A single piece is useless to a thief. Losing one piece loses nothing.",
                        ));
                        ui.label(RichText::new(t(
                            "• Ne les prends jamais en photo, ne les envoie à personne, ne les colle dans aucune conversation.",
                            "• Never photograph them, never send them to anyone, never paste them into any conversation.",
                        )).color(p.red));
                    });
                    for (i, s) in shares.iter().enumerate() {
                        card(ui, &p, |ui| {
                            ui.label(RichText::new(tf!("Morceau {}", "Piece {}", i + 1)).strong());
                            ui.label(RichText::new(s).monospace().size(16.0));
                        });
                    }
                    ui.checkbox(&mut self.shares_confirmed, t("J'ai recopié les 3 morceaux sur 3 papiers différents", "I copied the 3 pieces onto 3 different sheets of paper"));
                    if ui.add_enabled(self.shares_confirmed, egui::Button::new(RichText::new(t("Continuer", "Continue")).strong())).clicked() {
                        self.shares_to_show = None;
                    }
                });
            });
        });
    }
}

/// Démarre le nœud avec le portefeuille ouvert (dans le fil de l'opération).
fn start_node(opts: Options, w: Wallet, shares: Option<[String; 3]>) -> JobResult {
    // « Toujours allumé » : la fenêtre signale qu'elle est ouverte ; le nœud d'arrière-plan lui laisse
    // alors la place (au plus 30 s d'attente), puis reprend quand la fenêtre se ferme.
    crate::permanent::fenetre_battement(&opts.data_dir);
    crate::permanent::attendre_place(&opts.data_dir, Duration::from_secs(30));
    match Node::start(opts, w) {
        Ok(n) => JobResult::Started(n, shares),
        Err(e) => JobResult::Err(tf!("démarrage du nœud impossible : {e}", "could not start the node: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Écran principal
// ---------------------------------------------------------------------------

impl App {
    fn main_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        egui::Panel::top("haut").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(26.0), egui::Sense::hover());
                draw_logo(ui.painter(), r);
                ui.label(RichText::new("NumFranc").size(21.0).strong().color(p.accent));
                ui.add_space(8.0);
                // Onglets de tous les jours, puis ceux du mode expert.
                let essentiels = [
                    (Tab::Accueil, "Accueil", "Home"),
                    (Tab::Envoyer, "Envoyer", "Send"),
                    (Tab::Recevoir, "Recevoir", "Receive"),
                    (Tab::Historique, "Historique", "History"),
                    (Tab::Carnet, "Carnet", "Contacts"),
                ];
                let plus = [(Tab::Securite, "Sécurité", "Security"), (Tab::Explications, "Explications", "Explain")];
                let experts = [
                    (Tab::Explorateur, "Explorateur", "Explorer"),
                    (Tab::Emission, "Émission", "Issuance"),
                    (Tab::Avance, "Avancé", "Advanced"),
                    (Tab::Reseau, "Réseau", "Network"),
                ];
                let mut choisi = None;
                for (tab, fr, en) in essentiels {
                    if ui.selectable_label(self.tab == tab, t(fr, en)).clicked() {
                        choisi = Some(tab);
                    }
                }
                if self.settings.expert {
                    for (tab, fr, en) in plus.into_iter().chain(experts) {
                        if ui.selectable_label(self.tab == tab, t(fr, en)).clicked() {
                            choisi = Some(tab);
                        }
                    }
                } else {
                    let dans_plus = plus.iter().any(|(tab, _, _)| *tab == self.tab);
                    let titre = RichText::new(t("Plus…", "More…"));
                    ui.menu_button(if dans_plus { titre.strong().color(p.accent) } else { titre }, |ui| {
                        for (tab, fr, en) in plus {
                            if ui.selectable_label(self.tab == tab, t(fr, en)).clicked() {
                                choisi = Some(tab);
                                ui.close();
                            }
                        }
                    });
                }
                if ui.selectable_label(self.tab == Tab::Reglages, t("Réglages", "Settings")).clicked() {
                    choisi = Some(Tab::Reglages);
                }
                if let Some(tab) = choisi {
                    self.tab = tab;
                    self.error = None;
                    self.info = None;
                }
            });
            ui.add_space(4.0);
        });
        egui::Panel::bottom("bas").show(ui, |ui| {
            ui.horizontal(|ui| {
                let s = &self.snap;
                let (dot, txt) = if s.pairs == 0 {
                    (p.orange, t("recherche d'autres nœuds…", "looking for other nodes…").to_string())
                } else {
                    (p.green, tf!("{} pair(s)", "{} peer(s)", s.pairs))
                };
                let (r, _) = ui.allocate_exact_size(Vec2::splat(12.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 5.0, dot);
                ui.label(tf!("Bloc #{}  ·  {txt}", "Block #{}  ·  {txt}", s.height));
                ui.separator();
                let m = if !s.mining {
                    t("minage arrêté", "mining stopped").to_string()
                } else if !s.ready {
                    t("minage : synchronisation…", "mining: syncing…").to_string()
                } else {
                    tf!("minage : {} essais/s", "mining: {} tries/s", s.rate)
                };
                ui.label(m);
                if let Some(last) = events::recent(1).pop() {
                    ui.separator();
                    ui.label(RichText::new(last).small().color(p.grey));
                }
            });
        });
        if self.bienvenue {
            let mut fermer = false;
            egui::Window::new(t("Quelques mots avant de commencer", "A few words before you start"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_max_width(460.0);
                    let mine = self.node.as_ref().is_none_or(|n| n.mining.load(std::sync::atomic::Ordering::Relaxed));
                    let minage = if mine {
                        ("Ton minage est déjà en route. Laisse NumFranc ouvert : une récompense devient dépensable après 100 blocs.",
                         "Mining is already running. Keep NumFranc open: a reward becomes spendable after 100 blocks.")
                    } else {
                        ("Le minage est arrêté. Pour gagner des NFR, coche « Miner avec cet ordinateur » sur l'accueil et laisse NumFranc ouvert.",
                         "Mining is off. To earn NFR, tick « Mine with this computer » on the Home screen and keep NumFranc open.")
                    };
                    for (fr, en) in [
                        minage,
                        ("NumFranc ouvre tout seul le port sur ta box et cherche les autres nœuds. L'état est dans Réglages > Connexion.",
                         "NumFranc opens the port on your router by itself and looks for other nodes. Status: Settings > Connection."),
                        ("Les liens de paiement nfr:… s'ouvrent dans NumFranc, déjà rempli. Rien ne part sans ton code de dépense.",
                         "nfr:… payment links open in NumFranc, already filled in. Nothing is sent without your spending code."),
                        ("Garde tes 3 morceaux de secours sur 3 papiers séparés : 2 sur 3 suffisent pour tout récupérer.",
                         "Keep your 3 recovery pieces on 3 separate papers: any 2 of 3 recover everything."),
                    ] {
                        ui.label(t(fr, en));
                        ui.add_space(6.0);
                    }
                    ui.add_space(4.0);
                    if ui.button(t("J'ai compris", "Got it")).clicked() {
                        fermer = true;
                    }
                });
            if fermer {
                self.bienvenue = false;
                crate::install::bienvenue_vue(&self.opts.data_dir);
            }
        }
        if !self.bienvenue && !self.settings.permanent_asked && self.node.is_some() && self.shares_to_show.is_none() {
            let mut choix = None;
            egui::Window::new(t("Garder NumFranc allumé en permanence ?", "Keep NumFranc on all the time?"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_max_width(480.0);
                    for (fr, en) in [
                        ("Recommandé : NumFranc démarre avec l'ordinateur, continue quand tu fermes la fenêtre et se relance tout seul s'il s'arrête. Le réseau reste solide et tu continues à miner.",
                         "Recommended: NumFranc starts with the computer, keeps running when you close the window and restarts by itself if it stops. The network stays strong and you keep mining."),
                        ("Fenêtre fermée, il mine vers ton adresse de réception : ton portefeuille reste fermé et chiffré, aucun mot de passe n'est gardé.",
                         "With the window closed, it mines to your receiving address: your wallet stays closed and encrypted, no password is kept."),
                        ("Tu peux changer d'avis à tout moment : Réglages > Toujours allumé. Le nombre de cœurs (jour et nuit) se règle au même endroit.",
                         "You can change your mind at any time: Settings > Always on. The number of cores (day and night) is set in the same place."),
                    ] {
                        ui.label(t(fr, en));
                        ui.add_space(6.0);
                    }
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(RichText::new(t("Oui (recommandé)", "Yes (recommended)")).strong()).fill(p.accent.gamma_multiply(0.45))).clicked() {
                            choix = Some(true);
                        }
                        if ui.button(t("Non", "No")).clicked() {
                            choix = Some(false);
                        }
                    });
                });
            if let Some(on) = choix {
                self.settings.permanent_asked = true;
                self.set_permanent(on, ctx);
            }
        }
        if !self.toasts.is_empty() {
            egui::Area::new(egui::Id::unique("notifications")).anchor(egui::Align2::RIGHT_BOTTOM, [-14.0, -44.0]).show(ctx, |ui| {
                for (_, msg) in &self.toasts {
                    egui::Frame::default()
                        .fill(p.toast)
                        .stroke(egui::Stroke::new(1.0, p.green))
                        .corner_radius(6.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.set_max_width(380.0);
                            ui.colored_label(p.green, RichText::new(msg).strong());
                        });
                }
            });
        }
        if !self.maj_lancee {
            self.maj_lancee = true;
            let (dir, etat, c) = (self.opts.data_dir.clone(), self.maj_auto.clone(), ctx.clone());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(30));
                loop {
                    maj_tour(&dir, &etat);
                    c.request_repaint();
                    std::thread::sleep(Duration::from_secs(6 * 3600));
                }
            });
        }
        self.maj_bandeau(ui, ctx);
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| match self.tab {
                Tab::Accueil => self.home_tab(ui),
                Tab::Recevoir => self.receive_tab(ui, ctx),
                Tab::Envoyer => self.send_tab(ui, ctx),
                Tab::Historique => self.history_tab(ui),
                Tab::Carnet => self.contacts_tab(ui, ctx),
                Tab::Explorateur => self.explorer_tab(ui),
                Tab::Emission => self.emission_tab(ui),
                Tab::Explications => self.explain_tab(ui),
                Tab::Avance => self.advanced_tab(ui, ctx),
                Tab::Reseau => self.network_tab(ui),
                Tab::Securite => self.security_tab(ui, ctx),
                Tab::Reglages => self.settings_tab(ui, ctx),
            });
        });
    }

    fn home_tab(&mut self, ui: &mut egui::Ui) {
        let port = self.node.as_ref().map(|n| n.port_state());
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let s = &self.snap;
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Solde disponible", "Available balance")).color(p.grey));
            ui.label(RichText::new(format_amount(s.balance.available)).size(34.0).strong());
            egui::Grid::new("soldes").num_columns(2).spacing([24.0, 4.0]).show(ui, |ui| {
                ui.label(t("En maturation (récompenses de minage, 100 blocs)", "Maturing (mining rewards, 100 blocks)"));
                ui.label(format_amount(s.balance.immature));
                ui.end_row();
                ui.label(t("Verrouillé (date de déblocage)", "Locked (unlock date)"));
                ui.label(format_amount(s.balance.locked));
                ui.end_row();
                ui.label(t("En cours d'envoi", "Being sent"));
                ui.label(format_amount(s.balance.pending));
                ui.end_row();
            });
        });
        let cores = self.cores;
        ui.columns(2, |cols| {
            card(&mut cols[0], &p, |ui| {
                ui.label(RichText::new(t("Minage", "Mining")).strong());
                if self.settings.schedule {
                    let night = self.schedule_night.unwrap_or(false);
                    ui.colored_label(p.accent, if night { t("Horaire actif : mode nuit", "Schedule on: night mode") } else { t("Horaire actif : mode jour", "Schedule on: day mode") });
                }
                let mut on = s.mining;
                if ui.checkbox(&mut on, t("Miner avec cet ordinateur", "Mine with this computer")).changed() {
                    node.mining.store(on, Ordering::SeqCst);
                    self.settings.mine = on;
                    self.settings.save(&self.opts.data_dir);
                    events::log(if on { t("Minage démarré.", "Mining started.") } else { t("Minage arrêté.", "Mining stopped.") });
                    self.snap_at = None;
                }
                let mut th = s.threads;
                ui.add(egui::Slider::new(&mut th, 1..=cores).text(t("cœurs", "cores")));
                if th != s.threads {
                    node.threads.store(th, Ordering::SeqCst);
                    self.snap_at = None;
                }
                ui.label(tf!("Vitesse : {} essais par seconde", "Speed: {} tries per second", s.rate));
                ui.label(
                    RichText::new(t(
                        "Chaque essai remplit 4 Mio de mémoire (Argon2d). Plus de cœurs = plus de chances, mais plus de chaleur et de bruit.",
                        "Each try fills 4 MiB of memory (Argon2d). More cores = more chances, but more heat and noise.",
                    ))
                    .small()
                    .color(p.grey),
                );
            });
            card(&mut cols[1], &p, |ui| {
                ui.label(RichText::new(t("Réseau", "Network")).strong());
                ui.label(tf!("Bloc actuel : #{}  ({}…)", "Current block: #{}  ({}…)", s.height, s.tip));
                ui.label(tf!("NFR émis : {} sur 69 100 000", "NFR issued: {} out of 69,100,000", format_amount(total_before(s.height + 1))));
                ui.label(tf!("Pairs connectés : {}", "Connected peers: {}", s.pairs));
                port_lines(ui, &p, &port, false);
            });
        });
        self.chart_card(ui);
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Journal", "Log")).strong());
            for l in events::recent(10) {
                ui.label(RichText::new(l).monospace().size(12.5));
            }
        });
    }

    /// Graphique en barres des gains de minage par jour.
    fn chart_card(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        self.refresh_stats();
        card(ui, &p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(t("Gains de minage", "Mining earnings")).strong());
                ui.add_space(12.0);
                for d in [7usize, 30] {
                    if ui.selectable_label(self.stats_days == d, tf!("{d} jours", "{d} days")).clicked() && self.stats_days != d {
                        self.stats_days = d;
                        self.stats_at = None;
                    }
                }
            });
            let st = self.stats.clone();
            ui.label(tf!(
                "Total : {} en {} bloc(s) trouvé(s)",
                "Total: {} in {} block(s) found",
                format_amount(st.total),
                st.blocks
            ));
            let h = 150.0;
            let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), h + 22.0), egui::Sense::hover());
            let painter = ui.painter_at(rect);
            let max = st.days.iter().map(|d| d.1).max().unwrap_or(0).max(1);
            let n = st.days.len().max(1);
            let slot = rect.width() / n as f32;
            let bar_w = (slot * 0.7).max(2.0);
            let base = rect.top() + h;
            painter.line_segment([egui::pos2(rect.left(), base), egui::pos2(rect.right(), base)], egui::Stroke::new(1.0, p.grey));
            let mut hovered = None;
            for (i, (label, amount, count)) in st.days.iter().enumerate() {
                let x = rect.left() + slot * i as f32 + (slot - bar_w) / 2.0;
                let bh = (*amount as f32 / max as f32) * (h - 8.0);
                let bar = egui::Rect::from_min_max(egui::pos2(x, base - bh), egui::pos2(x + bar_w, base));
                painter.rect_filled(bar, 3.0, p.accent);
                let every = if n > 10 { 5 } else { 1 };
                if i % every == 0 || i == n - 1 {
                    painter.text(egui::pos2(x + bar_w / 2.0, base + 4.0), egui::Align2::CENTER_TOP, label, egui::FontId::proportional(11.0), p.grey);
                }
                if let Some(pos) = resp.hover_pos() {
                    if pos.x >= rect.left() + slot * i as f32 && pos.x < rect.left() + slot * (i + 1) as f32 {
                        hovered = Some((label.clone(), *amount, *count));
                    }
                }
            }
            if let Some((label, amount, count)) = hovered {
                resp.on_hover_text(tf!("{label} : {} ({count} bloc(s))", "{label}: {} ({count} block(s))", format_amount(amount)));
            }
        });
    }

    fn receive_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let main = node.wallet.lock().unwrap().main_address().unwrap_or([0; 32]);
        let addr = *self.shown_address.get_or_insert(main);
        let text = address_to_string(&addr);
        card(ui, &p, |ui| {
            ui.label(RichText::new(if addr == main { t("Ton adresse permanente", "Your permanent address") } else { t("Adresse à usage unique", "Single-use address") }).strong());
            ui.label(
                RichText::new(if addr == main {
                    t("La même pour toujours : tu peux la donner à tout le monde.", "Always the same: you can give it to everyone.")
                } else {
                    t("À donner à une seule personne, pour plus de discrétion.", "Give it to one person only, for more privacy.")
                })
                .color(p.grey),
            );
            ui.add_space(4.0);
            ui.label(RichText::new(&text).monospace().size(16.0));
            ui.add_space(4.0);
            ui.label(t("Empreinte (à vérifier avec l'expéditeur) :", "Fingerprint (check it with the sender):"));
            fingerprint_ui(ui, &addr);
            ui.horizontal_wrapped(|ui| {
                if ui.button(t("Copier l'adresse", "Copy the address")).clicked() {
                    ctx.copy_text(text.clone());
                    self.info = Some(t("adresse copiée", "address copied").into());
                }
                if ui.button(t("Nouvelle adresse à usage unique", "New single-use address")).clicked() {
                    if let Ok(a) = node.wallet.lock().unwrap().new_address() {
                        self.shown_address = Some(a);
                    }
                }
                if addr != main && ui.button(t("Revenir à l'adresse permanente", "Back to the permanent address")).clicked() {
                    self.shown_address = Some(main);
                }
                if ui.button(if self.show_qr { t("Cacher le QR code", "Hide the QR code") } else { t("Afficher le QR code", "Show the QR code") }).clicked() {
                    self.show_qr = !self.show_qr;
                }
            });
            info_line(ui, &p, &self.info);
            if self.show_qr {
                qr_ui(ui, &text);
            }
        });
    }

    fn send_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let (contacts, resolved, name) = {
            let chain_guard = node.chain.lock().unwrap();
            let w = node.wallet.lock().unwrap();
            if self.send.to.trim().to_lowercase().starts_with("nfr:") {
                if let Ok(req) = crate::wallet_plus::parse_payment_uri(&self.send.to) {
                    self.send.to = req.recipient;
                    if let Some(a) = req.amount {
                        self.send.amount = crate::wallet::format_amount_plain(a);
                    }
                    if !req.message.is_empty() {
                        self.send.memo = req.message;
                    }
                }
            }
            let r = if self.send.to.trim().is_empty() { None } else { Some(w.resolve_recipient_with(&self.send.to, &chain_guard)) };
            let name = r.as_ref().and_then(|x| x.as_ref().ok()).and_then(|a| w.contact_name(a).map(str::to_string));
            (w.contacts().to_vec(), r, name)
        };
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Envoyer des NFR", "Send NFR")).strong());
            ui.label(t("Destinataire : un nom du carnet, une adresse NFR1-…, un pseudo (alice.nfr) ou un lien de demande nfr:…", "Recipient: a contact name, an NFR1-… address, a name (alice.nfr) or an nfr:… payment link"));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.send.to).desired_width(520.0).hint_text(t("NFR1-… ou un nom du carnet", "NFR1-… or a contact name")));
                egui::ComboBox::from_id_salt("carnet_choix").selected_text(t("Carnet", "Contacts")).show_ui(ui, |ui| {
                    for c in &contacts {
                        if ui.selectable_label(false, &c.name).clicked() {
                            self.send.to = c.name.clone();
                        }
                    }
                });
            });
            match &resolved {
                Some(Ok(a)) => {
                    fingerprint_ui(ui, a);
                    match &name {
                        Some(n) => {
                            ui.colored_label(p.green, tf!("{n} — dans ton carnet", "{n} — in your contacts"));
                        }
                        None => {
                            ui.colored_label(p.orange, t(
                                "Attention : adresse absente de ton carnet : vérifie l'empreinte ci-dessus avec le destinataire (par téléphone par exemple). Un virus peut remplacer une adresse copiée.",
                                "Warning: this address is not in your contacts: check the fingerprint above with the recipient (by phone for example). A virus can replace a copied address.",
                            ));
                        }
                    }
                }
                Some(Err(e)) => {
                    ui.colored_label(p.red, e);
                }
                None => {}
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(t("Montant", "Amount"));
                ui.add(egui::TextEdit::singleline(&mut self.send.amount).desired_width(140.0).hint_text(t("ex. 12,5", "e.g. 12.5")));
                ui.label("NFR");
                ui.label(RichText::new(tf!("(disponible : {})", "(available: {})", format_amount(self.snap.balance.available))).color(p.grey));
            });
            let amount = if self.send.amount.trim().is_empty() { None } else { Some(parse_amount(&self.send.amount)) };
            if let Some(Err(e)) = &amount {
                ui.colored_label(p.red, e);
            }
            ui.label(t("Message joint (facultatif, PUBLIC et gravé à vie dans la chaîne)", "Attached message (optional, PUBLIC and engraved forever in the chain)"));
            ui.add(egui::TextEdit::singleline(&mut self.send.memo).desired_width(520.0));
            let mb = self.send.memo.len();
            ui.label(
                RichText::new(tf!("{mb} / {MAX_MEMO} octets (les accents comptent double)", "{mb} / {MAX_MEMO} bytes (accented letters count double)"))
                    .small()
                    .color(if mb > MAX_MEMO { p.red } else { p.grey }),
            );
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.send.lock, t("Verrouiller jusqu'à une date", "Lock until a date"));
                if self.send.lock {
                    ui.add(egui::TextEdit::singleline(&mut self.send.lock_text).desired_width(80.0));
                    ui.label(RichText::new(t("ex. 30min, 12h, 3j, 2sem, 1mois, 1an", "e.g. 30min, 12h, 3d, 2w, 1mo, 1y")).color(p.grey));
                }
            });
            let lock = if self.send.lock { Some(parse_lock_duration(&self.send.lock_text)) } else { None };
            match &lock {
                Some(Ok(secs)) => {
                    let when = local_time(self.snap.mtp.max(now_secs()) + secs);
                    ui.label(tf!(
                        "Le destinataire pourra dépenser à partir du {when} (environ 1 h de marge). Personne ne peut débloquer avant.",
                        "The recipient can spend from {when} (about 1 h margin). Nobody can unlock it before."
                    ));
                }
                Some(Err(e)) => {
                    ui.colored_label(p.red, e);
                }
                None => {}
            }
            ui.add_space(6.0);
            password_field(ui, t("Code de dépense (pour signer)", "Spending code (to sign)"), &mut self.send.code);
            error_line(ui, &p, &self.error);
            info_line(ui, &p, &self.info);
            let ok = matches!(resolved, Some(Ok(_)))
                && matches!(amount, Some(Ok(_)))
                && !matches!(lock, Some(Err(_)))
                && mb <= MAX_MEMO
                && !self.send.code.is_empty()
                && self.job.is_none();
            ui.horizontal(|ui| {
                if ui.add_enabled(ok, egui::Button::new(RichText::new(t("Signer et envoyer", "Sign and send")).strong())).clicked() {
                    let to = resolved.clone().unwrap().unwrap();
                    let amount = amount.clone().unwrap().unwrap();
                    let opts = PaymentOptions { memo: self.send.memo.clone(), lock_secs: lock.clone().and_then(|r| r.ok()).unwrap_or(0), now: now_secs() };
                    let code = Zeroizing::new(std::mem::take(&mut self.send.code));
                    let n = node.clone();
                    let who = name.clone().unwrap_or_else(|| short_addr(&to));
                    self.spawn(t("Ouverture du coffre (quelques secondes) puis signature post-quantique…", "Opening the vault (a few seconds) then post-quantum signature…"), ctx, move || {
                        match pay(&n, to, amount, &opts, &code) {
                            Ok(fee) => JobResult::Sent(tf!(
                                "{} envoyés à {who} (frais {}). Attends 6 blocs pour que ce soit sûr.",
                                "{} sent to {who} (fee {}). Wait 6 blocks for it to be safe.",
                                format_amount(amount),
                                format_amount(fee)
                            )),
                            Err(e) => JobResult::Err(e),
                        }
                    });
                }
                if let Some(job) = &self.job {
                    ui.spinner();
                    ui.label(&job.label);
                }
            });
        });
    }

    fn history_tab(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        if self.history_at.is_none_or(|t| t.elapsed() > Duration::from_secs(10)) {
            let c = node.chain.lock().unwrap();
            let items = node.wallet.lock().unwrap().history(&c);
            self.history = items
                .into_iter()
                .rev()
                .map(|it| {
                    let ts = c.hash_at(it.height).and_then(|h| c.header(&h)).map(|h| h.timestamp).unwrap_or(0);
                    (it, ts)
                })
                .collect();
            self.history_at = Some(Instant::now());
        }
        let (height, mtp) = (self.snap.height, self.snap.mtp);
        card(ui, &p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(t("Historique des paiements", "Payment history")).strong());
                ui.add_space(16.0);
                if ui.add_enabled(!self.history.is_empty(), egui::Button::new(t("Exporter en tableur (CSV)", "Export to spreadsheet (CSV)"))).clicked() {
                    match self.export_csv() {
                        Ok(path) => self.info = Some(tf!("Historique enregistré : {}", "History saved: {}", path.display())),
                        Err(e) => self.error = Some(e),
                    }
                }
            });
            error_line(ui, &p, &self.error);
            info_line(ui, &p, &self.info);
            if self.history.is_empty() {
                ui.label(RichText::new(t("Aucun paiement pour l'instant (les récompenses de minage ne sont pas listées).", "No payments yet (mining rewards are not listed).")).color(p.grey));
            }
            egui::Grid::new("histo").striped(true).num_columns(5).spacing([18.0, 6.0]).show(ui, |ui| {
                for (it, ts) in &self.history {
                    ui.label(local_time(*ts));
                    ui.label(RichText::new(tf!("bloc #{}", "block #{}", it.height)).color(p.grey));
                    let (txt, col) = match it.kind {
                        HistoryKind::Received => (t("Reçu", "Received"), p.green),
                        HistoryKind::Sent => (t("Envoyé", "Sent"), p.red),
                        HistoryKind::Vault => (t("Coffre", "Vault"), p.accent),
                    };
                    ui.colored_label(col, txt);
                    ui.label(RichText::new(format_amount(it.amount)).strong());
                    ui.vertical(|ui| {
                        if !is_unlocked(it.lock_until, height + 1, mtp) {
                            ui.colored_label(p.orange, tf!("verrouillé jusqu'au {}", "locked until {}", describe_lock(it.lock_until)));
                        }
                        if !it.memo.is_empty() {
                            ui.label(format!("« {} »", it.memo));
                        }
                    });
                    ui.end_row();
                }
            });
        });
    }

    /// Enregistre l'historique dans un fichier CSV (séparateur « ; », lisible par Excel et LibreOffice).
    fn export_csv(&self) -> Result<PathBuf, String> {
        let mut out = String::from("\u{feff}");
        out += t("date;bloc;type;montant (NFR);message;verrouillé jusqu'au\n", "date;block;type;amount (NFR);message;locked until\n");
        for (it, ts) in &self.history {
            let kind = match it.kind {
                HistoryKind::Received => t("Reçu", "Received"),
                HistoryKind::Sent => t("Envoyé", "Sent"),
                HistoryKind::Vault => t("Coffre", "Vault"),
            };
            // Un message qui commence par = + - @ serait lu comme une formule par Excel ou LibreOffice :
            // on le neutralise avec une apostrophe devant.
            let mut memo = it.memo.replace('"', "\"\"");
            if memo.starts_with(['=', '+', '-', '@', '\t', '\r', '＝', '＋', '－', '＠']) {
                memo.insert(0, '\'');
            }
            let lock = if it.lock_until > 0 { describe_lock(it.lock_until) } else { String::new() };
            out += &format!("{};{};{};{};\"{}\";{}\n", local_time(*ts), it.height, kind, csv_amount(it.amount), memo, lock);
        }
        let name = format!("numfranc-historique-{}.csv", Local::now().format("%Y-%m-%d_%Hh%M"));
        let path = downloads_dir().join(name);
        std::fs::write(&path, out).map_err(|e| e.to_string())?;
        Ok(path)
    }

    fn contacts_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let contacts = node.wallet.lock().unwrap().contacts().to_vec();
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Carnet d'adresses", "Contacts")).strong());
            ui.label(
                RichText::new(t(
                    "Enregistre une adresse une seule fois, après avoir vérifié son empreinte avec la personne. Le carnet est chiffré avec ton portefeuille.",
                    "Save an address once, after checking its fingerprint with the person. The contacts are encrypted with your wallet.",
                ))
                .color(p.grey),
            );
            if contacts.is_empty() {
                ui.label(t("Ton carnet est vide.", "Your contacts are empty."));
            }
            let mut remove = None;
            egui::Grid::new("carnet").striped(true).num_columns(4).spacing([16.0, 6.0]).show(ui, |ui| {
                for c in &contacts {
                    ui.label(RichText::new(&c.name).strong());
                    fingerprint_ui(ui, &c.address);
                    ui.label(RichText::new(short_addr(&c.address)).monospace());
                    ui.horizontal(|ui| {
                        if ui.small_button(t("Envoyer", "Send")).clicked() {
                            self.send.to = c.name.clone();
                            self.tab = Tab::Envoyer;
                        }
                        if ui.small_button(t("Copier", "Copy")).clicked() {
                            ctx.copy_text(address_to_string(&c.address));
                        }
                        if ui.small_button(t("Supprimer", "Delete")).clicked() {
                            remove = Some(c.name.clone());
                        }
                    });
                    ui.end_row();
                }
            });
            if let Some(n) = remove {
                if let Err(e) = node.wallet.lock().unwrap().remove_contact(&n) {
                    self.error = Some(e);
                }
            }
        });
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Ajouter un contact", "Add a contact")).strong());
            ui.horizontal(|ui| {
                ui.label(t("Nom", "Name"));
                ui.add(egui::TextEdit::singleline(&mut self.contact_name).desired_width(160.0).hint_text(t("ex. Maman", "e.g. Mom")));
            });
            ui.label(t("Adresse", "Address"));
            ui.add(egui::TextEdit::singleline(&mut self.contact_addr).desired_width(f32::INFINITY).hint_text("NFR1-…"));
            let parsed = if self.contact_addr.trim().is_empty() { None } else { Some(crate::wallet::parse_address(&self.contact_addr)) };
            match &parsed {
                Some(Ok(a)) => {
                    ui.label(t("Empreinte (vérifie-la avec la personne) :", "Fingerprint (check it with the person):"));
                    fingerprint_ui(ui, a);
                }
                Some(Err(e)) => {
                    ui.colored_label(p.red, e);
                }
                None => {}
            }
            error_line(ui, &p, &self.error);
            if ui.add_enabled(matches!(parsed, Some(Ok(_))) && !self.contact_name.trim().is_empty(), egui::Button::new(t("Ajouter au carnet", "Add to contacts"))).clicked() {
                let a = parsed.unwrap().unwrap();
                match node.wallet.lock().unwrap().add_contact(&self.contact_name, a) {
                    Ok(()) => {
                        self.contact_name.clear();
                        self.contact_addr.clear();
                        self.error = None;
                    }
                    Err(e) => self.error = Some(e),
                }
            }
        });
    }

    /// Explorateur de blocs : liste des derniers blocs et détail d'un bloc.
    fn explorer_tab(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let tip = self.snap.height;
        let top = self.explorer_top.unwrap_or(tip).min(tip);
        const PAGE: u64 = 20;
        card(ui, &p, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(t("Explorateur de blocs", "Block explorer")).strong());
                ui.add_space(16.0);
                ui.label(t("Aller au bloc", "Go to block"));
                let r = ui.add(egui::TextEdit::singleline(&mut self.explorer_go).desired_width(90.0).hint_text("#"));
                let go = ui.button("OK").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if go {
                    if let Ok(h) = self.explorer_go.trim().trim_start_matches('#').parse::<u64>() {
                        if h <= tip {
                            self.explorer_sel = Some(h);
                            self.explorer_top = Some((h + PAGE / 2).min(tip));
                        }
                    }
                }
            });
            ui.horizontal(|ui| {
                if ui.add_enabled(top < tip, egui::Button::new(t("« Plus récents", "« Newer"))).clicked() {
                    self.explorer_top = Some((top + PAGE).min(tip));
                }
                if ui.add_enabled(top >= PAGE, egui::Button::new(t("Plus anciens »", "Older »"))).clicked() {
                    self.explorer_top = Some(top - PAGE);
                }
                if ui.button(t("Dernier bloc", "Latest block")).clicked() {
                    self.explorer_top = None;
                }
            });
            let c = node.chain.lock().unwrap();
            let w = node.wallet.lock().unwrap();
            egui::Grid::new("blocs").striped(true).num_columns(5).spacing([18.0, 4.0]).show(ui, |ui| {
                ui.label(RichText::new(t("Bloc", "Block")).strong());
                ui.label(RichText::new(t("Date", "Date")).strong());
                ui.label(RichText::new(t("Transactions", "Transactions")).strong());
                ui.label(RichText::new(t("Récompense", "Reward")).strong());
                ui.label(RichText::new(t("Mineur", "Miner")).strong());
                ui.end_row();
                let mut h = top;
                for _ in 0..PAGE {
                    let Some(b) = c.block_at(h) else { break };
                    let sel = self.explorer_sel == Some(h);
                    if ui.selectable_label(sel, format!("#{h}")).clicked() {
                        self.explorer_sel = Some(h);
                    }
                    ui.label(local_time(b.header.timestamp));
                    ui.label(format!("{}", b.txs.len()));
                    ui.label(format_amount(b.txs[0].output_sum().unwrap_or(0)));
                    let mine = b.txs[0].outputs.iter().any(|o| w.is_mine(&o.address));
                    if h == 0 {
                        ui.label(RichText::new("genesis").color(p.grey));
                    } else if mine {
                        ui.colored_label(p.green, t("toi", "you"));
                    } else {
                        ui.label(RichText::new(b.txs[0].outputs.first().map(|o| short_addr(&o.address)).unwrap_or_default()).monospace().size(12.0));
                    }
                    ui.end_row();
                    if h == 0 {
                        break;
                    }
                    h -= 1;
                }
            });
        });
        let Some(sel) = self.explorer_sel else { return };
        let c = node.chain.lock().unwrap();
        let w = node.wallet.lock().unwrap();
        let Some(b) = c.block_at(sel) else { return };
        card(ui, &p, |ui| {
            ui.label(RichText::new(tf!("Bloc #{sel}", "Block #{sel}")).size(20.0).strong());
            egui::Grid::new("detail").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                ui.label(t("Empreinte", "Hash"));
                ui.label(RichText::new(hex(&b.hash())).monospace().size(11.5));
                ui.end_row();
                ui.label(t("Bloc précédent", "Previous block"));
                ui.label(RichText::new(hex(&b.header.previous_block_hash)).monospace().size(11.5));
                ui.end_row();
                ui.label(t("Date", "Date"));
                ui.label(local_time(b.header.timestamp));
                ui.end_row();
                ui.label(t("Difficulté", "Difficulty"));
                let zeros: u32 = b.header.target.iter().take_while(|&&x| x == 0).count() as u32 * 8
                    + b.header.target.iter().find(|&&x| x != 0).map(|x| x.leading_zeros()).unwrap_or(0);
                ui.label(tf!("cible à {zeros} bits de zéros en tête (≈ 2^{zeros} essais Argon2d)", "target with {zeros} leading zero bits (≈ 2^{zeros} Argon2d tries)"));
                ui.end_row();
                ui.label("Nonce");
                ui.label(format!("{}", b.header.nonce));
                ui.end_row();
                ui.label(t("Taille", "Size"));
                ui.label(tf!("{} octets", "{} bytes", b.serialize().len()));
                ui.end_row();
            });
            ui.separator();
            for (i, tx) in b.txs.iter().enumerate() {
                let kind = if i == 0 { t("Récompense de minage", "Mining reward") } else { t("Paiement", "Payment") };
                ui.label(RichText::new(format!("{kind} — {}…", &hex(&tx.txid())[..24])).strong());
                if i > 0 {
                    let from_me = tx.inputs.iter().any(|x| w.is_mine(&address_of_pubkey(&x.pubkey)));
                    ui.label(RichText::new(tf!(
                        "{} entrée(s) signée(s) ML-DSA-87{}",
                        "{} input(s) signed with ML-DSA-87{}",
                        tx.inputs.len(),
                        if from_me { t(" — envoyé par toi", " — sent by you") } else { "" }
                    )).color(p.grey));
                }
                for o in &tx.outputs {
                    ui.horizontal(|ui| {
                        ui.label("•");
                        ui.label(RichText::new(format_amount(o.amount)).strong());
                        ui.label(RichText::new(short_addr(&o.address)).monospace());
                        if w.is_mine(&o.address) {
                            ui.colored_label(p.green, t("(toi)", "(you)"));
                        }
                        if o.lock_until > 0 {
                            ui.colored_label(p.orange, tf!("verrouillé jusqu'au {}", "locked until {}", describe_lock(o.lock_until)));
                        }
                    });
                }
                if !tx.memo.is_empty() {
                    ui.label(tf!("Message : « {} »", "Message: “{}”", tx.memo_text()));
                }
                ui.add_space(4.0);
            }
        });
    }

    fn network_tab(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Réseau", "Network")).strong());
            ui.label(tf!("Port local : {}", "Local port: {}", node.opts.port));
            port_lines(ui, &p, &Some(node.port_state()), true);
            ui.label(tf!("Bloc actuel : #{}  ({}…)", "Current block: #{}  ({}…)", self.snap.height, self.snap.tip));
            ui.label(t("Les autres nœuds sont trouvés automatiquement : réseau local, puis annuaire mondial.", "Other nodes are found automatically: local network, then world directory."));
            ui.label(RichText::new(tf!(
                "Connexions inconnues bloquées sans bruit (robots qui sondent Internet) : {}",
                "Unknown connections silently blocked (bots scanning the Internet): {}",
                self.snap.blocked
            )).color(p.grey));
        });
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Pairs connectés", "Connected peers")).strong());
            let list = node.peer_list();
            if list.is_empty() {
                ui.label(RichText::new(t("Aucun pair pour l'instant : la recherche continue.", "No peer yet: still searching.")).color(p.grey));
            }
            egui::Grid::new("pairs").striped(true).num_columns(3).show(ui, |ui| {
                for (a, out, h) in list {
                    ui.label(RichText::new(a).monospace());
                    ui.label(if out { t("sortant", "outgoing") } else { t("entrant", "incoming") });
                    ui.label(tf!("bloc #{h}", "block #{h}"));
                    ui.end_row();
                }
            });
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.connect_to).desired_width(240.0).hint_text(t("hôte:port", "host:port")));
                if ui.button(t("Se connecter", "Connect")).clicked() && !self.connect_to.trim().is_empty() {
                    let n = node.clone();
                    let target = self.connect_to.trim().to_string();
                    std::thread::spawn(move || n.connect_to(target));
                    self.connect_to.clear();
                }
            });
        });
    }

    fn security_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Protections de ton portefeuille", "Your wallet's protections")).strong());
            ui.label(t("• Fichier chiffré deux fois : AES-256-GCM puis XChaCha20-Poly1305 (512 bits de clé au total).", "• File encrypted twice: AES-256-GCM then XChaCha20-Poly1305 (512 key bits in total)."));
            ui.label(t(
                "• Clés tirées de tes mots de passe par Argon2id : 256 Mio par essai pour l'ouverture, 1 Gio et 4 passes pour le code de dépense. Chaque essai pour deviner un mot de passe coûte cher, même à un voleur qui a copié le fichier.",
                "• Keys derived from your passwords with Argon2id: 256 MiB per try for opening, 1 GiB and 4 passes for the spending code. Every guess is expensive, even for a thief who copied the file.",
            ));
            ui.label(t("• Tes mots de passe ne sont enregistrés nulle part, même chiffrés : ils servent seulement à fabriquer les clés.", "• Your passwords are stored nowhere, not even encrypted: they are only used to build the keys."));
            ui.label(t("• Signatures post-quantiques ML-DSA-87 (niveau 5 du NIST).", "• Post-quantum ML-DSA-87 signatures (NIST level 5)."));
        });
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Code de secours (3 morceaux)", "Recovery code (3 pieces)")).strong());
            if let Some(s) = &self.sec_shares {
                ui.label(t("2 morceaux sur 3 suffisent. Ce sont toujours les mêmes morceaux.", "2 pieces out of 3 are enough. They are always the same pieces."));
                for (i, x) in s.iter().enumerate() {
                    ui.label(RichText::new(tf!("Morceau {} : {x}", "Piece {}: {x}", i + 1)).monospace());
                }
                if ui.button(t("Cacher les morceaux", "Hide the pieces")).clicked() {
                    self.sec_shares = None;
                }
            } else {
                password_field(ui, spend_label(), &mut self.sec_code);
                if ui.add_enabled(!self.sec_code.is_empty() && self.job.is_none(), egui::Button::new(t("Afficher les 3 morceaux", "Show the 3 pieces"))).clicked() {
                    let n = node.clone();
                    let code = Zeroizing::new(std::mem::take(&mut self.sec_code));
                    self.spawn(t("Ouverture du coffre…", "Opening the vault…"), ctx, move || match n.recovery_shares(&code) {
                        Ok(s) => JobResult::Shares(s),
                        Err(e) => JobResult::Err(e),
                    });
                }
            }
        });
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Changer les mots de passe", "Change the passwords")).strong());
            password_field(ui, t("Code de dépense ACTUEL", "CURRENT spending code"), &mut self.chg_old);
            Self::passwords_form(ui, &p, &mut self.chg);
            error_line(ui, &p, &self.error);
            info_line(ui, &p, &self.info);
            if ui.add_enabled(!self.chg_old.is_empty() && self.chg.check().is_ok() && self.job.is_none(), egui::Button::new(t("Changer", "Change"))).clicked() {
                let n = node.clone();
                let old = Zeroizing::new(self.chg_old.clone());
                let (o, s) = (Zeroizing::new(self.chg.open1.clone()), Zeroizing::new(self.chg.spend1.clone()));
                self.spawn(t("Rechiffrement du portefeuille…", "Re-encrypting the wallet…"), ctx, move || match n.change_passwords(&old, &o, &s) {
                    Ok(()) => JobResult::Info(t("mots de passe changés", "passwords changed").into()),
                    Err(e) => JobResult::Err(e),
                });
            }
        });
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let port = self.node.as_ref().map(|n| n.port_state());
        let p = self.pal();
        let mut changed = false;
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Apparence", "Appearance")).strong());
            ui.horizontal(|ui| {
                ui.label(t("Langue", "Language"));
                for l in crate::i18n::Lang::ALL {
                    changed |= ui.selectable_value(&mut self.settings.lang, l, l.name()).changed();
                }
            });
            ui.horizontal(|ui| {
                ui.label(t("Thème", "Theme"));
                changed |= ui.selectable_value(&mut self.settings.dark, false, t("Clair", "Light")).changed();
                changed |= ui.selectable_value(&mut self.settings.dark, true, t("Sombre", "Dark")).changed();
            });
            ui.horizontal(|ui| {
                ui.label(t("Couleur principale", "Main colour"));
                for (i, &(fr, en, light, dark)) in ACCENTS.iter().enumerate() {
                    let c: [u8; 3] = if self.settings.dark { dark } else { light };
                    let col = Color32::from_rgb(c[0], c[1], c[2]);
                    let (r, resp) = ui.allocate_exact_size(Vec2::splat(26.0), egui::Sense::click());
                    ui.painter().circle_filled(r.center(), 11.0, col);
                    if self.settings.accent == i {
                        ui.painter().circle_stroke(r.center(), 13.0, egui::Stroke::new(2.0, ui.visuals().text_color()));
                    }
                    if resp.on_hover_text(t(fr, en)).clicked() {
                        self.settings.accent = i;
                        changed = true;
                    }
                }
            });
        });
        let cores = self.cores;
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Minage selon l'horaire", "Scheduled mining")).strong());
            ui.label(RichText::new(t(
                "Par exemple : à fond la nuit quand personne n'utilise l'ordinateur, doucement (ou pas du tout) le jour.",
                "For example: full speed at night when nobody uses the computer, gently (or not at all) during the day.",
            )).color(p.grey));
            if ui.checkbox(&mut self.settings.schedule, t("Activer l'horaire", "Enable the schedule")).changed() {
                self.schedule_night = None;
                changed = true;
            }
            ui.add_enabled_ui(self.settings.schedule, |ui| {
                ui.horizontal(|ui| {
                    ui.label(t("Nuit de", "Night from"));
                    changed |= ui.add(egui::DragValue::new(&mut self.settings.night_start).range(0..=23).suffix(" h")).changed();
                    ui.label(t("à", "to"));
                    changed |= ui.add(egui::DragValue::new(&mut self.settings.night_end).range(0..=23).suffix(" h")).changed();
                });
                changed |= ui.add(egui::Slider::new(&mut self.settings.cores_night, 0..=cores).text(t("cœurs la nuit (0 = arrêt)", "cores at night (0 = off)"))).changed();
                changed |= ui.add(egui::Slider::new(&mut self.settings.cores_day, 0..=cores).text(t("cœurs le jour (0 = arrêt)", "cores during the day (0 = off)"))).changed();
            });
        });
        let mut permanent = self.settings.permanent;
        let mut permanent_change = false;
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Toujours allumé", "Always on")).strong());
            permanent_change = ui.checkbox(&mut permanent, t("Garder NumFranc allumé en permanence (recommandé)", "Keep NumFranc on all the time (recommended)")).changed();
            ui.label(
                RichText::new(if permanent {
                    t(
                        "NumFranc démarre avec l'ordinateur et se relance tout seul. Quand tu fermes la fenêtre, il continue en arrière-plan : il garde le réseau et mine vers ton adresse de réception, avec les cœurs réglés ci-dessus. Ton portefeuille reste fermé et chiffré.",
                        "NumFranc starts with the computer and restarts by itself. When you close the window it keeps running in the background: it keeps the network going and mines to your receiving address, with the cores set above. Your wallet stays closed and encrypted.",
                    )
                } else {
                    t("Fermer la fenêtre arrête NumFranc.", "Closing the window stops NumFranc.")
                })
                .small()
                .color(p.grey),
            );
        });
        if permanent_change {
            self.settings.permanent_asked = true;
            self.set_permanent(permanent, ctx);
        }
        if let Some(etat) = port.clone() {
            let aide = self.node.as_ref().and_then(|n| n.aide_box());
            let mut manuel = self.settings.manual_port;
            let mut manuel_change = false;
            card(ui, &p, |ui| {
                ui.label(RichText::new(t("Connexion", "Connection")).strong());
                port_lines(ui, &p, &port, true);
                manuel_change = port_guide(ui, &p, &etat, &aide, &mut manuel);
            });
            if manuel_change {
                self.settings.manual_port = manuel;
                if let Some(n) = &self.node {
                    n.set_manual_port(manuel);
                }
                changed = true;
            }
        }
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Mises à jour", "Updates")).strong());
            ui.label(RichText::new(t(
                "NumFranc vérifie tout seul au démarrage puis toutes les 6 heures. Une nouvelle version n'est proposée que si la signature de l'auteur et l'empreinte du fichier sont bonnes.",
                "NumFranc checks by itself at startup and then every 6 hours. A new version is offered only if the author's signature and the file's fingerprint are correct.",
            ))
            .small()
            .color(p.grey));
            if let EtatMaj::Erreur(e) = &*self.maj_auto.lock().unwrap() {
                ui.label(RichText::new(tf!("Dernière mise à jour automatique : {e}", "Last automatic update: {e}")).small().color(p.red));
            }
            ui.label(tf!(
                "Version installée : {}. La vérification télécharge la liste signée de la dernière version et contrôle sa signature avant de te la proposer.",
                "Installed version: {}. The check downloads the signed list of the latest version and verifies its signature before offering it.",
                env!("CARGO_PKG_VERSION")
            ));
            if let Some(rx) = &self.maj_attente {
                if let Ok(r) = rx.try_recv() {
                    self.maj = Some(r);
                    self.maj_attente = None;
                } else {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(t("Vérification…", "Checking…"));
                    });
                    ctx.request_repaint_after(Duration::from_millis(200));
                }
            }
            if self.maj_attente.is_none() && ui.button(t("Vérifier les mises à jour", "Check for updates")).clicked() {
                let (tx, rx) = std::sync::mpsc::channel();
                let dossier = self.opts.data_dir.clone();
                let etat = self.maj_auto.clone();
                std::thread::spawn(move || {
                    let r = crate::maj::verifier(&dossier);
                    let nouvelle = matches!(r, Ok(crate::maj::Resultat::Nouvelle(_)));
                    let _ = tx.send(r);
                    // Nouvelle version : téléchargement et vérification tout de suite (bandeau en haut).
                    if nouvelle {
                        maj_tour(&dossier, &etat);
                    }
                });
                self.maj_attente = Some(rx);
                self.maj = None;
            }
            match &self.maj {
                Some(Ok(crate::maj::Resultat::Nouvelle(v))) => {
                    ui.colored_label(p.green, tf!("Version {v} disponible — signature de l'auteur vérifiée", "Version {v} available — author's signature verified"));
                    if crate::maj::peut_installer() {
                        ui.label(t(
                            "Elle se télécharge et se vérifie toute seule : le bouton « Installer et relancer » apparaît en haut de la fenêtre.",
                            "It downloads and checks itself: the « Install and restart » button appears at the top of the window.",
                        ));
                    } else if ui.button(t("Ouvrir la page de téléchargement", "Open the download page")).clicked() {
                        crate::maj::ouvrir_page();
                    }
                }
                Some(Ok(crate::maj::Resultat::AJour(_))) => {
                    ui.colored_label(p.green, t("NumFranc est à jour.", "NumFranc is up to date."));
                }
                Some(Err(e)) => {
                    ui.colored_label(p.red, e.as_str());
                }
                None => {}
            }
        });
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Mode expert", "Expert mode")).strong());
            ui.label(t(
                "Désactivé, NumFranc ne montre que l'essentiel. Activé, tous les onglets apparaissent : Explorateur, Émission, Avancé et Réseau.",
                "When off, NumFranc only shows the essentials. When on, every tab appears: Explorer, Issuance, Advanced and Network.",
            ));
            if ui.checkbox(&mut self.settings.expert, t("Activer le mode expert", "Turn on expert mode")).changed() {
                changed = true;
                if !self.settings.expert && matches!(self.tab, Tab::Explorateur | Tab::Emission | Tab::Avance | Tab::Reseau) {
                    self.tab = Tab::Accueil;
                }
            }
        });
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Raccourci", "Shortcut")).strong());
            ui.label(t(
                "Ajoute NumFranc au menu des applications : tu pourras le lancer d'un clic, sans Terminal.",
                "Add NumFranc to the applications menu: launch it with one click, without a Terminal.",
            ));
            if ui.button(t("Ajouter NumFranc au menu des applications", "Add NumFranc to the applications menu")).clicked() {
                match crate::install::add_to_menu(&self.opts.data_dir) {
                    Ok(m) => {
                        self.info = Some(m);
                        self.error = None;
                    }
                    Err(e) => self.error = Some(e),
                }
            }
            error_line(ui, &p, &self.error);
            info_line(ui, &p, &self.info);
        });
        ui.label(
            RichText::new(t(
                "NumFranc a l'ambition de devenir une infrastructure de paiement post-quantique de référence, utilisée par les particuliers comme par les entreprises. Logiciel libre en développement : aucune vente de NFR, aucune promesse de valeur. Licence MIT, sans garantie.",
                "NumFranc aims to become a leading post-quantum payment infrastructure, used by individuals and businesses alike. Open-source software under development: no NFR for sale, no promise of value. MIT licence, no warranty.",
            ))
            .small()
            .color(p.grey),
        );
        if changed {
            if !self.settings.schedule {
                self.schedule_night = None;
            } else {
                self.schedule_night = None; // réappliquer tout de suite
            }
            self.save_settings(ctx);
        }
    }
}

/// Petit logo dessiné (six bandes bleues et rouges en hexagone, « N » au centre),
/// utilisé dans la barre du haut. Mêmes formes que assets/logo.svg (repère 512 × 512).
fn draw_logo(painter: &egui::Painter, r: egui::Rect) {
    let k = r.width().min(r.height()) / 512.0;
    let o = r.center() - egui::vec2(256.0 * k, 256.0 * k);
    let p = |x: f32, y: f32| egui::pos2(o.x + x * k, o.y + y * k);
    let marine = Color32::from_rgb(0, 38, 84);
    let rouge = Color32::from_rgb(225, 0, 15);
    let blanc = egui::Stroke::new(7.0 * k, Color32::WHITE);
    // Fond blanc de l'hexagone (le logo reste lisible en thème sombre).
    let fond = [(256.0, 28.0), (453.5, 142.0), (453.5, 370.0), (256.0, 484.0), (58.5, 370.0), (58.5, 142.0)];
    painter.add(egui::Shape::convex_polygon(fond.iter().map(|&(x, y)| p(x, y)).collect(), Color32::WHITE, blanc));
    // Les six bandes qui tournent, séparées par un filet blanc.
    let bandes: [[(f32, f32); 5]; 6] = [
        [(256.0, 90.0), (309.7, 59.0), (453.5, 142.0), (453.5, 204.0), (399.8, 173.0)],
        [(399.8, 173.0), (453.5, 204.0), (453.5, 370.0), (399.8, 401.0), (399.8, 339.0)],
        [(399.8, 339.0), (399.8, 401.0), (256.0, 484.0), (202.3, 453.0), (256.0, 422.0)],
        [(256.0, 422.0), (202.3, 453.0), (58.5, 370.0), (58.5, 308.0), (112.2, 339.0)],
        [(112.2, 339.0), (58.5, 308.0), (58.5, 142.0), (112.2, 111.0), (112.2, 173.0)],
        [(112.2, 173.0), (112.2, 111.0), (256.0, 28.0), (309.7, 59.0), (256.0, 90.0)],
    ];
    for (i, b) in bandes.iter().enumerate() {
        let c = if i % 2 == 0 { marine } else { rouge };
        painter.add(egui::Shape::convex_polygon(b.iter().map(|&(x, y)| p(x, y)).collect(), c, blanc));
    }
    // Le « N » (police Unbounded, découpé en trois morceaux convexes).
    let n: [&[(f32, f32)]; 3] = [
        &[(185.97, 177.0), (222.87, 177.0), (222.87, 300.0), (185.97, 300.0)],
        &[(288.96, 177.0), (326.03, 177.0), (326.03, 300.0), (288.96, 300.0)],
        &[(222.87, 218.0), (222.87, 177.0), (235.34, 177.0), (288.96, 256.54), (288.96, 300.0), (278.14, 300.0)],
    ];
    for m in n {
        painter.add(egui::Shape::convex_polygon(m.iter().map(|&(x, y)| p(x, y)).collect(), marine, egui::Stroke::NONE));
    }
}

/// Prépare, signe et diffuse un paiement. Renvoie les frais.
pub fn pay(node: &Arc<Node>, to: Address, amount: u64, opts: &PaymentOptions, code: &str) -> Result<u64, String> {
    // Le long calcul du code de dépense (Argon2) se fait AVANT de verrouiller quoi que ce soit.
    node.prepare_spend(code)?;
    let tx: Result<Transaction, String> = {
        let c = node.chain.lock().unwrap();
        let mp = node.mempool.lock().unwrap();
        let mut w = node.wallet.lock().unwrap();
        let r = w.create_payment(&c, &mp, to, amount, opts, Some(code));
        w.clear_pre_seed();
        r
    };
    let tx = tx?;
    let fee = {
        let c = node.chain.lock().unwrap();
        let ins: u64 = tx.inputs.iter().filter_map(|i| c.utxo.get(&i.prev)).map(|u| u.amount).sum();
        ins - tx.output_sum().unwrap_or(0)
    };
    node.submit_tx(tx)?;
    Ok(fee)
}
