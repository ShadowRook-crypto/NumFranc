//! Onglets de la v0.6 : Émission, Explications (mode pas à pas) et Avancé
//! (gel, paiements annulables, pseudos, groupes multi-signature, preuve de réserve, demande de paiement).

use super::*;
use crate::emission::block_reward;
use crate::merkle::merkle_root;
use crate::wallet::Protection;
use crate::wallet_plus::{self, payment_uri, verify_reserve};
use std::collections::HashMap;

#[derive(Default)]
pub(super) struct PlusState {
    // Explications
    ex_tx_mode: bool,
    ex_height: String,
    ex_sel: Option<u64>,
    ex_step: usize,
    ex_tx: usize,
    ex_pow: Option<(u64, [u8; 64])>,
    ex_origin: HashMap<(crate::tx::Hash, u32), Option<(u64, Address)>>,
    // Avancé
    code: String,
    unfreeze_open: String,
    unfreeze_spend: String,
    unfreeze_a: String,
    unfreeze_b: String,
    prot_threshold: String,
    prot_delay: String,
    prot_guardian: String,
    prot_loaded: bool,
    name_input: String,
    name_target: String,
    group_name: String,
    group_m: String,
    group_members: String,
    ms_group: String,
    ms_to: String,
    ms_amount: String,
    ms_memo: String,
    ms_text: String,
    reserve_amount: String,
    reserve_challenge: String,
    reserve_proof: String,
    verify_text: String,
    verify_challenge: String,
    verify_result: Option<Result<String, String>>,
    req_amount: String,
    req_message: String,
    req_to: String,
    autostart: Option<bool>,
}

fn h16(h: &[u8]) -> String {
    let s = hex(h);
    format!("{}…{}", &s[..16], &s[s.len() - 8..])
}

fn step_box(ui: &mut egui::Ui, p: &Pal, title: &str, body: &str) {
    ui.label(RichText::new(title).size(17.0).strong().color(p.accent));
    ui.add_space(4.0);
    ui.label(body);
    ui.add_space(6.0);
}

fn kv(ui: &mut egui::Ui, k: &str, v: String) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(k).strong());
        ui.label(RichText::new(v).monospace());
    });
}

impl App {
    // ------------------------------------------------------------------ Émission
    pub(super) fn emission_tab(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let height = node.chain.lock().unwrap().height();
        let minted = total_before(height + 1);
        let reward = block_reward(height + 1, minted);
        let palier = (height + 1) / PALIER_BLOCKS;
        let to_next = PALIER_BLOCKS - (height + 1) % PALIER_BLOCKS;
        let next_reward = block_reward((palier + 1) * PALIER_BLOCKS, total_before((palier + 1) * PALIER_BLOCKS));
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Tableau de bord de l'émission", "Issuance dashboard")).strong());
            ui.label(t(
                "Calculé par TON nœud à partir des règles du protocole : personne ne peut te mentir sur la quantité de NFR qui existe.",
                "Computed by YOUR node from the protocol rules: nobody can lie to you about how many NFR exist.",
            ));
            ui.add_space(6.0);
            let frac = minted as f32 / HARD_CAP as f32;
            ui.add(egui::ProgressBar::new(frac).text(format!("{:.4} %", frac * 100.0)).desired_width(ui.available_width().min(600.0)));
            ui.add_space(4.0);
            kv(ui, &t("NFR déjà créés : ", "NFR already created: ").to_string(), format!("{} / {}", format_amount(minted), format_amount(HARD_CAP)));
            kv(ui, &t("NFR restant à créer : ", "NFR left to create: ").to_string(), format_amount(HARD_CAP - minted));
            kv(ui, &t("Récompense du prochain bloc : ", "Next block reward: ").to_string(), format_amount(reward));
            kv(ui, &t("Palier actuel : ", "Current tier: ").to_string(), crate::tf!("{} ({} blocs par palier)", "{} ({} blocks per tier)", palier, PALIER_BLOCKS));
            let secs = to_next * TARGET_BLOCK_TIME;
            kv(
                ui,
                &t("Prochain palier : ", "Next tier: ").to_string(),
                tf!(
                    "dans {} blocs (environ {} jours), récompense {}",
                    "in {} blocks (about {} days), reward {}",
                    to_next,
                    secs / 86_400,
                    format_amount(next_reward)
                ),
            );
        });
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Les prochains paliers", "The next tiers")).strong());
            egui::Grid::new("paliers").striped(true).num_columns(4).show(ui, |ui| {
                for h in [t("Palier", "Tier"), t("Blocs", "Blocks"), t("Récompense", "Reward"), t("Total créé à la fin", "Total created at end")] {
                    ui.label(RichText::new(h).strong());
                }
                ui.end_row();
                for n in palier..palier + 8 {
                    let start = n * PALIER_BLOCKS;
                    let end = (n + 1) * PALIER_BLOCKS;
                    let r = block_reward(start, total_before(start));
                    ui.label(if n == palier { format!("{n} (actuel)") } else { n.to_string() });
                    ui.label(format!("{start} – {}", end - 1));
                    ui.label(format_amount(r));
                    ui.label(format_amount(total_before(end)));
                    ui.end_row();
                }
            });
            ui.label(RichText::new(t(
                "Palier 0 : démarrage doux à 6,91 NFR ; palier 1 : pic à 69,10 NFR ; ensuite −10 % à chaque palier. Plafond fixe : 69 100 000 NFR.",
                "Tier 0: soft start at 6.91 NFR; tier 1: peak at 69.10 NFR; then −10 % each tier. Fixed cap: 69,100,000 NFR.",
            )).color(p.grey));
        });
    }

    // ------------------------------------------------------------------ Explications
    fn origin_of(&mut self, node: &Arc<Node>, from_height: u64, prev: &crate::tx::OutPoint) -> Option<(u64, Address)> {
        let key = (prev.txid, prev.vout);
        if let Some(v) = self.plus.ex_origin.get(&key) {
            return *v;
        }
        let c = node.chain.lock().unwrap();
        let mut found = None;
        'outer: for h in (from_height.saturating_sub(2_000)..from_height).rev() {
            let Some(b) = c.block_at(h) else { continue };
            for tx in &b.txs {
                if tx.txid() == prev.txid {
                    found = tx.outputs.get(prev.vout as usize).map(|o| (o.amount, o.address));
                    break 'outer;
                }
            }
        }
        drop(c);
        self.plus.ex_origin.insert(key, found);
        found
    }

    pub(super) fn explain_tab(&mut self, ui: &mut egui::Ui) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let tip = self.snap.height;
        let sel = self.plus.ex_sel.unwrap_or(tip).min(tip);
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Mode explication", "Explanation mode")).strong());
            ui.label(t(
                "Choisis un bloc, puis avance étape par étape : tu verras ce que ton ordinateur vérifie avant d'accepter un bloc ou un paiement. Ça ne change rien au fonctionnement, c'est juste pour comprendre.",
                "Pick a block, then go step by step: you will see what your computer checks before accepting a block or a payment. It changes nothing, it is only to learn.",
            ));
            ui.horizontal(|ui| {
                ui.label(t("Bloc n°", "Block #"));
                let r = ui.add(egui::TextEdit::singleline(&mut self.plus.ex_height).desired_width(90.0).hint_text(sel.to_string()));
                let go = ui.button("OK").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if go {
                    if let Ok(h) = self.plus.ex_height.trim().trim_start_matches('#').parse::<u64>() {
                        if h <= tip {
                            self.plus.ex_sel = Some(h);
                            self.plus.ex_step = 0;
                            self.plus.ex_tx = 0;
                        }
                    }
                }
                if ui.button(t("Dernier bloc", "Latest block")).clicked() {
                    self.plus.ex_sel = None;
                    self.plus.ex_step = 0;
                    self.plus.ex_tx = 0;
                }
                ui.separator();
                if ui.selectable_label(!self.plus.ex_tx_mode, t("Un bloc", "A block")).clicked() {
                    self.plus.ex_tx_mode = false;
                    self.plus.ex_step = 0;
                }
                if ui.selectable_label(self.plus.ex_tx_mode, t("Une transaction", "A transaction")).clicked() {
                    self.plus.ex_tx_mode = true;
                    self.plus.ex_step = 0;
                }
            });
        });
        let Some(block) = node.chain.lock().unwrap().block_at(sel) else {
            ui.label(t("Bloc introuvable.", "Block not found."));
            return;
        };
        let steps = if self.plus.ex_tx_mode { 6 } else { 6 };
        card(ui, &p, |ui| {
            ui.horizontal(|ui| {
                if ui.add_enabled(self.plus.ex_step > 0, egui::Button::new(t("Précédent", "Previous"))).clicked() {
                    self.plus.ex_step -= 1;
                }
                ui.label(tf!("Étape {} sur {}", "Step {} of {}", self.plus.ex_step + 1, steps));
                if ui.add_enabled(self.plus.ex_step + 1 < steps, egui::Button::new(t("Suivant", "Next"))).clicked() {
                    self.plus.ex_step += 1;
                }
            });
            ui.separator();
            if self.plus.ex_tx_mode {
                self.explain_tx(ui, &p, &node, sel, &block);
            } else {
                self.explain_block(ui, &p, &node, sel, &block);
            }
        });
    }

    fn explain_block(&mut self, ui: &mut egui::Ui, p: &Pal, node: &Arc<Node>, h: u64, b: &crate::block::Block) {
        let hd = &b.header;
        match self.plus.ex_step {
            0 => {
                step_box(
                    ui,
                    p,
                    &tf!("1. L'en-tête du bloc #{h}", "1. The header of block #{h}"),
                    t(
                        "Un bloc est une page de registre. Son en-tête (212 octets) résume tout le bloc en six champs :",
                        "A block is a ledger page. Its header (212 bytes) sums up the whole block in six fields:",
                    ),
                );
                kv(ui, "version", hd.version.to_string());
                kv(ui, t("bloc précédent", "previous block"), h16(&hd.previous_block_hash));
                kv(ui, "racine de Merkle", h16(&hd.merkle_root));
                kv(ui, t("date", "time"), local_time(hd.timestamp));
                kv(ui, t("cible", "target"), h16(&hd.target));
                kv(ui, "nonce", hd.nonce.to_string());
            }
            1 => {
                step_box(
                    ui,
                    p,
                    t("2. L'empreinte (le « nom ») du bloc", "2. The block's fingerprint (its “name”)"),
                    t(
                        "Les 212 octets de l'en-tête passent deux fois dans la fonction SHA3-512. Le résultat, 64 octets, est le nom du bloc : changer UN seul bit de l'en-tête donne un nom complètement différent.",
                        "The 212 header bytes go twice through SHA3-512. The 64-byte result is the block's name: changing ONE bit of the header gives a completely different name.",
                    ),
                );
                kv(ui, t("empreinte", "fingerprint"), hex(&hd.hash()));
                if h > 0 {
                    let prev_ok = node.chain.lock().unwrap().hash_at(h - 1) == Some(hd.previous_block_hash);
                    ui.colored_label(
                        if prev_ok { p.green } else { p.red },
                        if prev_ok {
                            t("OK : Le « bloc précédent » est bien le bloc #(n−1) : c'est ça qui forme la chaîne.", "OK : The “previous block” is indeed block #(n−1): that is what forms the chain.")
                        } else {
                            t("ERREUR : Le bloc précédent ne correspond pas.", "ERREUR : The previous block does not match.")
                        },
                    );
                }
            }
            2 => {
                step_box(
                    ui,
                    p,
                    t("3. La preuve de travail", "3. Proof of work"),
                    t(
                        "Pour proposer un bloc, un mineur a dû essayer des milliards de nonces. Pour chaque essai on calcule Argon2d, une fonction qui exige 4 Mio de mémoire (elle avantage les ordinateurs ordinaires). Le bloc n'est valable que si ce résultat, lu comme un grand nombre, est plus PETIT que la cible. Vérifier ne demande qu'UN calcul.",
                        "To propose a block, a miner had to try billions of nonces. Each try computes Argon2d, a function that needs 4 MiB of memory (it favours ordinary computers). The block is only valid if the result, read as a big number, is SMALLER than the target. Checking takes ONE computation.",
                    ),
                );
                if self.plus.ex_pow.map(|x| x.0) != Some(h) {
                    self.plus.ex_pow = Some((h, hd.pow()));
                }
                let pow = self.plus.ex_pow.unwrap().1;
                kv(ui, t("résultat Argon2d", "Argon2d result"), h16(&pow));
                kv(ui, t("cible", "target"), h16(&hd.target));
                let ok = hd.meets_target() || h == 0;
                ui.colored_label(p.green, if ok { t("OK : résultat < cible : le travail est prouvé.", "OK : result < target: the work is proven.") } else { "ERREUR" });
                let zeros = pow.iter().take_while(|x| **x == 0).count() * 2 + usize::from(pow.iter().find(|x| **x != 0).is_some_and(|x| *x < 16));
                ui.label(tf!("(le résultat commence par {zeros} zéros hexadécimaux)", "(the result starts with {zeros} hexadecimal zeros)"));
            }
            3 => {
                step_box(
                    ui,
                    p,
                    t("4. La racine de Merkle", "4. The Merkle root"),
                    t(
                        "Chaque transaction a un identifiant (txid). On les associe deux par deux, on recalcule l'empreinte, et ainsi de suite jusqu'à n'en garder qu'une : la racine de Merkle, inscrite dans l'en-tête. Modifier une transaction change la racine, donc l'empreinte du bloc, donc la preuve de travail s'effondre.",
                        "Each transaction has an identifier (txid). They are paired two by two and hashed again, and so on until one is left: the Merkle root, written in the header. Changing a transaction changes the root, hence the block's fingerprint, hence the proof of work collapses.",
                    ),
                );
                let ids: Vec<_> = b.txs.iter().map(|x| x.txid()).collect();
                for (i, id) in ids.iter().enumerate() {
                    kv(ui, &format!("txid #{i}"), h16(id));
                }
                let root = merkle_root(&ids);
                kv(ui, t("racine recalculée", "recomputed root"), h16(&root));
                let ok = root == hd.merkle_root;
                ui.colored_label(if ok { p.green } else { p.red }, if ok { t("OK : identique à l'en-tête", "OK : same as the header") } else { "ERREUR" });
            }
            4 => {
                step_box(
                    ui,
                    p,
                    t("5. Les transactions du bloc", "5. The block's transactions"),
                    t(
                        "La première transaction (« coinbase ») crée la récompense du mineur : aucune entrée, ses sorties valent la récompense du palier + les frais des autres transactions. Les suivantes déplacent des pièces existantes.",
                        "The first transaction (“coinbase”) creates the miner's reward: no input, its outputs equal the tier reward + the other transactions' fees. The others move existing coins.",
                    ),
                );
                for (i, x) in b.txs.iter().enumerate() {
                    let out = x.output_sum().unwrap_or(0);
                    let kind = if x.is_coinbase() { t("coinbase (récompense)", "coinbase (reward)") } else { t("paiement", "payment") };
                    ui.label(format!("#{i}  {kind} — {} entrée(s), {} sortie(s), {}", x.inputs.len(), x.outputs.len(), format_amount(out)));
                }
                let minted = total_before(h);
                ui.label(tf!("Récompense prévue pour ce bloc : {}", "Expected reward for this block: {}", format_amount(block_reward(h, minted))));
            }
            _ => {
                step_box(
                    ui,
                    p,
                    t("6. Le verdict", "6. The verdict"),
                    t(
                        "Ton nœud accepte le bloc si TOUT est vrai : le lien avec le bloc précédent, la preuve de travail, la racine de Merkle, la taille, la récompense exacte, et chaque transaction (signatures valides, pièces non déjà dépensées, montants justes). Au moindre défaut le bloc est jeté, même s'il vient d'un pair « de confiance ».",
                        "Your node accepts the block only if EVERYTHING holds: the link to the previous block, the proof of work, the Merkle root, the size, the exact reward and every transaction (valid signatures, unspent coins, correct amounts). Any flaw and the block is thrown away, even from a “trusted” peer.",
                    ),
                );
                ui.label(t("Passe maintenant en mode « Une transaction » pour voir ce que ça veut dire pour un paiement.", "Now switch to “A transaction” to see what that means for a payment."));
            }
        }
    }

    fn explain_tx(&mut self, ui: &mut egui::Ui, p: &Pal, node: &Arc<Node>, h: u64, b: &crate::block::Block) {
        ui.horizontal(|ui| {
            ui.label(t("Transaction n°", "Transaction #"));
            egui::ComboBox::from_id_salt("ex_tx").selected_text(self.plus.ex_tx.to_string()).show_ui(ui, |ui| {
                for i in 0..b.txs.len() {
                    ui.selectable_value(&mut self.plus.ex_tx, i, i.to_string());
                }
            });
        });
        let idx = self.plus.ex_tx.min(b.txs.len() - 1);
        let tx = &b.txs[idx];
        match self.plus.ex_step {
            0 => {
                step_box(
                    ui,
                    p,
                    t("1. Les entrées : d'où vient l'argent", "1. Inputs: where the money comes from"),
                    t(
                        "Une entrée désigne une pièce précise (une sortie d'une ancienne transaction) que l'expéditeur dépense en entier. Si elle vaut plus que le paiement, la différence revient en « monnaie rendue ».",
                        "An input points to one specific coin (an output of an older transaction) that the sender spends entirely. If it is worth more than the payment, the difference comes back as “change”.",
                    ),
                );
                if tx.is_coinbase() {
                    ui.label(t("Cette transaction est une coinbase : elle n'a pas d'entrée, elle CRÉE la récompense du mineur.", "This is a coinbase: it has no input, it CREATES the miner's reward."));
                }
                for (i, inp) in tx.inputs.iter().enumerate() {
                    if tx.is_coinbase() {
                        break;
                    }
                    let o = self.origin_of(node, h, &inp.prev);
                    let from = match o {
                        Some((a, ad)) => format!("{} — {}", format_amount(a), short_addr(&ad)),
                        None => t("(origine hors des 2000 derniers blocs)", "(origin older than the last 2000 blocks)").to_string(),
                    };
                    kv(ui, &format!("{} #{i}", t("entrée", "input")), format!("{}:{}  ->  {from}", h16(&inp.prev.txid), inp.prev.vout));
                }
            }
            1 => {
                step_box(
                    ui,
                    p,
                    t("2. Les sorties : où va l'argent", "2. Outputs: where the money goes"),
                    t(
                        "Chaque sortie crée une nouvelle pièce pour une adresse. Elle peut être verrouillée jusqu'à une date, ou « retenue » : l'expéditeur peut alors l'annuler avant cette date.",
                        "Each output creates a new coin for an address. It can be locked until a date, or “retained”: the sender can then cancel it before that date.",
                    ),
                );
                for (i, o) in tx.outputs.iter().enumerate() {
                    let mut line = format!("{}  ->  {}", format_amount(o.amount), address_to_string(&o.address));
                    if o.lock_until != 0 {
                        line += &format!("  [{} {}]", t("verrou", "lock"), describe_lock(o.lock_until));
                    }
                    if o.cancel.is_some() {
                        line += &format!("  [{}]", t("annulable", "cancellable"));
                    }
                    kv(ui, &format!("{} #{i}", t("sortie", "output")), line);
                }
                if !tx.memo.is_empty() {
                    kv(ui, "message", String::from_utf8_lossy(&tx.memo).into_owned());
                }
                if let Some(n) = &tx.name_op {
                    kv(ui, t("pseudo", "name"), format!("{}.nfr -> {}", n.name, short_addr(&n.owner)));
                }
            }
            2 => {
                step_box(
                    ui,
                    p,
                    t("3. Les frais", "3. The fee"),
                    t(
                        "Frais = total des entrées − total des sorties. Le mineur les garde : plus ils sont élevés, plus le paiement est servi vite. Interdit : sorties > entrées (ce serait créer de l'argent).",
                        "Fee = total inputs − total outputs. The miner keeps it: the higher, the faster the payment is served. Forbidden: outputs > inputs (that would create money).",
                    ),
                );
                if tx.is_coinbase() {
                    ui.label(t("Une coinbase n'a pas de frais : sa valeur est contrôlée par la règle d'émission.", "A coinbase has no fee: its value is controlled by the issuance rule."));
                } else {
                    let mut total_in = Some(0u64);
                    for inp in &tx.inputs {
                        total_in = match (total_in, self.origin_of(node, h, &inp.prev)) {
                            (Some(s), Some((a, _))) => Some(s + a),
                            _ => None,
                        };
                    }
                    let out = tx.output_sum().unwrap_or(0);
                    match total_in {
                        Some(i) => {
                            kv(ui, t("entrées", "inputs"), format_amount(i));
                            kv(ui, t("sorties", "outputs"), format_amount(out));
                            kv(ui, t("frais", "fee"), format_amount(i.saturating_sub(out)));
                        }
                        None => {
                            ui.label(t("(il manque l'origine d'une entrée pour calculer)", "(an input's origin is missing to compute)"));
                        }
                    }
                }
            }
            3 => {
                step_box(
                    ui,
                    p,
                    t("4. La signature post-quantique", "4. The post-quantum signature"),
                    t(
                        "Pour prouver qu'il a le droit de dépenser, l'expéditeur signe la transaction avec sa clé secrète (ML-DSA-87, norme FIPS 204). Il joint sa clé publique (2 592 octets) et la signature (4 627 octets). L'adresse n'est que l'empreinte SHA3-512 de la clé publique : ton nœud vérifie donc (a) que l'empreinte de la clé publique est bien l'adresse de la pièce, (b) que la signature est valide. Un ordinateur quantique ne casse pas ce type de signature.",
                        "To prove the right to spend, the sender signs the transaction with their secret key (ML-DSA-87, FIPS 204). They attach their public key (2,592 bytes) and the signature (4,627 bytes). The address is just the SHA3-512 fingerprint of the public key: your node checks (a) that the public key's fingerprint is the coin's address, (b) that the signature is valid. A quantum computer does not break this kind of signature.",
                    ),
                );
                for (i, inp) in tx.inputs.iter().enumerate().filter(|_| !tx.is_coinbase()) {
                    if let Some(w) = &inp.multi {
                        kv(ui, &format!("{} #{i}", t("entrée", "input")), tf!("groupe {} sur {} — {} signature(s)", "group {} of {} — {} signature(s)", w.m, w.members.len(), w.sigs.len()));
                    } else {
                        kv(ui, &format!("{} #{i}", t("clé publique", "public key")), format!("{} octets, {}", inp.pubkey.len(), h16(&inp.pubkey)));
                        kv(ui, &format!("{} #{i}", t("signature", "signature")), format!("{} octets, {}", inp.signature.len(), h16(&inp.signature)));
                        kv(ui, &format!("{} #{i}", t("adresse", "address")), short_addr(&address_of_pubkey(&inp.pubkey)));
                    }
                }
                if tx.is_coinbase() {
                    ui.label(t("Une coinbase n'a pas de signature.", "A coinbase has no signature."));
                }
            }
            4 => {
                step_box(
                    ui,
                    p,
                    t("5. Ce qui est signé", "5. What is signed"),
                    t(
                        "On ne signe pas les signatures elles-mêmes : on signe un « résumé » (sighash) de tout le reste de la transaction (pièces dépensées, destinataires, montants, message). Si quelqu'un change le montant ou l'adresse en route, la signature ne correspond plus et la transaction est rejetée.",
                        "The signatures themselves are not signed: a “digest” (sighash) of everything else in the transaction is (coins spent, recipients, amounts, message). If anyone changes the amount or address on the way, the signature no longer matches and the transaction is rejected.",
                    ),
                );
                kv(ui, "sighash", hex(&tx.sighash()));
            }
            _ => {
                step_box(
                    ui,
                    p,
                    t("6. L'identifiant (txid) et la taille", "6. The identifier (txid) and size"),
                    t(
                        "Le txid est l'empreinte SHA3-512 (double) de la transaction complète. C'est lui qui entre dans l'arbre de Merkle, et que les pièces futures citeront pour dépenser les sorties de celle-ci.",
                        "The txid is the (double) SHA3-512 fingerprint of the complete transaction. It goes into the Merkle tree, and future coins cite it to spend this one's outputs.",
                    ),
                );
                kv(ui, "txid", hex(&tx.txid()));
                kv(ui, t("taille", "size"), tf!("{} octets (une signature post-quantique est lourde : c'est pour ça que les frais se calculent à la taille)", "{} bytes (a post-quantum signature is heavy: that is why fees depend on size)", tx.size()));
            }
        }
    }

    // ------------------------------------------------------------------ Avancé
    fn run_tx_job(&mut self, ctx: &egui::Context, label: &str, ok_msg: String, code: Zeroizing<String>, f: impl FnOnce(&mut Wallet, &crate::chain::Chain, &crate::mempool::Mempool) -> Result<Transaction, String> + Send + 'static) {
        let node = self.node.clone().unwrap();
        self.spawn(label, ctx, move || {
            // Code de dépense ouvert AVANT de verrouiller la chaîne, le mempool et le portefeuille.
            if let Err(e) = node.prepare_spend(&code) {
                return JobResult::Err(e);
            }
            let tx = {
                let c = node.chain.lock().unwrap();
                let mp = node.mempool.lock().unwrap();
                let mut w = node.wallet.lock().unwrap();
                let r = f(&mut w, &c, &mp);
                w.clear_pre_seed();
                r
            };
            match tx.and_then(|tx| node.submit_tx(tx)) {
                Ok(()) => JobResult::Sent(ok_msg),
                Err(e) => JobResult::Err(e),
            }
        });
    }

    fn run_text_job(&mut self, ctx: &egui::Context, label: &str, f: impl FnOnce(&Arc<Node>) -> Result<(String, String), String> + Send + 'static) {
        let node = self.node.clone().unwrap();
        self.spawn(label, ctx, move || match f(&node) {
            Ok((kind, text)) => JobResult::Text(kind, text),
            Err(e) => JobResult::Err(e),
        });
    }

    pub(super) fn plus_output(&mut self, kind: String, text: String) {
        match kind.as_str() {
            "proposal" => self.plus.ms_text = text,
            "proof" => self.plus.reserve_proof = text,
            _ => {}
        }
        self.info = Some(t("Fait.", "Done.").to_string());
    }

    pub(super) fn advanced_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.pal();
        let node = self.node.clone().unwrap();
        let busy = self.job.is_some();
        let (frozen, protection, groups, retained, names) = {
            let c = node.chain.lock().unwrap();
            let w = node.wallet.lock().unwrap();
            (w.is_frozen(), w.protection().cloned(), w.groups().to_vec(), w.retained_by_me(&c), w.my_names(&c))
        };
        if !self.plus.prot_loaded {
            self.plus.prot_loaded = true;
            if let Some(pr) = &protection {
                self.plus.prot_threshold = format_amount(pr.threshold);
                self.plus.prot_delay = format!("{}min", pr.delay_secs / 60);
                self.plus.prot_guardian = pr.guardian.map(|g| address_to_string(&g)).unwrap_or_default();
            } else {
                self.plus.prot_delay = "1j".into();
            }
        }
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Fonctions avancées", "Advanced features")).strong());
            ui.label(t("Le code de dépense ci-dessous sert aux opérations de cet onglet qui signent ou ouvrent le coffre.", "The spending code below is used by this tab's operations that sign or open the vault."));
            password_field(ui, spend_label(), &mut self.plus.code);
            error_line(ui, &p, &self.error);
            info_line(ui, &p, &self.info);
            if let Some(j) = &self.job {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(&j.label);
                });
            }
        });

        // ---- Gel
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Gel du portefeuille", "Wallet freeze")).strong());
            if frozen {
                ui.colored_label(p.orange, t("GELÉ : plus aucun envoi n'est possible depuis cet ordinateur, même avec tes mots de passe. Recevoir et miner continuent.", "FROZEN: nothing can be sent from this computer, even with your passwords. Receiving and mining continue."));
                ui.label(t("Pour dégeler il faut les TROIS codes : mot de passe d'ouverture, nouveau code de dépense, et deux morceaux du code de secours.", "To unfreeze you need ALL THREE codes: opening password, a new spending code, and two recovery pieces."));
                password_field(ui, open_label(), &mut self.plus.unfreeze_open);
                password_field(ui, t("NOUVEAU code de dépense", "NEW spending code"), &mut self.plus.unfreeze_spend);
                password_field(ui, t("Morceau de secours 1", "Recovery piece 1"), &mut self.plus.unfreeze_a);
                password_field(ui, t("Morceau de secours 2", "Recovery piece 2"), &mut self.plus.unfreeze_b);
                let ok = !busy && [&self.plus.unfreeze_open, &self.plus.unfreeze_spend, &self.plus.unfreeze_a, &self.plus.unfreeze_b].iter().all(|s| !s.is_empty());
                if ui.add_enabled(ok, egui::Button::new(t("Dégeler", "Unfreeze"))).clicked() {
                    let n = node.clone();
                    let (o, s, a, b) = (
                        Zeroizing::new(std::mem::take(&mut self.plus.unfreeze_open)),
                        Zeroizing::new(std::mem::take(&mut self.plus.unfreeze_spend)),
                        Zeroizing::new(std::mem::take(&mut self.plus.unfreeze_a)),
                        Zeroizing::new(std::mem::take(&mut self.plus.unfreeze_b)),
                    );
                    self.spawn(t("Dégel (quelques secondes)…", "Unfreezing (a few seconds)…"), ctx, move || match n.wallet.lock().unwrap().unfreeze(&o, &s, &a, &b) {
                        Ok(()) => JobResult::Info(t("Portefeuille dégelé. Ton nouveau code de dépense est actif.", "Wallet unfrozen. Your new spending code is active.").into()),
                        Err(e) => JobResult::Err(e),
                    });
                }
            } else {
                ui.label(t(
                    "Gèle ton portefeuille quand tu pars en voyage ou que tu n'as pas besoin de dépenser : la clé secrète est EFFACÉE de cet ordinateur. Un voleur qui aurait même tes deux mots de passe ne pourrait rien envoyer.",
                    "Freeze your wallet when travelling or when you do not need to spend: the secret key is ERASED from this computer. A thief with even both passwords could send nothing.",
                ));
                ui.colored_label(p.orange, t("Assure-toi d'avoir tes morceaux de secours : sans eux, le dégel est impossible.", "Make sure you have your recovery pieces: without them, unfreezing is impossible."));
                if ui.add_enabled(!busy && !self.plus.code.is_empty(), egui::Button::new(t("Geler le portefeuille", "Freeze the wallet"))).clicked() {
                    let n = node.clone();
                    let code = Zeroizing::new(std::mem::take(&mut self.plus.code));
                    self.spawn(t("Gel (quelques secondes)…", "Freezing (a few seconds)…"), ctx, move || {
                        if let Err(e) = n.prepare_spend(&code) {
                            return JobResult::Err(e);
                        }
                        let r = n.wallet.lock().unwrap().freeze(&code);
                        n.clear_spend();
                        match r {
                            Ok(()) => JobResult::Info(t("Portefeuille gelé.", "Wallet frozen.").into()),
                            Err(e) => JobResult::Err(e),
                        }
                    });
                }
            }
        });

        // ---- Protection des gros paiements
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Délai d'annulation des gros paiements", "Cancellation delay for large payments")).strong());
            ui.label(t(
                "Au-dessus du montant choisi, chaque paiement est RETENU : le destinataire ne peut le dépenser qu'après le délai, et toi (ou un « gardien » de confiance) peux l'annuler d'ici là. Si un voleur t'envoie à une mauvaise adresse ou vide ton portefeuille, tu as le temps de réagir.",
                "Above the chosen amount, each payment is HELD: the recipient can only spend it after the delay, and you (or a trusted “guardian”) can cancel it until then. If a thief sends to a wrong address or drains your wallet, you have time to react.",
            ));
            ui.horizontal(|ui| {
                ui.label(t("À partir de", "From"));
                ui.add(egui::TextEdit::singleline(&mut self.plus.prot_threshold).desired_width(100.0));
                ui.label("NFR   ");
                ui.label(t("délai", "delay"));
                ui.add(egui::TextEdit::singleline(&mut self.plus.prot_delay).desired_width(70.0));
                ui.label(RichText::new(t("ex. 30min, 12h, 1j, 1sem (max 30 j)", "e.g. 30min, 12h, 1d, 1w (max 30 d)")).color(p.grey));
            });
            ui.horizontal(|ui| {
                ui.label(t("Gardien (facultatif)", "Guardian (optional)"));
                ui.add(egui::TextEdit::singleline(&mut self.plus.prot_guardian).desired_width(420.0).hint_text("NFR1-…"));
            });
            ui.label(RichText::new(t("Un gardien peut annuler à ta place, mais pas toi : utile si tu crains d'être forcé ou piraté.", "A guardian can cancel instead of you, and you cannot: useful if you fear coercion or hacking.")).color(p.grey));
            ui.label(RichText::new(t(
                "Un paiement annulé par le gardien te revient toujours (règle du réseau à partir du 9 novembre 2026 ; avant cette date, le gardien peut l'envoyer ailleurs). Le code de dépense ci-dessus est demandé pour changer ces réglages.",
                "A payment cancelled by the guardian always comes back to you (network rule from 9 November 2026; before that date, the guardian can send it elsewhere). The spending code above is required to change these settings.",
            ))
            .color(p.orange));
            ui.horizontal(|ui| {
                if ui.add_enabled(!busy && !self.plus.code.is_empty(), egui::Button::new(t("Enregistrer", "Save"))).clicked() {
                    let r = (|| {
                        let th = parse_amount(&self.plus.prot_threshold)?;
                        let d = parse_lock_duration(&self.plus.prot_delay)?;
                        let g = if self.plus.prot_guardian.trim().is_empty() { None } else { Some(crate::wallet::parse_address(&self.plus.prot_guardian)?) };
                        node.wallet.lock().unwrap().set_protection(Some(Protection { threshold: th, delay_secs: d, guardian: g }), Some(&self.plus.code))
                    })();
                    match r {
                        Ok(()) => self.info = Some(t("Protection enregistrée.", "Protection saved.").into()),
                        Err(e) => self.error = Some(e),
                    }
                }
                if protection.is_some() && ui.add_enabled(!busy && !self.plus.code.is_empty(), egui::Button::new(t("Désactiver", "Disable"))).clicked() {
                    match node.wallet.lock().unwrap().set_protection(None, Some(&self.plus.code)) {
                        Ok(()) => {
                            self.info = Some(t("Protection désactivée.", "Protection disabled.").into());
                            self.plus.prot_loaded = false;
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
            });
            match &protection {
                Some(pr) => ui.colored_label(p.green, tf!("Active : dès {} NFR, retenue de {} s.", "Active: from {} NFR, held for {} s.", format_amount(pr.threshold), pr.delay_secs)),
                None => ui.colored_label(p.grey, t("Désactivée.", "Disabled.")),
            };
            if !retained.is_empty() {
                ui.separator();
                ui.label(RichText::new(t("Paiements encore annulables", "Payments you can still cancel")).strong());
                for r in &retained {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(tf!("{} -> {}, déblocage {}", "{} -> {}, unlocks {}", format_amount(r.amount), short_addr(&r.to), describe_lock(r.unlock)));
                        if ui.add_enabled(!busy && !self.plus.code.is_empty() && !frozen, egui::Button::new(t("Annuler", "Cancel"))).clicked() {
                            let code = Zeroizing::new(self.plus.code.clone());
                            let op = r.op;
                            self.run_tx_job(ctx, t("Annulation…", "Cancelling…"), t("Paiement annulé : les fonds reviennent sur ton portefeuille.", "Payment cancelled: the funds return to your wallet.").into(), code.clone(), move |w, c, mp| w.cancel_retained(c, mp, op, Some(&code)));
                        }
                    });
                }
            }
        });

        // ---- Pseudos
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Pseudos (nom.nfr)", "Names (name.nfr)")).strong());
            ui.label(t(
                "Au lieu de donner une adresse de 77 caractères, donne « alice.nfr ». Le pseudo est inscrit dans la chaîne (3 à 32 caractères : lettres minuscules, chiffres, tiret). Il coûte des frais uniques : 100 NFR pour 3 lettres, 25 pour 4, 5 pour 5 à 7, 1 NFR à partir de 8.",
                "Instead of giving a 77-character address, give “alice.nfr”. The name is written in the chain (3 to 32 characters: lowercase letters, digits, hyphen). One-time fee: 100 NFR for 3 letters, 25 for 4, 5 for 5 to 7, 1 NFR from 8.",
            ));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.plus.name_input).desired_width(220.0).hint_text("alice"));
                ui.label(".nfr");
                let cost = Wallet::name_cost(&self.plus.name_input);
                if !self.plus.name_input.trim().is_empty() {
                    ui.label(tf!("frais : {}", "fee: {}", format_amount(cost)));
                }
                if ui.add_enabled(!busy && !frozen && !self.plus.code.is_empty() && !self.plus.name_input.trim().is_empty(), egui::Button::new(t("Réserver", "Register"))).clicked() {
                    let (code, name) = (Zeroizing::new(self.plus.code.clone()), self.plus.name_input.clone());
                    let msg = tf!("Pseudo demandé : il sera actif dans quelques minutes (dès qu'un bloc le contient).", "Name requested: it will be active in a few minutes (once a block contains it).");
                    self.plus.name_input.clear();
                    self.run_tx_job(ctx, t("Signature…", "Signing…"), msg, code.clone(), move |w, c, mp| w.register_name(c, mp, &name, Some(&code)));
                }
            });
            for (n, h) in &names {
                ui.label(format!("{n}.nfr  ({} #{h})", t("depuis le bloc", "since block")));
            }
            if !names.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(t("Transférer le pseudo", "Transfer the name"));
                    egui::ComboBox::from_id_salt("pseudo_t").selected_text(if self.plus.name_target.is_empty() { "—".to_string() } else { self.plus.name_target.clone() }).show_ui(ui, |ui| {
                        for (n, _) in &names {
                            ui.selectable_value(&mut self.plus.name_target, n.clone(), n);
                        }
                    });
                    ui.add(egui::TextEdit::singleline(&mut self.plus.ms_to).desired_width(320.0).hint_text(t("vers : NFR1-… ou nom du carnet", "to: NFR1-… or contact name")));
                    if ui.add_enabled(!busy && !frozen && !self.plus.code.is_empty() && !self.plus.name_target.is_empty(), egui::Button::new(t("Transférer", "Transfer"))).clicked() {
                        let dest = node.wallet.lock().unwrap().resolve_recipient(&self.plus.ms_to);
                        match dest {
                            Ok(d) => {
                                let (code, name) = (Zeroizing::new(self.plus.code.clone()), self.plus.name_target.clone());
                                self.run_tx_job(ctx, t("Signature…", "Signing…"), t("Transfert envoyé.", "Transfer sent.").into(), code.clone(), move |w, c, mp| w.transfer_name(c, mp, &name, d, Some(&code)));
                            }
                            Err(e) => self.error = Some(e),
                        }
                    }
                });
            }
        });

        // ---- Groupes / multi-signature
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Groupes à plusieurs signatures (multi-signature)", "Multi-signature groups")).strong());
            ui.label(t(
                "Un groupe M sur N : N personnes partagent une adresse, et il faut l'accord de M d'entre elles pour dépenser (par exemple 2 sur 3 : toi, ton père, ta mère). Chacun garde sa propre clé : personne ne peut tout seul.",
                "An M-of-N group: N people share an address, and M of them must agree to spend (for example 2 of 3: you, your father, your mother). Everyone keeps their own key: nobody can alone.",
            ));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.plus.group_name).desired_width(120.0).hint_text(t("nom du groupe", "group name")));
                ui.label("M =");
                ui.add(egui::TextEdit::singleline(&mut self.plus.group_m).desired_width(30.0).hint_text("2"));
            });
            ui.label(t("Adresses des membres (une par ligne, la tienne comprise ; tu peux écrire un nom du carnet)", "Members' addresses (one per line, yours included; contact names allowed)"));
            ui.add(egui::TextEdit::multiline(&mut self.plus.group_members).desired_rows(3).desired_width(560.0));
            if ui.add_enabled(!busy, egui::Button::new(t("Créer le groupe", "Create the group"))).clicked() {
                let r = (|| {
                    let m: u8 = self.plus.group_m.trim().parse().map_err(|_| t("M doit être un nombre", "M must be a number").to_string())?;
                    let mut w = node.wallet.lock().unwrap();
                    let members: Result<Vec<Address>, String> = self.plus.group_members.lines().filter(|l| !l.trim().is_empty()).map(|l| w.resolve_recipient(l)).collect();
                    w.add_group(&self.plus.group_name, m, &members?)
                })();
                match r {
                    Ok(a) => {
                        self.info = Some(tf!("Groupe créé. Adresse du groupe : {}", "Group created. Group address: {}", address_to_string(&a)));
                        self.plus.group_name.clear();
                        self.plus.group_members.clear();
                    }
                    Err(e) => self.error = Some(e),
                }
            }
            for g in &groups {
                ui.separator();
                let (avail, other) = {
                    let c = node.chain.lock().unwrap();
                    let mp = node.mempool.lock().unwrap();
                    node.wallet.lock().unwrap().group_balance(&c, &mp, g)
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("{} ({} / {})", g.name, g.m, g.members.len())).strong());
                    ui.label(tf!("disponible {}, en attente {}", "available {}, pending {}", format_amount(avail), format_amount(other)));
                    if ui.small_button(t("Copier l'adresse", "Copy address")).clicked() {
                        ui.ctx().copy_text(wallet_plus::group_address_string(g));
                    }
                    if ui.small_button(t("Supprimer", "Delete")).clicked() {
                        let _ = node.wallet.lock().unwrap().remove_group(&g.name);
                    }
                });
                ui.label(RichText::new(wallet_plus::group_address_string(g)).monospace().small());
            }
            if !groups.is_empty() {
                ui.separator();
                ui.label(RichText::new(t("1) Proposer un paiement du groupe", "1) Propose a group payment")).strong());
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("ms_group").selected_text(if self.plus.ms_group.is_empty() { "—".to_string() } else { self.plus.ms_group.clone() }).show_ui(ui, |ui| {
                        for g in &groups {
                            ui.selectable_value(&mut self.plus.ms_group, g.name.clone(), &g.name);
                        }
                    });
                    ui.add(egui::TextEdit::singleline(&mut self.plus.ms_amount).desired_width(90.0).hint_text(t("montant", "amount")));
                });
                ui.add(egui::TextEdit::singleline(&mut self.plus.ms_memo).desired_width(420.0).hint_text(t("message (facultatif)", "message (optional)")));
                if ui.add_enabled(!busy && !self.plus.ms_group.is_empty(), egui::Button::new(t("Préparer la proposition", "Prepare the proposal"))).clicked() {
                    let r = (|| {
                        let c = node.chain.lock().unwrap();
                        let mp = node.mempool.lock().unwrap();
                        let w = node.wallet.lock().unwrap();
                        let to = w.resolve_recipient_with(&self.plus.ms_to, &c)?;
                        w.ms_propose(&c, &mp, &self.plus.ms_group, to, parse_amount(&self.plus.ms_amount)?, &self.plus.ms_memo)
                    })();
                    match r {
                        Ok(text) => {
                            self.plus.ms_text = text;
                            self.info = Some(t("Proposition prête : envoie-la aux autres membres (le destinataire est celui du champ « vers » ci-dessus).", "Proposal ready: send it to the other members (the recipient is the “to” field above).").into());
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                ui.label(RichText::new(t("2) Relire, signer, puis 3) envoyer", "2) Review, sign, then 3) send")).strong());
                ui.add(egui::TextEdit::multiline(&mut self.plus.ms_text).desired_rows(3).desired_width(560.0).hint_text("NFRMS1-…"));
                if !self.plus.ms_text.trim().is_empty() {
                    let info = {
                        let c = node.chain.lock().unwrap();
                        node.wallet.lock().unwrap().ms_info(&self.plus.ms_text, &c)
                    };
                    match info {
                        Ok(i) => {
                            for (a, v) in &i.outputs {
                                ui.label(format!("-> {}  {}", format_amount(*v), short_addr(a)));
                            }
                            if !i.memo.is_empty() {
                                ui.label(format!("message : « {} »", i.memo));
                            }
                            if let Some(f) = i.fee {
                                ui.label(tf!("frais : {}", "fee: {}", format_amount(f)));
                            }
                            let (have, need) = i.signatures.first().copied().unwrap_or((0, 0));
                            ui.label(tf!("signatures : {} sur {} nécessaires", "signatures: {} of {} needed", have, need));
                            ui.horizontal(|ui| {
                                let can_sign = !busy && i.i_am_member && !i.i_signed && !i.ready && !frozen && !self.plus.code.is_empty();
                                if ui.add_enabled(can_sign, egui::Button::new(t("Signer", "Sign"))).clicked() {
                                    let (text, code) = (self.plus.ms_text.clone(), Zeroizing::new(self.plus.code.clone()));
                                    self.run_text_job(ctx, t("Signature…", "Signing…"), move |n| {
                                        n.prepare_spend(&code)?;
                                        let r = n.wallet.lock().unwrap().ms_sign(&text, Some(&code));
                                        n.clear_spend();
                                        r.map(|s| ("proposal".to_string(), s))
                                    });
                                }
                                if i.i_signed {
                                    ui.colored_label(p.green, t("OK : tu as signé", "OK : you signed"));
                                }
                                if ui.add_enabled(!busy && i.ready, egui::Button::new(t("Envoyer au réseau", "Broadcast"))).clicked() {
                                    match wallet_plus::finalize_proposal(&self.plus.ms_text).and_then(|tx| node.submit_tx(tx)) {
                                        Ok(()) => {
                                            self.info = Some(t("Paiement du groupe envoyé.", "Group payment sent.").into());
                                            self.plus.ms_text.clear();
                                        }
                                        Err(e) => self.error = Some(e),
                                    }
                                }
                                if ui.small_button(t("Copier", "Copy")).clicked() {
                                    ui.ctx().copy_text(self.plus.ms_text.clone());
                                }
                            });
                        }
                        Err(e) => {
                            ui.colored_label(p.red, e);
                        }
                    }
                }
            }
        });

        // ---- Preuve de réserve
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Preuve de réserve", "Proof of reserve")).strong());
            ui.label(t(
                "Prouve que tu détiens AU MOINS un montant, sans montrer le reste de tes adresses ni ton solde exact. Chaque adresse citée signe un message qui contient le dernier bloc connu et un mot choisi par celui qui te le demande (pour qu'une vieille preuve ne serve pas deux fois).",
                "Prove you hold AT LEAST an amount, without showing your other addresses or exact balance. Each cited address signs a message containing the latest known block and a word chosen by whoever asks you (so an old proof cannot be reused).",
            ));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.plus.reserve_amount).desired_width(110.0).hint_text(t("au moins…", "at least…")));
                ui.label("NFR");
                ui.add(egui::TextEdit::singleline(&mut self.plus.reserve_challenge).desired_width(200.0).hint_text(t("mot demandé", "requested word")));
                if ui.add_enabled(!busy && !frozen && !self.plus.code.is_empty(), egui::Button::new(t("Créer la preuve", "Create the proof"))).clicked() {
                    match parse_amount(&self.plus.reserve_amount) {
                        Ok(a) => {
                            let (code, ch) = (Zeroizing::new(self.plus.code.clone()), self.plus.reserve_challenge.clone());
                            self.run_text_job(ctx, t("Signature…", "Signing…"), move |n| {
                                n.prepare_spend(&code)?;
                                let r = {
                                    let c = n.chain.lock().unwrap();
                                    n.wallet.lock().unwrap().prove_reserve(&c, a, &ch, Some(&code))
                                };
                                n.clear_spend();
                                r.map(|s| ("proof".to_string(), s))
                            });
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
            });
            if !self.plus.reserve_proof.is_empty() {
                let mut shown = self.plus.reserve_proof.clone();
                ui.add(egui::TextEdit::multiline(&mut shown).desired_rows(2).desired_width(560.0));
                if ui.small_button(t("Copier la preuve", "Copy the proof")).clicked() {
                    ui.ctx().copy_text(self.plus.reserve_proof.clone());
                }
            }
            ui.separator();
            ui.label(t("Vérifier la preuve de quelqu'un d'autre (ton nœud contrôle tout lui-même) :", "Check someone else's proof (your node checks everything itself):"));
            ui.add(egui::TextEdit::multiline(&mut self.plus.verify_text).desired_rows(2).desired_width(560.0).hint_text("NFRPROOF1-…"));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.plus.verify_challenge).desired_width(200.0).hint_text(t("mot que tu avais demandé", "word you asked for")));
                if ui.button(t("Vérifier", "Check")).clicked() {
                    let c = node.chain.lock().unwrap();
                    let ch = self.plus.verify_challenge.trim();
                    self.plus.verify_result = Some(verify_reserve(&self.plus.verify_text, &c, if ch.is_empty() { None } else { Some(ch) }).map(|i| {
                        tf!(
                            "OK : Prouvé : au moins {} sur {} adresse(s), au bloc #{} (il y a {} blocs).",
                            "OK : Proven: at least {} on {} address(es), at block #{} ({} blocks ago).",
                            format_amount(i.claimed),
                            i.addresses.len(),
                            i.height,
                            i.age_blocks
                        )
                    }));
                }
            });
            match &self.plus.verify_result {
                Some(Ok(m)) => {
                    ui.colored_label(p.green, m);
                }
                Some(Err(e)) => {
                    ui.colored_label(p.red, e);
                }
                None => {}
            }
        });

        // ---- Demande de paiement
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Demande de paiement", "Payment request")).strong());
            ui.label(t("Crée un lien (et un QR code) avec ton adresse, un montant et un message. La personne le colle dans l'onglet Envoyer.", "Create a link (and QR code) with your address, an amount and a message. The payer pastes it in the Send tab."));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.plus.req_amount).desired_width(100.0).hint_text(t("montant", "amount")));
                ui.add(egui::TextEdit::singleline(&mut self.plus.req_message).desired_width(360.0).hint_text(t("message (ex. Merci pour le déjeuner)", "message (e.g. Thanks for lunch)")));
            });
            let to = names.first().map(|n| format!("{}.nfr", n.0)).unwrap_or_else(|| address_to_string(&node.wallet.lock().unwrap().keys[0].0));
            let amount = if self.plus.req_amount.trim().is_empty() { Ok(None) } else { parse_amount(&self.plus.req_amount).map(Some) };
            match amount {
                Ok(a) if self.plus.req_message.len() <= MAX_MEMO => {
                    let uri = payment_uri(&to, a, &self.plus.req_message);
                    self.plus.req_to = uri.clone();
                    ui.label(RichText::new(&uri).monospace().small());
                    if ui.small_button(t("Copier le lien", "Copy the link")).clicked() {
                        ui.ctx().copy_text(uri.clone());
                    }
                    qr_ui(ui, &uri);
                }
                Ok(_) => {
                    ui.colored_label(p.red, t("message trop long", "message too long"));
                }
                Err(e) => {
                    ui.colored_label(p.red, e);
                }
            }
        });

        // ---- Démarrage automatique
        card(ui, &p, |ui| {
            ui.label(RichText::new(t("Démarrage automatique et arrière-plan", "Automatic start and background")).strong());
            ui.label(t(
                "NumFranc peut s'ouvrir tout seul quand tu ouvres ta session, fenêtre réduite : le nœud reste allumé et aide le réseau, le minage continue. Il faut quand même taper ton mot de passe d'ouverture (pour que ton portefeuille reste protégé). Fermer la fenêtre arrête NumFranc ; réduis-la plutôt.",
                "NumFranc can open by itself when you log in, window minimized: the node stays on and helps the network, mining continues. Your opening password is still required (to keep your wallet protected). Closing the window stops NumFranc; minimize it instead.",
            ));
            if self.settings.permanent {
                ui.label(RichText::new(t(
                    "Remplacé par « Toujours allumé » (Réglages) : NumFranc démarre déjà avec l'ordinateur et continue sans la fenêtre.",
                    "Replaced by « Always on » (Settings): NumFranc already starts with the computer and keeps running without the window.",
                ))
                .color(p.green));
                return;
            }
            let on = *self.plus.autostart.get_or_insert_with(crate::install::autostart_enabled);
            let mut v = on;
            if ui.checkbox(&mut v, t("Démarrer NumFranc à l'ouverture de la session", "Start NumFranc at login")).changed() {
                match crate::install::set_autostart(v, &self.opts.data_dir) {
                    Ok(m) => {
                        self.info = Some(m);
                        self.plus.autostart = Some(v);
                    }
                    Err(e) => self.error = Some(e),
                }
            }
        });
    }
}
