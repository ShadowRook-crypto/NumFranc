//! Commandes de la console ajoutées en v0.6.

use super::{ask_secret, describe_lock};
use numfranc::config::*;
use numfranc::emission::{block_reward, total_before};
use numfranc::node::Node;
use numfranc::wallet::{address_to_string, format_amount, parse_address, parse_amount, parse_lock_duration, Protection};
use numfranc::wallet_plus;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const COMMANDS_PLUS: &str = "\
Fonctions avancées :
  emission                    tableau de bord : NFR créés, restants, prochains paliers
  gel                         geler le portefeuille (plus aucun envoi, même avec les mots de passe)
  degel                       dégeler (mot de passe d'ouverture, nouveau code de dépense, 2 morceaux de secours)
  protection SEUIL DÉLAI      retenir les paiements ≥ SEUIL pendant DÉLAI (annulables) ; ex. protection 100 1j
      option : gardien ADRESSE    seul ce gardien pourra annuler
  protection off              désactiver
  retenus                     paiements encore annulables
  annuler N                   annuler le paiement retenu n° N (voir « retenus »)
  pseudos                     vos pseudos
  pseudo reserver NOM         réserver NOM.nfr (frais uniques selon la longueur)
  pseudo transferer NOM DEST  faire pointer NOM.nfr vers une autre adresse
  groupe creer NOM M ADR...   groupe M sur N (adresses ou noms du carnet, la vôtre comprise)
  groupe liste | groupe supprimer NOM
  groupe proposer NOM DEST MONTANT [message TEXTE]   prépare une proposition (texte NFRMS1-…)
  groupe info TEXTE | groupe signer TEXTE | groupe envoyer TEXTE
  preuve creer MONTANT [MOT]  preuve de réserve : vous détenez au moins MONTANT
  preuve verifier TEXTE [MOT] vérifier la preuve de quelqu'un
  demande [MONTANT] [message TEXTE]   lien de paiement nfr:… à donner à celui qui doit vous payer
  demarrage on|off            démarrage automatique à l'ouverture de session";

fn code(node: &Arc<Node>) -> Result<Zeroizing<String>, String> {
    let c = ask_secret("Code de dépense : ");
    // Ouvre le coffre sans rien verrouiller (Argon2) ; l'opération qui suit reprend la graine (voir `submit`).
    node.prepare_spend(&c)?;
    Ok(c)
}

fn submit(node: &Arc<Node>, f: impl FnOnce(&mut numfranc::wallet::Wallet, &numfranc::chain::Chain, &numfranc::mempool::Mempool) -> Result<numfranc::tx::Transaction, String>) -> Result<(), String> {
    let tx = {
        let c = node.chain.lock().unwrap();
        let mp = node.mempool.lock().unwrap();
        let mut w = node.wallet.lock().unwrap();
        let r = f(&mut w, &c, &mp);
        w.clear_pre_seed();
        r?
    };
    node.submit_tx(tx)
}

fn split_message(rest: &[&str]) -> (Vec<String>, String) {
    match rest.iter().position(|w| *w == "message") {
        Some(i) => (rest[..i].iter().map(|s| s.to_string()).collect(), rest[i + 1..].join(" ")),
        None => (rest.iter().map(|s| s.to_string()).collect(), String::new()),
    }
}

/// Renvoie None si la commande n'est pas de celles-ci.
pub fn run(node: &Arc<Node>, parts: &[&str]) -> Option<Result<(), String>> {
    Some(match parts {
        ["emission"] => {
            let h = node.chain.lock().unwrap().height();
            let minted = total_before(h + 1);
            let palier = (h + 1) / PALIER_BLOCKS;
            println!("NFR créés        : {} sur {}", format_amount(minted), format_amount(HARD_CAP));
            println!("NFR restants     : {}", format_amount(HARD_CAP - minted));
            println!("Récompense/bloc  : {}", format_amount(block_reward(h + 1, minted)));
            println!("Palier actuel    : {palier} (prochain dans {} blocs)", PALIER_BLOCKS - (h + 1) % PALIER_BLOCKS);
            for n in palier + 1..palier + 5 {
                let s = n * PALIER_BLOCKS;
                println!("  palier {n:<3} : {} par bloc", format_amount(block_reward(s, total_before(s))));
            }
            Ok(())
        }
        ["gel"] => (|| {
            println!("Le portefeuille sera GELÉ : la clé secrète est effacée de cet ordinateur.");
            println!("Il faudra le mot de passe d'ouverture, un nouveau code de dépense et 2 morceaux de secours pour dégeler.");
            if super::ask("Tapez « geler » pour confirmer : ") != "geler" {
                return Err("annulé".into());
            }
            let c = ask_secret("Code de dépense : ");
            let r = node.wallet.lock().unwrap().freeze(&c);
            node.clear_spend();
            r?;
            println!("Portefeuille gelé.");
            Ok(())
        })(),
        ["degel"] => (|| {
            let o = ask_secret("Mot de passe d'ouverture : ");
            let s = ask_secret("NOUVEAU code de dépense : ");
            let a = ask_secret("Morceau de secours 1 : ");
            let b = ask_secret("Morceau de secours 2 : ");
            node.wallet.lock().unwrap().unfreeze(&o, &s, &a, &b)?;
            println!("Portefeuille dégelé. Le nouveau code de dépense est actif.");
            Ok(())
        })(),
        ["protection"] => {
            match node.wallet.lock().unwrap().protection() {
                Some(p) => println!("Protection : dès {} NFR, retenue {} s{}", format_amount(p.threshold), p.delay_secs, p.guardian.map(|g| format!(", gardien {}", address_to_string(&g))).unwrap_or_default()),
                None => println!("Protection désactivée. Exemple : protection 100 1j"),
            }
            Ok(())
        }
        ["protection", "off"] => (|| {
            let c = code(node)?;
            node.wallet.lock().unwrap().set_protection(None, Some(&c)).map(|_| println!("Protection désactivée."))
        })(),
        ["protection", th, delay, rest @ ..] => (|| {
            let guardian = match rest {
                [] => None,
                ["gardien", a] => Some(parse_address(a)?),
                _ => return Err("usage : protection SEUIL DÉLAI [gardien ADRESSE]".into()),
            };
            let p = Protection { threshold: parse_amount(th)?, delay_secs: parse_lock_duration(delay)?, guardian };
            let c = code(node)?;
            node.wallet.lock().unwrap().set_protection(Some(p), Some(&c))?;
            println!("Protection enregistrée.");
            Ok(())
        })(),
        ["retenus"] => {
            let c = node.chain.lock().unwrap();
            let list = node.wallet.lock().unwrap().retained_by_me(&c);
            if list.is_empty() {
                println!("Aucun paiement annulable.");
            }
            for (i, r) in list.iter().enumerate() {
                println!("{}. {} → {}  déblocage {}", i + 1, format_amount(r.amount), address_to_string(&r.to), describe_lock(r.unlock));
            }
            Ok(())
        }
        ["annuler", n] => (|| {
            let n: usize = n.parse().map_err(|_| "numéro invalide")?;
            let op = {
                let c = node.chain.lock().unwrap();
                let list = node.wallet.lock().unwrap().retained_by_me(&c);
                list.get(n.wrapping_sub(1)).ok_or("numéro inconnu (voir « retenus »)")?.op
            };
            let c = code(node)?;
            submit(node, |w, ch, mp| w.cancel_retained(ch, mp, op, Some(&c)))?;
            println!("Annulation envoyée : les fonds reviennent sur votre portefeuille.");
            Ok(())
        })(),
        ["pseudos"] => {
            let c = node.chain.lock().unwrap();
            let v = node.wallet.lock().unwrap().my_names(&c);
            if v.is_empty() {
                println!("Aucun pseudo. Exemple : pseudo reserver alice");
            }
            for (n, h) in v {
                println!("{n}.nfr  (depuis le bloc #{h})");
            }
            Ok(())
        }
        ["pseudo", "reserver", name] => (|| {
            println!("Frais uniques pour « {name}.nfr » : {}", format_amount(numfranc::wallet::Wallet::name_cost(name)));
            let c = code(node)?;
            let name = name.to_string();
            submit(node, |w, ch, mp| w.register_name(ch, mp, &name, Some(&c)))?;
            println!("Demande envoyée : le pseudo sera actif dès qu'un bloc la contiendra.");
            Ok(())
        })(),
        ["pseudo", "transferer", name, dest] => (|| {
            let to = {
                let c = node.chain.lock().unwrap();
                node.wallet.lock().unwrap().resolve_recipient_with(dest, &c)?
            };
            let c = code(node)?;
            let name = name.to_string();
            submit(node, |w, ch, mp| w.transfer_name(ch, mp, &name, to, Some(&c)))?;
            println!("Transfert envoyé.");
            Ok(())
        })(),
        ["groupe", "creer", name, m, members @ ..] if !members.is_empty() => (|| {
            let m: u8 = m.parse().map_err(|_| "M doit être un nombre")?;
            let mut w = node.wallet.lock().unwrap();
            let list: Result<Vec<_>, String> = members.iter().map(|a| w.resolve_recipient(a)).collect();
            let a = w.add_group(name, m, &list?)?;
            println!("Groupe créé. Adresse du groupe (à donner pour y déposer des NFR) :\n{}", address_to_string(&a));
            Ok(())
        })(),
        ["groupe", "liste"] => {
            let c = node.chain.lock().unwrap();
            let mp = node.mempool.lock().unwrap();
            let w = node.wallet.lock().unwrap();
            if w.groups().is_empty() {
                println!("Aucun groupe.");
            }
            for g in w.groups() {
                let (a, o) = w.group_balance(&c, &mp, g);
                println!("{} ({} sur {})  disponible {}, en attente {}\n  {}", g.name, g.m, g.members.len(), format_amount(a), format_amount(o), wallet_plus::group_address_string(g));
            }
            Ok(())
        }
        ["groupe", "supprimer", name] => node.wallet.lock().unwrap().remove_group(name).map(|_| println!("Groupe supprimé de ce portefeuille (les fonds restent sur l'adresse du groupe).")),
        ["groupe", "proposer", name, dest, amount, rest @ ..] => (|| {
            let (_, memo) = split_message(rest);
            let c = node.chain.lock().unwrap();
            let mp = node.mempool.lock().unwrap();
            let w = node.wallet.lock().unwrap();
            let to = w.resolve_recipient_with(dest, &c)?;
            let text = w.ms_propose(&c, &mp, name, to, parse_amount(amount)?, &memo)?;
            println!("Proposition (à envoyer aux autres membres, qui la signent avec « groupe signer ») :\n{text}");
            Ok(())
        })(),
        ["groupe", "info", text] => (|| {
            let c = node.chain.lock().unwrap();
            let i = node.wallet.lock().unwrap().ms_info(text, &c)?;
            for (a, v) in &i.outputs {
                println!("→ {}  {}", format_amount(*v), address_to_string(a));
            }
            if !i.memo.is_empty() {
                println!("message : « {} »", i.memo);
            }
            match i.fee {
                Some(f) => println!("frais : {}", format_amount(f)),
                None => println!("frais : inconnus (pièce absente de votre chaîne)"),
            }
            println!("signatures : {:?} (présentes, nécessaires) — {}", i.signatures, if i.ready { "COMPLÈTE" } else { "incomplète" });
            println!("vous êtes membre : {} ; vous avez signé : {}", i.i_am_member, i.i_signed);
            Ok(())
        })(),
        ["groupe", "signer", text] => (|| {
            let c = code(node)?;
            let s = node.wallet.lock().unwrap().ms_sign(text, Some(&c));
            node.clear_spend();
            let s = s?;
            println!("Proposition signée par vous (à transmettre au membre suivant ou à envoyer) :\n{s}");
            Ok(())
        })(),
        ["groupe", "envoyer", text] => (|| {
            let tx = wallet_plus::finalize_proposal(text)?;
            node.submit_tx(tx)?;
            println!("Paiement du groupe envoyé.");
            Ok(())
        })(),
        ["preuve", "creer", amount, rest @ ..] => (|| {
            let a = parse_amount(amount)?;
            let c = code(node)?;
            let ch = node.chain.lock().unwrap();
            let proof = node.wallet.lock().unwrap().prove_reserve(&ch, a, &rest.join(" "), Some(&c));
            node.clear_spend();
            let proof = proof?;
            println!("Preuve de réserve (au moins {}) :\n{proof}", format_amount(a));
            Ok(())
        })(),
        ["preuve", "verifier", text, rest @ ..] => (|| {
            let c = node.chain.lock().unwrap();
            let mot = rest.join(" ");
            let i = wallet_plus::verify_reserve(text, &c, if mot.is_empty() { None } else { Some(&mot) })?;
            println!("✔ Prouvé : au moins {} sur {} adresse(s), au bloc #{} (il y a {} blocs).", format_amount(i.claimed), i.addresses.len(), i.height, i.age_blocks);
            Ok(())
        })(),
        ["demande", rest @ ..] => (|| {
            let (head, memo) = split_message(rest);
            let amount = match head.as_slice() {
                [] => None,
                [a] => Some(parse_amount(a)?),
                _ => return Err("usage : demande [MONTANT] [message TEXTE]".into()),
            };
            let c = node.chain.lock().unwrap();
            let w = node.wallet.lock().unwrap();
            let to = w.my_names(&c).first().map(|n| format!("{}.nfr", n.0)).unwrap_or_else(|| address_to_string(&w.keys_main()));
            println!("{}", wallet_plus::payment_uri(&to, amount, &memo));
            Ok(())
        })(),
        ["demarrage", mode @ ("on" | "off")] => numfranc::install::set_autostart(*mode == "on", &node.data_dir()).map(|m| println!("{m}")),
        _ => return None,
    })
}
