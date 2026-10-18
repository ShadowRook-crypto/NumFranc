//! macOS : quand on clique sur un lien nfr:…, le système n'envoie pas le lien en argument
//! (comme sous Windows et Linux) mais par un « Apple Event » GetURL adressé à l'application.
//! Ce module installe le récepteur de cet événement et dépose le lien pour la fenêtre,
//! exactement comme install::hand_over_link. Le lien ne fait que remplir le formulaire « Envoyer ».

use objc2::rc::Retained;
use objc2::runtime::NSObject;
use objc2::{AllocAnyThread, define_class, msg_send, sel};
use objc2_foundation::{NSAppleEventDescriptor, NSAppleEventManager};
use std::path::PathBuf;
use std::sync::OnceLock;

static DOSSIER: OnceLock<PathBuf> = OnceLock::new();

/// Code « GURL » : classe et identifiant de l'Apple Event « ouvrir une adresse ».
const GURL: u32 = u32::from_be_bytes(*b"GURL");
/// Mot-clé « ---- » : l'objet direct de l'événement, c'est-à-dire le lien lui-même.
const OBJET_DIRECT: u32 = u32::from_be_bytes(*b"----");

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "NumFrancRecepteurLiens"]
    struct Recepteur;

    impl Recepteur {
        #[unsafe(method(recevoirLien:reponse:))]
        fn recevoir_lien(&self, event: &NSAppleEventDescriptor, _reponse: &NSAppleEventDescriptor) {
            // SAFETY : paramDescriptorForKeyword: prend un mot-clé de 4 caractères (u32) et renvoie un descripteur ou nil.
            let objet: Option<Retained<NSAppleEventDescriptor>> = unsafe { msg_send![event, paramDescriptorForKeyword: OBJET_DIRECT] };
            let Some(lien) = objet.and_then(|d| d.stringValue()) else { return };
            if let Some(dossier) = DOSSIER.get()
                && let Err(e) = crate::install::hand_over_link(dossier, &lien.to_string())
            {
                eprintln!("Lien de paiement ignoré : {e}");
            }
        }
    }
);

/// À appeler une fois, avant d'ouvrir la fenêtre.
pub fn installer(dossier: PathBuf) {
    if DOSSIER.set(dossier).is_err() {
        return;
    }
    let recepteur: Retained<Recepteur> = unsafe { msg_send![Recepteur::alloc(), init] };
    let gestionnaire = NSAppleEventManager::sharedAppleEventManager();
    // SAFETY : le sélecteur correspond à la méthode définie ci-dessus (deux descripteurs, rien en retour),
    // et le récepteur est gardé en vie jusqu'à la fin du programme (le gestionnaire ne le retient pas).
    unsafe {
        let _: () = msg_send![
            &*gestionnaire,
            setEventHandler: &*recepteur,
            andSelector: sel!(recevoirLien:reponse:),
            forEventClass: GURL,
            andEventID: GURL
        ];
    }
    std::mem::forget(recepteur);
}
