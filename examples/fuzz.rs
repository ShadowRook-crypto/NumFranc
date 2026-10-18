//! Tests de résistance (« fuzzing ») : envoie des millions d'entrées abîmées ou aléatoires
//! à tous les décodeurs de NumFranc. Le programme ne doit JAMAIS planter (panic) :
//! une donnée invalide doit toujours donner une erreur propre.
//!
//!   cargo run --release --example fuzz -- 2000000
//!
//! Chaque fil essaie des entrées différentes (graine fixe : les résultats sont reproductibles).

use numfranc::block::Block;
use numfranc::chain::genesis_block;
use numfranc::p2p::{read_message, write_message, Message};
use numfranc::signature::KeyPair;
use numfranc::tx::{address_of_pubkey, normalize_members, NameKind, NameOp, OutPoint, PartialSig, Transaction, TxIn, TxOut};
use std::sync::atomic::{AtomicU64, Ordering};

/// Petit générateur pseudo-aléatoire (xorshift64*), suffisant pour le fuzzing.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Abîme une entrée valide : bits inversés, octets remplacés, coupures, insertions, longueurs géantes.
fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 => v.truncate(rng.below(v.len() + 1)),
            3 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.next() as u8);
            }
            4 if v.len() >= 4 => {
                // Remplace 4 octets par une longueur énorme (piège classique).
                let i = rng.below(v.len() - 3);
                v[i..i + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, rng.next() as u8]);
            }
            5 if v.len() >= 2 => {
                let i = rng.below(v.len() - 1);
                v[i] = 0xFD + rng.below(3) as u8; // marqueurs de varint
            }
            _ => v.extend((0..rng.below(16)).map(|_| rng.next() as u8)),
        }
    }
    v
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let kp = KeyPair::from_seed(&[3; 32]);
    let mut tx = Transaction::new(
        vec![TxIn::single(OutPoint { txid: [9; 64], vout: 1 }, kp.public_key_bytes().to_vec(), vec![0; 4627])],
        vec![
            TxOut::retained(5, address_of_pubkey(b"x"), 1_800_000_000, [8; 32]),
            TxOut::new(7, [1; 32]),
        ],
        "Bonjour".as_bytes().to_vec(),
    );
    tx.name_op = Some(NameOp { kind: NameKind::Register, name: "alice".into(), owner: [4; 32] });
    tx.inputs[0].signature = kp.sign(&tx.sighash()).unwrap().to_vec();
    // Entrée multi-signature (2 sur 3), pour que les mutations visitent aussi ce décodeur.
    let kps: Vec<KeyPair> = (1..=3u8).map(|i| KeyPair::from_seed(&[i; 32])).collect();
    let members = normalize_members(2, &kps.iter().map(|k| address_of_pubkey(&k.public_key_bytes())).collect::<Vec<_>>()).unwrap();
    let mut mtx = Transaction::new(vec![TxIn::multisig(OutPoint { txid: [7; 64], vout: 0 }, 2, members.clone())], vec![TxOut::new(9, [2; 32])], Vec::new());
    let sh = mtx.sighash();
    let mut sigs: Vec<PartialSig> = kps[..2]
        .iter()
        .map(|k| PartialSig {
            index: members.iter().position(|m| *m == address_of_pubkey(&k.public_key_bytes())).unwrap() as u8,
            pubkey: k.public_key_bytes().to_vec(),
            signature: k.sign(&sh).unwrap().to_vec(),
        })
        .collect();
    sigs.sort_by_key(|s| s.index);
    mtx.inputs[0].multi.as_mut().unwrap().sigs = sigs;
    let mut block = genesis_block();
    block.txs.push(tx.clone());
    let mut msgs = Vec::new();
    for m in [
        Message::Version { version: 4, height: 42, listen_port: 6910, nonce: 7 },
        Message::GetBlocks(vec![[1; 64], [2; 64]]),
        Message::Addr(vec!["1.2.3.4:6910".into()]),
        Message::Block(block.clone()),
        Message::Tx(tx.clone()),
        Message::Tx(mtx.clone()),
    ] {
        let mut b = Vec::new();
        write_message(&mut b, &m).unwrap();
        msgs.push(b);
    }
    let hexed = |p: &str, b: &[u8]| format!("{p}{}", numfranc::encoding::hex(b)).into_bytes();
    let mut out = vec![
        ("lien de paiement", b"nfr:NFR1-abcdef?amount=12.5&message=Merci%20%C3%A0%20toi".to_vec()),
        ("proposition multi-signature", hexed("NFRMS1-", &mtx.serialize())),
        ("preuve de réserve", hexed("NFRPROOF1-", &[7u8; 200])),
    ];
    out.push(("transaction", tx.serialize()));
    out.push(("transaction multi-signature", mtx.serialize()));
    out.push(("bloc", block.serialize()));
    for m in msgs {
        out.push(("message réseau", m));
    }
    out
}

fn main() {
    let total: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2) as u64;
    let base = samples();
    let done = AtomicU64::new(0);
    let start = std::time::Instant::now();
    std::thread::scope(|s| {
        for t in 0..threads {
            let (base, done) = (&base, &done);
            s.spawn(move || {
                let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (t + 1).wrapping_mul(0xD1B5_4A32_D192_ED03));
                let per = total / threads;
                let chain = numfranc::chain::Chain::with_genesis(genesis_block());
                for i in 0..per {
                    let (kind, sample) = &base[rng.below(base.len())];
                    // 1 fois sur 8 : octets entièrement aléatoires.
                    let data = if i % 8 == 0 {
                        (0..rng.below(300)).map(|_| rng.next() as u8).collect()
                    } else {
                        mutate(&mut rng, sample)
                    };
                    let r = std::panic::catch_unwind(|| {
                        let _ = Transaction::from_bytes(&data);
                        let _ = Block::from_bytes(&data);
                        if let Ok(Ok(Message::Tx(tx))) = read_message(&mut data.as_slice()) {
                            let _ = tx.check_stateless();
                        }
                        let text = String::from_utf8_lossy(&data);
                        let _ = numfranc::wallet::parse_address(&text);
                        let _ = numfranc::wallet::parse_amount(&text);
                        let _ = numfranc::wallet::parse_lock_duration(&text);
                        let _ = numfranc::vault::join_shares(&text, &text);
                        let _ = numfranc::wallet_plus::parse_payment_uri(&text);
                        let _ = numfranc::wallet_plus::proposal_to_tx(&text);
                        let _ = numfranc::wallet_plus::verify_reserve(&text, &chain, None);
                    });
                    if r.is_err() {
                        eprintln!("PLANTAGE avec une entrée de type {kind} : {}", numfranc::encoding::hex(&data));
                        std::process::exit(1);
                    }
                    if i % 100_000 == 0 && t == 0 {
                        eprintln!("{} entrées testées…", done.load(Ordering::Relaxed));
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    println!(
        "Aucun plantage : {} entrées abîmées testées en {:.0} s.",
        done.load(Ordering::Relaxed),
        start.elapsed().as_secs_f64()
    );
}
