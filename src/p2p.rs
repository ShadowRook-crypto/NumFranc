//! Messages réseau. Trame : magic (4) | commande (12) | longueur (4) | somme de contrôle (4) | charge utile.

use crate::block::Block;
use crate::config::{MAGIC, MAX_BLOCK_SIZE};
use crate::encoding::{put_varint, DecodeError, Reader};
use crate::hashing::hash512;
use crate::tx::{Hash, Transaction};
use std::io::{self, Read, Write};

pub const MAX_PAYLOAD: usize = MAX_BLOCK_SIZE + 1_024;

/// Début du message d'erreur d'une commande inconnue (version plus récente du protocole) : ignorée, sans exclusion.
pub const UNKNOWN_COMMAND: &str = "commande inconnue";

/// Taille maximale du contenu selon la commande : on refuse avant de réserver la mémoire.
fn max_payload(cmd: &str) -> usize {
    match cmd {
        "verack" | "getaddr" => 0,
        "version" => 4 + 8 + 2 + 8,
        "tip" | "ping" | "pong" => 8,
        "getblocks" => 9 + 200 * 64,
        "addr" => 3 + 1_000 * 256,
        "tx" => crate::config::MAX_TX_SIZE,
        "block" => MAX_PAYLOAD,
        "point" => crate::points::TAILLE,
        // Commande inconnue : lue (pour rester synchronisé sur la connexion) puis ignorée, si elle est petite.
        _ => 64 * 1024,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Version { version: u32, height: u64, listen_port: u16, nonce: u64 },
    Verack,
    GetBlocks(Vec<Hash>),
    Block(Block),
    Tx(Transaction),
    Tip(u64),
    GetAddr,
    Addr(Vec<String>),
    Ping(u64),
    Pong(u64),
    /// Point de contrôle signé (voir points.rs).
    Point(crate::points::PointSigne),
}

impl Message {
    pub fn command(&self) -> &'static str {
        match self {
            Message::Version { .. } => "version",
            Message::Verack => "verack",
            Message::GetBlocks(_) => "getblocks",
            Message::Block(_) => "block",
            Message::Tx(_) => "tx",
            Message::Tip(_) => "tip",
            Message::GetAddr => "getaddr",
            Message::Addr(_) => "addr",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::Point(_) => "point",
        }
    }

    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Message::Version { version, height, listen_port, nonce } => {
                out.extend_from_slice(&version.to_be_bytes());
                out.extend_from_slice(&height.to_be_bytes());
                out.extend_from_slice(&listen_port.to_be_bytes());
                out.extend_from_slice(&nonce.to_be_bytes());
            }
            Message::Verack | Message::GetAddr => {}
            Message::GetBlocks(loc) => {
                put_varint(&mut out, loc.len() as u64);
                for h in loc {
                    out.extend_from_slice(h);
                }
            }
            Message::Block(b) => out = b.serialize(),
            Message::Tx(t) => out = t.serialize(),
            Message::Point(p) => out = p.encoder(),
            Message::Tip(h) | Message::Ping(h) | Message::Pong(h) => out.extend_from_slice(&h.to_be_bytes()),
            Message::Addr(list) => {
                put_varint(&mut out, list.len() as u64);
                for a in list {
                    out.push(a.len() as u8);
                    out.extend_from_slice(a.as_bytes());
                }
            }
        }
        out
    }

    pub fn decode(command: &str, payload: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(payload);
        let m = match command {
            "version" => Message::Version { version: r.u32()?, height: r.u64()?, listen_port: r.u16()?, nonce: r.u64()? },
            "verack" => Message::Verack,
            "getaddr" => Message::GetAddr,
            "getblocks" => {
                let n = r.count(64)?;
                if n > 200 {
                    return Err(DecodeError("localisateur trop long"));
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(r.array()?);
                }
                Message::GetBlocks(v)
            }
            "block" => return Ok(Message::Block(Block::from_bytes(payload)?)),
            "tx" => return Ok(Message::Tx(Transaction::from_bytes(payload)?)),
            "point" => return Ok(Message::Point(crate::points::PointSigne::decoder(payload)?)),
            "tip" => Message::Tip(r.u64()?),
            "ping" => Message::Ping(r.u64()?),
            "pong" => Message::Pong(r.u64()?),
            "addr" => {
                let n = r.count(2)?;
                if n > 1_000 {
                    return Err(DecodeError("trop d'adresses"));
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let len = r.u8()? as usize;
                    let s = std::str::from_utf8(r.bytes(len)?).map_err(|_| DecodeError("adresse non UTF-8"))?;
                    v.push(s.to_string());
                }
                Message::Addr(v)
            }
            _ => return Err(DecodeError(UNKNOWN_COMMAND)),
        };
        r.finish()?;
        Ok(m)
    }
}

pub fn write_message(w: &mut impl Write, msg: &Message) -> io::Result<()> {
    let payload = msg.payload();
    let mut frame = Vec::with_capacity(24 + payload.len());
    frame.extend_from_slice(&MAGIC);
    let mut cmd = [0u8; 12];
    cmd[..msg.command().len()].copy_from_slice(msg.command().as_bytes());
    frame.extend_from_slice(&cmd);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&hash512(&payload)[..4]);
    frame.extend_from_slice(&payload);
    w.write_all(&frame)?;
    w.flush()
}

/// Lit un message complet. Erreur d'E/S = connexion perdue ; Err(String) = message invalide.
pub fn read_message(r: &mut impl Read) -> io::Result<Result<Message, String>> {
    let mut head = [0u8; 24];
    r.read_exact(&mut head)?;
    if head[0..4] != MAGIC {
        return Ok(Err("mauvais octets magiques".into()));
    }
    let cmd_raw = &head[4..16];
    let end = cmd_raw.iter().position(|&b| b == 0).unwrap_or(12);
    let cmd = String::from_utf8_lossy(&cmd_raw[..end]).to_string();
    let len = u32::from_be_bytes(head[16..20].try_into().unwrap()) as usize;
    if len > MAX_PAYLOAD || len > max_payload(&cmd) {
        return Ok(Err("message trop grand".into()));
    }
    // Lecture par morceaux : la mémoire n'est réservée qu'au fur et à mesure que les octets arrivent.
    let mut payload = Vec::with_capacity(len.min(64 * 1024));
    r.take(len as u64).read_to_end(&mut payload)?;
    if payload.len() != len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "message coupé"));
    }
    if hash512(&payload)[..4] != head[20..24] {
        return Ok(Err("somme de contrôle invalide".into()));
    }
    Ok(Message::decode(&cmd, &payload).map_err(|e| format!("{} ({cmd})", e.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_des_messages() {
        let msgs = vec![
            Message::Version { version: 1, height: 42, listen_port: 6910, nonce: 7 },
            Message::Verack,
            Message::GetBlocks(vec![[1; 64], [2; 64]]),
            Message::Tip(99),
            Message::GetAddr,
            Message::Addr(vec!["192.168.1.35:6910".into()]),
            Message::Ping(5),
            Message::Block(crate::chain::genesis_block()),
            Message::Point(crate::points::PointSigne::signer(&crate::signature::KeyPair::from_seed(&[3; 32]), 12, [5; 64]).unwrap()),
        ];
        for m in msgs {
            let mut buf = Vec::new();
            write_message(&mut buf, &m).unwrap();
            let got = read_message(&mut buf.as_slice()).unwrap().unwrap();
            assert_eq!(got, m);
        }
    }

    #[test]
    fn trame_corrompue_detectee() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Message::Tip(1)).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 1;
        assert!(read_message(&mut buf.as_slice()).unwrap().is_err());
    }
}
