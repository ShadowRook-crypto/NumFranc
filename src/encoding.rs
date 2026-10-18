//! Lecture et écriture binaires (big-endian), avec contrôles de bornes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError("données tronquées"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    /// Entier de taille variable (forme canonique obligatoire).
    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let v = match self.u8()? {
            0xFD => {
                let v = self.u16()? as u64;
                if v < 0xFD { return Err(DecodeError("varint non canonique")); }
                v
            }
            0xFE => {
                let v = self.u32()? as u64;
                if v <= 0xFFFF { return Err(DecodeError("varint non canonique")); }
                v
            }
            0xFF => {
                let v = self.u64()?;
                if v <= 0xFFFF_FFFF { return Err(DecodeError("varint non canonique")); }
                v
            }
            b => b as u64,
        };
        Ok(v)
    }
    /// Lit un nombre d'éléments, en refusant un nombre impossible vu les données restantes.
    pub fn count(&mut self, min_item_size: usize) -> Result<usize, DecodeError> {
        let n = self.varint()?;
        if n as u128 * min_item_size.max(1) as u128 > self.remaining() as u128 {
            return Err(DecodeError("nombre d'éléments incohérent"));
        }
        Ok(n as usize)
    }
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.remaining() != 0 {
            return Err(DecodeError("octets en trop"));
        }
        Ok(())
    }
}

pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0xFD {
        out.push(v as u8);
    } else if v <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_aller_retour() {
        for v in [0u64, 1, 252, 253, 65535, 65536, u32::MAX as u64, u64::MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut r = Reader::new(&out);
            assert_eq!(r.varint().unwrap(), v);
            r.finish().unwrap();
        }
    }

    #[test]
    fn varint_non_canonique_refuse() {
        let mut r = Reader::new(&[0xFD, 0x00, 0x05]);
        assert!(r.varint().is_err());
    }

    #[test]
    fn hex_aller_retour() {
        assert_eq!(from_hex(&hex(&[0, 255, 16])).unwrap(), vec![0, 255, 16]);
        assert!(from_hex("zz").is_none());
    }
}
