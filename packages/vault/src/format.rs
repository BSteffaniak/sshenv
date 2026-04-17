//! Binary encoding and decoding of the vault file format.

use anyhow::Result;
use sshenv_vault_models::{MAGIC, RecipientEntry, VERSION, VaultHeader, VaultModelsError};

/// Output of [`parse`]: raw deserialized sections. The payload ciphertext
/// has **not** been decrypted.
#[derive(Debug)]
pub struct ParsedVault {
    pub header: VaultHeader,
    pub recipients: Vec<RecipientEntry>,
    pub payload: Vec<u8>,
}

/// Encode a vault to bytes: magic + version + flags + recipients + payload.
///
/// # Errors
///
/// Returns an error if any length would overflow `u32`.
pub fn encode(
    header: VaultHeader,
    recipients: &[RecipientEntry],
    payload_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let recip_wire_len: usize = recipients.iter().map(RecipientEntry::wire_len).sum();
    let recip_len_u32: u32 = u32::try_from(recip_wire_len)
        .map_err(|_| anyhow::anyhow!("recipient block too large: {recip_wire_len} bytes"))?;
    let payload_len_u32: u32 = u32::try_from(payload_ciphertext.len())
        .map_err(|_| anyhow::anyhow!("payload too large: {} bytes", payload_ciphertext.len()))?;

    let mut out = Vec::with_capacity(4 + 1 + 1 + 4 + recip_wire_len + 4 + payload_ciphertext.len());
    out.extend_from_slice(&MAGIC);
    out.push(header.version);
    out.push(header.flags);
    out.extend_from_slice(&recip_len_u32.to_be_bytes());

    for r in recipients {
        let fp_len_u16: u16 = u16::try_from(r.fingerprint.len())
            .map_err(|_| anyhow::anyhow!("fingerprint too long: {} bytes", r.fingerprint.len()))?;
        let wrap_len_u32: u32 = u32::try_from(r.wrapped_key.len()).map_err(|_| {
            anyhow::anyhow!(
                "wrapped key too large for recipient {}: {} bytes",
                r.fingerprint,
                r.wrapped_key.len()
            )
        })?;
        out.extend_from_slice(&fp_len_u16.to_be_bytes());
        out.extend_from_slice(r.fingerprint.as_bytes());
        out.extend_from_slice(&wrap_len_u32.to_be_bytes());
        out.extend_from_slice(&r.wrapped_key);
    }

    out.extend_from_slice(&payload_len_u32.to_be_bytes());
    out.extend_from_slice(payload_ciphertext);
    Ok(out)
}

/// Parse a byte slice into its sections. Does not decrypt.
///
/// # Errors
///
/// Returns an error if the input is truncated, has bad magic, an
/// unsupported version, or internal length fields disagree.
pub fn parse(input: &[u8]) -> Result<ParsedVault> {
    let mut r = Reader::new(input);
    let magic = r.take(4)?;
    if magic != MAGIC {
        return Err(VaultModelsError::BadMagic.into());
    }
    let version = r.take(1)?[0];
    if version != VERSION {
        return Err(VaultModelsError::UnsupportedVersion(version).into());
    }
    let flags = r.take(1)?[0];
    if flags != 0 {
        return Err(VaultModelsError::BadFlags(flags).into());
    }

    let recip_len = read_u32_be(r.take(4)?);
    let recip_block = r
        .take(usize::try_from(recip_len).map_err(|_| {
            anyhow::anyhow!("recipients length {recip_len} does not fit in usize")
        })?)?;
    let recipients = parse_recipients(recip_block)?;

    let payload_len = read_u32_be(r.take(4)?);
    let payload_bytes = r
        .take(usize::try_from(payload_len).map_err(|_| {
            anyhow::anyhow!("payload length {payload_len} does not fit in usize")
        })?)?;

    Ok(ParsedVault {
        header: VaultHeader { version, flags },
        recipients,
        payload: payload_bytes.to_vec(),
    })
}

fn parse_recipients(input: &[u8]) -> Result<Vec<RecipientEntry>> {
    let mut r = Reader::new(input);
    let mut out = Vec::new();
    while !r.is_empty() {
        let fp_len = read_u16_be(
            r.take(2)
                .map_err(|_| VaultModelsError::TruncatedRecipients)?,
        );
        let fp_bytes = r
            .take(fp_len as usize)
            .map_err(|_| VaultModelsError::TruncatedRecipients)?;
        let fingerprint = std::str::from_utf8(fp_bytes)
            .map_err(|_| VaultModelsError::InvalidFingerprintUtf8)?
            .to_string();
        let wrap_len = read_u32_be(
            r.take(4)
                .map_err(|_| VaultModelsError::TruncatedRecipients)?,
        );
        let wrap = r
            .take(usize::try_from(wrap_len).map_err(|_| {
                anyhow::anyhow!("wrapped key length {wrap_len} does not fit in usize")
            })?)
            .map_err(|_| VaultModelsError::TruncatedRecipients)?
            .to_vec();
        out.push(RecipientEntry {
            fingerprint,
            public_key_line: String::new(),
            wrapped_key: wrap,
        });
    }
    Ok(out)
}

fn read_u16_be(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(VaultModelsError::Truncated {
                expected: n,
                had: self.buf.len().saturating_sub(self.pos),
            }
            .into());
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_parse_empty_recipients_empty_payload() {
        let header = VaultHeader::default();
        let bytes = encode(header, &[], &[]).expect("encode");
        let parsed = parse(&bytes).expect("parse");
        assert_eq!(parsed.header, header);
        assert!(parsed.recipients.is_empty());
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn encode_then_parse_roundtrip_with_recipients() {
        let header = VaultHeader::default();
        let recipients = vec![
            RecipientEntry {
                fingerprint: "SHA256:aaa".into(),
                public_key_line: "ignored on decode".into(),
                wrapped_key: vec![1, 2, 3],
            },
            RecipientEntry {
                fingerprint: "SHA256:bbb".into(),
                public_key_line: "also ignored".into(),
                wrapped_key: vec![4, 5, 6, 7],
            },
        ];
        let payload = b"\xde\xad\xbe\xef\x00\x11".to_vec();
        let bytes = encode(header, &recipients, &payload).expect("encode");
        let parsed = parse(&bytes).expect("parse");
        assert_eq!(parsed.header, header);
        assert_eq!(parsed.recipients.len(), 2);
        assert_eq!(parsed.recipients[0].fingerprint, "SHA256:aaa");
        assert_eq!(parsed.recipients[0].wrapped_key, vec![1, 2, 3]);
        assert_eq!(parsed.recipients[1].wrapped_key, vec![4, 5, 6, 7]);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut bytes = encode(VaultHeader::default(), &[], &[]).unwrap();
        bytes[0] = b'X';
        let err = parse(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("bad magic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        let mut bytes = encode(VaultHeader::default(), &[], &[]).unwrap();
        bytes[4] = 0xFF;
        let err = parse(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("unsupported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rejects_nonzero_flags() {
        let mut bytes = encode(VaultHeader::default(), &[], &[]).unwrap();
        bytes[5] = 0x01;
        let err = parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("flags"), "unexpected error: {err}");
    }

    #[test]
    fn parse_rejects_truncated_input() {
        let bytes = encode(VaultHeader::default(), &[], &[]).unwrap();
        let err = parse(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("truncat"),
            "unexpected error: {err}"
        );
    }
}
