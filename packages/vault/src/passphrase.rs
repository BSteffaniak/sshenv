//! Passphrase factor support for v2 vault policies.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use rand_core::RngCore;
use sshenv_vault_models::{UnlockFactorKindV2, UnlockFactorV2};
use zeroize::Zeroizing;

const PASSPHRASE_FACTOR_ID: &str = "passphrase:default";
const SALT_HEX: &str = "salt_hex";
const ARGON2_M_COST: &str = "argon2_m_cost";
const ARGON2_T_COST: &str = "argon2_t_cost";
const ARGON2_P_COST: &str = "argon2_p_cost";
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

const DEFAULT_M_COST: u32 = 19_456;
const DEFAULT_T_COST: u32 = 2;
const DEFAULT_P_COST: u32 = 1;

/// Create metadata for a passphrase factor and return the derived factor key.
///
/// # Errors
///
/// Returns an error if Argon2 rejects the configured parameters.
pub fn create_factor(passphrase: &str) -> Result<(UnlockFactorV2, Zeroizing<[u8; KEY_LEN]>)> {
    let mut salt = [0_u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    let factor_key = derive_factor_key(
        passphrase,
        &salt,
        DEFAULT_M_COST,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )?;

    let mut params = BTreeMap::new();
    params.insert(SALT_HEX.to_string(), hex::encode(salt));
    params.insert(ARGON2_M_COST.to_string(), DEFAULT_M_COST.to_string());
    params.insert(ARGON2_T_COST.to_string(), DEFAULT_T_COST.to_string());
    params.insert(ARGON2_P_COST.to_string(), DEFAULT_P_COST.to_string());

    Ok((
        UnlockFactorV2 {
            id: PASSPHRASE_FACTOR_ID.to_string(),
            kind: UnlockFactorKindV2::Passphrase,
            recipient_fingerprint: None,
            params,
        },
        factor_key,
    ))
}

/// Derive the factor key for an existing metadata factor.
///
/// # Errors
///
/// Returns an error if metadata is missing/invalid or Argon2 fails.
pub fn derive_factor_from_metadata(
    factor: &UnlockFactorV2,
    passphrase: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if factor.kind != UnlockFactorKindV2::Passphrase {
        bail!("factor {} is not a passphrase factor", factor.id);
    }

    let salt_hex = factor
        .params
        .get(SALT_HEX)
        .context("passphrase factor is missing salt")?;
    let salt = hex::decode(salt_hex).context("passphrase factor has invalid salt")?;
    let m_cost = parse_param(factor, ARGON2_M_COST)?;
    let t_cost = parse_param(factor, ARGON2_T_COST)?;
    let p_cost = parse_param(factor, ARGON2_P_COST)?;

    derive_factor_key(passphrase, &salt, m_cost, t_cost, p_cost)
}

/// True when the factor is the default passphrase factor.
#[must_use]
pub fn is_passphrase_factor(factor: &UnlockFactorV2) -> bool {
    factor.kind == UnlockFactorKindV2::Passphrase
}

fn parse_param(factor: &UnlockFactorV2, key: &str) -> Result<u32> {
    factor
        .params
        .get(key)
        .with_context(|| format!("passphrase factor is missing {key}"))?
        .parse::<u32>()
        .with_context(|| format!("passphrase factor has invalid {key}"))
}

fn derive_factor_key(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|err| anyhow::anyhow!("invalid Argon2 parameters: {err}"))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|err| anyhow::anyhow!("failed to derive passphrase factor: {err}"))?;
    Ok(Zeroizing::new(out))
}
