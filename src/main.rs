use std::{fs, path::PathBuf, env};
use dotenv::dotenv;
use alloy::{
    primitives::B256,
    signers::k256::sha2::{Digest, Sha256},
};
use blst::{min_pk::Signature, BLST_ERROR};
use clap::ValueEnum;
use ethereum_consensus::{
    crypto::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
    },
    deneb::{compute_fork_data_root, compute_signing_root, Root}
};
use eyre::{eyre, Context, Result};
use keystore::{keystore_paths, KeystoreError, KeystoreSecret};
use lighthouse_eth2_keystore::Keystore;
use serde::Serialize;
use signer::{compute_commit_boost_signing_root, verify_message_signature};
use tracing::{debug, warn};

mod keystore;
mod signer;




fn main() {
    dotenv().ok();
    let keys_path = env::var("KEYS_PATH").expect("couldn't find keys path in env file");
    let password_path = env::var("SECRETS_PATH").expect("couldn't find secrets path in env file");
    let out = env::var("OUT_FILE").expect("couldn't find out file in env file");
    let delegate_pbukey_str = env::var("DELEGATEE_PUBLICKEY").expect("couldn't find delegatee publickey in env file");
    let delegatee_pubkey:BlsPublicKey = parse_bls_public_key(delegate_pbukey_str.as_str()).expect("Invalid public key");
    let _ = tracing_subscriber::fmt().with_target(false).try_init();
    let keystore_secret = KeystoreSecret::from_directory(password_path.as_str()).unwrap();
    let signed_messages = generate_from_keystore(
        &keys_path,
        keystore_secret,
        delegatee_pubkey,
        Chain::Kurtosis,
        Action::Delegate,
    ).expect("Invalid signed message request");

    debug!("Signed {} messages with keystore", signed_messages.len());

    // Verify signatures
    for message in &signed_messages {
        verify_message_signature(message, Chain::Kurtosis).expect("invalid signature");
    }

    write_to_file(out.as_str(), &signed_messages).expect("invalid file");
    println!("Signed delegation messages generated and saved to {}", out);
}

/// Parse a BLS public key from a string
pub fn parse_bls_public_key(delegatee_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = delegatee_pubkey.strip_prefix("0x").unwrap_or(delegatee_pubkey);
    BlsPublicKey::try_from(
        hex::decode(hex_pk).wrap_err("Failed to hex-decode delegatee pubkey")?.as_slice(),
    )
    .map_err(|e| eyre::eyre!("Failed to parse delegatee public key '{}': {}", hex_pk, e))
}


pub fn generate_from_keystore(
    keys_path: &str,
    keystore_secret: KeystoreSecret,
    delegatee_pubkey: BlsPublicKey,
    chain: Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut signed_messages = Vec::with_capacity(keystores_paths.len());
    debug!("Found {} keys in the keystore", keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let password = keystore_secret.get(ks.pubkey()).ok_or(KeystoreError::MissingPassword)?;
        let kp = ks.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let validator_pubkey = BlsPublicKey::try_from(kp.pk.serialize().to_vec().as_ref())?;
        let validator_private_key = kp.sk;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed));
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}


/// Supported chains for the CLI
#[derive(Debug, Clone, Copy, ValueEnum, Hash, PartialEq, Eq)]
#[clap(rename_all = "kebab_case")]
pub enum Chain {
    Mainnet,
    Holesky,
    Helder,
    Kurtosis,
}

impl Chain {
    /// Get the fork version for the given chain.
    pub fn fork_version(&self) -> [u8; 4] {
        match self {
            Chain::Mainnet => [0, 0, 0, 0],
            Chain::Holesky => [1, 1, 112, 0],
            Chain::Helder => [16, 0, 0, 0],
            Chain::Kurtosis => [16, 0, 0, 56],
        }
    }

    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            1 => Some(Self::Mainnet),
            17000 => Some(Self::Holesky),
            3151908 => Some(Self::Kurtosis),
            7014190335 => Some(Self::Helder),
            _ => None,
        }
    }
}
/// The action to perform.
#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum Action {
    /// Create a delegation message.
    Delegate,
    /// Create a revocation message.
    Revoke,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum SignedMessageAction {
    /// Signal delegation of a validator pubkey to a delegatee pubkey.
    Delegation,
    /// Signal revocation of a previously delegated pubkey.
    Revocation,
}

/// Transparent serialization of signed messages.
/// This is used to serialize and deserialize signed messages
///
/// e.g. serde_json::to_string(&signed_message):
/// ```
/// {
///    "message": {
///       "action": 0,
///       "validator_pubkey": "0x...",
///       "delegatee_pubkey": "0x..."
///    },
///   "signature": "0x..."
/// },
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SignedMessage {
    Delegation(SignedDelegation),
    Revocation(SignedRevocation),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DelegationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl DelegationMessage {
    /// Create a new delegation message.
    pub fn new(validator_pubkey: BlsPublicKey, delegatee_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Delegation as u8, validator_pubkey, delegatee_pubkey }
    }

    /// Compute the digest of the delegation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.delegatee_pubkey.to_vec());

        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RevocationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl RevocationMessage {
    /// Create a new revocation message.
    pub fn new(validator_pubkey: BlsPublicKey, delegatee_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Revocation as u8, validator_pubkey, delegatee_pubkey }
    }

    /// Compute the digest of the revocation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.delegatee_pubkey.to_vec());

        hasher.finalize().into()
    }
}

/// Write some serializable data to an output json file
pub fn write_to_file<T: Serialize>(out: &str, data: &T) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, data)?;
    Ok(())
}