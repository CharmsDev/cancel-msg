use anyhow::{Context, Result};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::{sha256d, Hash, HashEngine};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{MessageSignature, signed_msg_hash};
use charms_data::{Charms, NativeOutput};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "cancel-msg")]
#[command(about = "Generate and sign cancellation messages for Cast DEX orders")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate and sign the message
    Sign {
        /// The message to sign
        message: String,
        /// Extended private key (xprv)
        #[arg(long)]
        xprv: String,
        /// Derivation path from the xprv (e.g., "0/4")
        #[arg(long)]
        path: String,
    },
    /// Convert a P2WPKH address to P2PKH address (for bitcoin-cli signmessage)
    P2pkh {
        /// P2WPKH address to convert
        address: String,
    },
    /// Compute the message hash for a given message string (using Bitcoin signed message hash)
    MsgHash {
        /// The message string to hash
        message: String,
    },
    /// Compute the cancellation message from a spell file and UTXO ID
    Message {
        /// Path to the spell YAML file
        spell: String,
        /// The UTXO ID being canceled (txid:vout)
        utxo_id: String,
    },
}

fn sign_message(msg: &str, xprv_str: &str, path_str: &str) -> Result<String> {
    let secp = Secp256k1::new();

    // Parse the xprv
    let xprv = Xpriv::from_str(xprv_str)
        .context("Failed to parse xprv")?;

    // Parse and derive the path
    let path = DerivationPath::from_str(&format!("m/{}", path_str))
        .context("Failed to parse derivation path")?;

    let derived = xprv.derive_priv(&secp, &path)
        .context("Failed to derive private key")?;

    // Compute the Bitcoin message hash
    let msg_hash = signed_msg_hash(msg);
    let msg_digest = Message::from_digest(*msg_hash.as_byte_array());

    // Sign with recoverable signature
    let sig = secp.sign_ecdsa_recoverable(&msg_digest, &derived.private_key);

    // Create MessageSignature
    let message_signature = MessageSignature::new(sig, true);

    // Serialize to bytes and hex-encode
    let sig_bytes = message_signature.serialize();
    Ok(hex::encode(sig_bytes))
}

/// Convert a P2WPKH address to P2PKH address
fn p2wpkh_to_p2pkh(address_str: &str) -> Result<String> {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::{Network, PubkeyHash};

    let address: bitcoin::Address<NetworkUnchecked> = address_str.parse()
        .context("Failed to parse address")?;

    // Assume mainnet for checked conversion
    let checked = address.assume_checked();

    // Extract the witness program (pubkey hash) from P2WPKH
    let script = checked.script_pubkey();
    let bytes = script.as_bytes();

    // P2WPKH script is: OP_0 <20-byte-pubkey-hash>
    // bytes[0] = 0x00 (OP_0)
    // bytes[1] = 0x14 (push 20 bytes)
    // bytes[2..22] = pubkey hash
    if bytes.len() != 22 || bytes[0] != 0x00 || bytes[1] != 0x14 {
        anyhow::bail!("Not a valid P2WPKH address");
    }

    let pubkey_hash_bytes: [u8; 20] = bytes[2..22].try_into()
        .context("Failed to extract pubkey hash")?;
    let pubkey_hash = PubkeyHash::from_byte_array(pubkey_hash_bytes);

    // Create P2PKH address
    let p2pkh_addr = bitcoin::Address::p2pkh(pubkey_hash, Network::Bitcoin);

    Ok(p2pkh_addr.to_string())
}

/// Expand aliases in a YAML value using the alias map
fn expand_aliases(value: &mut serde_yaml::Value, alias_map: &HashMap<String, String>) {
    use serde_yaml::Value;

    match value {
        Value::String(s) if alias_map.contains_key(s.as_str()) => {
            *s = alias_map[s.as_str()].clone();
        }
        Value::Mapping(map) => {
            // First, expand keys that are aliases
            let keys_to_replace: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_str())
                .filter(|k| alias_map.contains_key(*k))
                .map(|k| k.to_string())
                .collect();

            for old_key in keys_to_replace {
                if let Some(val) = map.remove(&Value::String(old_key.clone())) {
                    let new_key = alias_map[&old_key].clone();
                    map.insert(Value::String(new_key), val);
                }
            }

            // Recurse into values
            for (_, v) in map.iter_mut() {
                expand_aliases(v, alias_map);
            }
        }
        Value::Sequence(seq) => {
            for v in seq.iter_mut() {
                expand_aliases(v, alias_map);
            }
        }
        _ => {}
    }
}

/// Compute the cancellation message from a spell file and UTXO ID
fn compute_cancellation_message(spell_path: &str, utxo_id: &str) -> Result<String> {
    use serde_yaml::Value;

    // Read and parse the spell file
    let spell_content = fs::read_to_string(spell_path).context("Failed to read spell file")?;
    let mut spell: Value =
        serde_yaml::from_str(&spell_content).context("Failed to parse spell YAML")?;

    // Extract apps mapping for alias expansion
    let apps = spell
        .get("apps")
        .context("Spell missing 'apps' section")?
        .as_mapping()
        .context("'apps' should be a mapping")?
        .clone();

    let mut alias_map = HashMap::new();
    for (key, value) in &apps {
        if let (Some(alias), Some(app_id)) = (key.as_str(), value.as_str()) {
            alias_map.insert(alias.to_string(), app_id.to_string());
        }
    }

    // Extract outputs and expand aliases
    let outs = spell
        .get_mut("outs")
        .context("Spell missing 'outs' section")?;

    expand_aliases(outs, &alias_map);

    let outs_seq = outs.as_sequence().context("'outs' should be a sequence")?;

    // Build tx_outs and tx_coin_outs
    let mut tx_outs: Vec<Charms> = Vec::new();
    let mut tx_coin_outs: Vec<NativeOutput> = Vec::new();

    for out in outs_seq {
        let out_map = out.as_mapping().context("Output should be a mapping")?;

        // Extract coin value and address for coin_outs
        if let Some(coin_value) = out_map.get(&Value::String("coin".to_string())) {
            if let Some(coin) = coin_value.as_u64() {
                // Get the address and convert to script bytes
                let address_str = out_map
                    .get(&Value::String("address".to_string()))
                    .and_then(|v| v.as_str())
                    .context("Output with coin must have address")?;

                let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = address_str
                    .parse()
                    .context("Failed to parse address")?;
                let checked = address.assume_checked();
                let script = checked.script_pubkey();

                tx_coin_outs.push(NativeOutput {
                    amount: coin,
                    dest: script.to_bytes(),
                });
            }
        }

        // Extract and convert charms
        if let Some(charms_value) = out_map.get(&Value::String("charms".to_string())) {
            // Deserialize the expanded charms
            let charms: Charms = serde_yaml::from_value(charms_value.clone())
                .context("Failed to deserialize charms")?;
            tx_outs.push(charms);
        } else {
            tx_outs.push(Charms::default());
        }
    }

    // Compute outputs_hash = sha256d(outs_bytes || coin_outs_bytes)
    let mut engine = sha256d::Hash::engine();

    let outs_bytes =
        charms_data::util::write(&tx_outs).context("Failed to serialize outs")?;
    engine.input(&outs_bytes);

    let coin_outs: Option<Vec<NativeOutput>> = if tx_coin_outs.is_empty() {
        None
    } else {
        Some(tx_coin_outs)
    };
    let coin_outs_bytes =
        charms_data::util::write(&coin_outs).context("Failed to serialize coin_outs")?;
    engine.input(&coin_outs_bytes);

    let outputs_hash = sha256d::Hash::from_engine(engine);

    // Format the message
    Ok(format!("{} {}", utxo_id, outputs_hash))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sign { message, xprv, path } => {
            let signature = sign_message(&message, &xprv, &path)?;

            println!("Message: {}", message);
            println!("Signature (hex): {}", signature);
            println!();
            println!("Add to spell private_inputs.$CAST.edit_orders.cancel:");
            println!("  0: {}", signature);
        }
        Commands::P2pkh { address } => {
            let p2pkh = p2wpkh_to_p2pkh(&address)?;
            println!("{}", p2pkh);
        }
        Commands::MsgHash { message } => {
            let msg_hash = signed_msg_hash(&message);
            println!("Message: {}", message);
            println!("Message hash: {}", msg_hash);
        }
        Commands::Message { spell, utxo_id } => {
            let message = compute_cancellation_message(&spell, &utxo_id)?;
            println!("{}", message);
        }
    }

    Ok(())
}
