// SPDX-License-Identifier: CC0-1.0

//! Demonstrate creating a transaction that spends to and from p2tr outputs.
use bitcoin::consensus::Encodable;
use hex::DisplayHex;
use std::fmt::UpperHex;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, TweakedKeypair, UntweakedPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{rand, Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    transaction, Address, Amount, KnownHrp, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, WitnessProgram,
};
use bitcoin::{CompressedPublicKey, NetworkKind};
use hex_lit::hex;

// the utxo to spend must be correct
const UTXO_TX_HASH: &'static str =
    "84d0cb3070d7b673028bb24a946ef68f9333d6617b33f4377c0d436f848c22f0";
const UTXO_INDEX: u32 = 1;
// the utxo amount must be correct or will get invalid sig
const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20000);

const SPEND_AMOUNT: Amount = Amount::from_sat(3_000); // the amount to transfer to destination

// sats to spend on transaction
const FEE_SATS: u64 = 1000;

// use the tweaked address + secret key or with no tweak at all
// TWEAK should _not_ be used with remove signers or MPC integrations.
const USE_TWEAK: bool = false;
// Use alternative signing algorithm used by MPC signer.
// Both signer types should work / have the same implementation.
const USE_ALT_SCHNORR_SIGNING: bool = true;

fn main() {
    let secp = Secp256k1::new();

    // Get a keypair we control. In a real application these would come from a stored secret.
    let keypair = senders_keys(&secp);

    let public_key = keypair.public_key();
    // let sender_address_ref = Address::p2wpkh(&CompressedPublicKey(public_key), KnownHrp::Mainnet);
    // println!("normal segwit address: {}", sender_address_ref);
    let sender_address_ref = if USE_TWEAK {
        Address::from_witness_program(
            WitnessProgram::p2tr(&secp, public_key.into(), None),
            // WitnessProgram::new_p2tr(public_key_raw),
            KnownHrp::Mainnet,
        )
    } else {
        let mut public_key_raw = [0u8; 32];
        let public_key_serialized = keypair.public_key().serialize();
        public_key_raw.clone_from_slice(&public_key_serialized[1..]);
        Address::from_witness_program(WitnessProgram::new_p2tr(public_key_raw), KnownHrp::Mainnet)
    };

    println!("sender taproot address: {} (tweaked={})", sender_address_ref, USE_TWEAK);

    let (internal_key, _parity) = keypair.x_only_public_key();

    // Get an unspent output that is locked to the key above that we control.
    // In a real application these would come from the chain.
    let (dummy_out_point, dummy_utxo) = dummy_unspent_transaction_output(&secp, internal_key);

    // Get an address to send to.
    let address = receivers_address();

    // The input for the transaction we are constructing.
    let input = TxIn {
        previous_output: dummy_out_point, // The dummy output we are spending.
        script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(), // Filled in after signing.
    };

    // The spend output is locked to a key controlled by the receiver.
    let spend = TxOut { value: SPEND_AMOUNT, script_pubkey: address.script_pubkey() };

    // The change output is locked to a key controlled by us.
    let change_amount: Amount = Amount::from_sat(
        // 1000 sat fee.
        DUMMY_UTXO_AMOUNT.to_sat() - SPEND_AMOUNT.to_sat() - FEE_SATS,
    );
    let change = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None), // Change comes back to us.
    };

    // The transaction we want to sign and broadcast.
    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: vec![input],                  // Input goes into index 0.
        output: vec![spend, change],         // Outputs, order does not matter.
    };
    let input_index = 0;

    // Get the sighash to sign.

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![dummy_utxo];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let msg = Message::from_digest(sighash.to_byte_array());

    let signature = if USE_TWEAK {
        let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
        secp.sign_schnorr(&msg, &tweaked.to_inner())
    } else {
        if USE_ALT_SCHNORR_SIGNING {
            println!("signing using k256 schnorr implementation");
            use k256::ecdsa::signature::hazmat::PrehashSigner;
            use k256::ecdsa::signature::DigestSigner;
            use k256::ecdsa::signature::Signer;
            let secret_bytes = keypair.secret_bytes();
            let schnorr_key = k256::schnorr::SigningKey::from_bytes(&secret_bytes).unwrap();
            let mut sig_bytes =
                schnorr_key.sign_prehash(&sighash.to_byte_array()).unwrap().to_bytes();

            bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap()
        } else {
            println!("signing using rust-bitcoin schnorr implementation");
            secp.sign_schnorr(&msg, &keypair)
        }
    };

    // Update the witness stack.
    let signature = bitcoin::taproot::Signature { signature, sighash_type };
    *sighasher.witness_mut(input_index).unwrap() = Witness::p2tr_key_spend(&signature);

    // Get the signed transaction.
    let tx = sighasher.into_transaction();

    // BOOM! Transaction signed and ready to broadcast.
    let mut buffer = Vec::<u8>::new();
    // println!("{:#?}", tx);
    tx.consensus_encode(&mut buffer);
    // can decode on: https://live.blockcypher.com/btc/decodetx/
    println!("btc tx hex:\n{}", buffer.as_hex());

    // try to broadcast by copying and pasting to:
    // https://mempool.space/tx/push
}

/// An example of keys controlled by the transaction sender.
///
/// In a real application these would be actual secrets.
fn senders_keys<C: Signing>(secp: &Secp256k1<C>) -> Keypair {
    let sk_hex = std::env::var("MAINNET_PRIVATE_KEY")
        .expect("must set 32 byte hex in variable: MAINNET_PRIVATE_KEY");
    let sk = SecretKey::from_str(&sk_hex).unwrap();
    Keypair::from_secret_key(secp, &sk)
}

/// A dummy address for the receiver.
///
/// We lock the spend output to the key associated with this address.
///
/// (FWIW this is an arbitrary mainnet address from block 805222.)
fn receivers_address() -> Address {
    Address::from_str("bc1p8gsj9wp5qsdjduvfe5trq34tr9n8720kw6r4ytw9pds6xra640tqqup53c")
        .expect("a valid address")
        .require_network(Network::Bitcoin)
        .expect("valid address for mainnet")
}

/// Creates a p2wpkh output locked to the key associated with `wpkh`.
///
/// An utxo is described by the `OutPoint` (txid and index within the transaction that it was
/// created). Using the out point one can get the transaction by `txid` and using the `vout` get the
/// transaction value and script pubkey (`TxOut`) of the utxo.
///
/// This output is locked to keys that we control, in a real application this would be a valid
/// output taken from a transaction that appears in the chain.
fn dummy_unspent_transaction_output<C: Verification>(
    secp: &Secp256k1<C>,
    internal_key: UntweakedPublicKey,
) -> (OutPoint, TxOut) {
    let script_pubkey = if USE_TWEAK {
        ScriptBuf::new_p2tr(secp, internal_key, None)
    } else {
        // assume the public key is already 'tweaked'
        ScriptBuf::new_p2tr_tweaked(internal_key.dangerous_assume_tweaked())
    };

    let out_point = OutPoint { txid: Txid::from_str(UTXO_TX_HASH).unwrap(), vout: UTXO_INDEX };

    let utxo = TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey };

    (out_point, utxo)
}
