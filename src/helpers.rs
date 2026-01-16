use std::io::Cursor;

use bitcoin::{
    ecdsa::Signature as EcdsaSignature,
    opcodes,
    script::Instruction,
    sighash::{EcdsaSighashType, TapSighashType},
    taproot::Signature as SchnorrSignature,
    Address, Network, Script, ScriptBuf, TxIn, Txid,
};
use ciborium::de::from_reader;
use xxhash_rust::xxh3::xxh3_128;

use crate::types::{Amount, UtxoKey};

/// Extracts the Bitcoin address from a script, if possible.
///
/// Returns `None` for non-standard scripts (e.g., bare multisig, OP_RETURN, unknown scripts).
/// Supported script types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR (Taproot).
pub fn extract_address(script: &Script, network: Network) -> Option<String> {
    Address::from_script(script, network)
        .ok()
        .map(|addr| addr.to_string())
}

/// Returns true if bytes resemble a DER-encoded ECDSA signature plus sighash byte.
fn looks_like_der_signature(data: &[u8]) -> bool {
    // DER signatures are typically 70-73 bytes + 1 sighash byte,
    // but may be shorter in degenerate cases; enforce a broad valid range.
    (9..=74).contains(&data.len()) && data.first() == Some(&0x30)
}

pub fn compute_utxo_key(txid: &Txid, vout: u32) -> UtxoKey {
    let mut payload = [0u8; 36];
    payload[..32].copy_from_slice(txid.as_ref());
    payload[32..].copy_from_slice(&vout.to_le_bytes());

    // xxh3_128 is extremely fast and provides enough entropy; truncate to 96 bits.
    let hash = xxh3_128(&payload).to_le_bytes();
    let mut key = [0u8; 12];
    key.copy_from_slice(&hash[..12]);
    key
}

pub fn leading_zero_count(txid: &Txid) -> u8 {
    let mut count: u8 = 0;
    let bytes: &[u8] = txid.as_ref();

    // bitcoin::Txid stores the hash in little-endian order; scan it in
    // reverse so we count the human-visible leading zeros.
    for &byte in bytes.iter().rev() {
        if byte == 0 {
            count += 2;
            continue;
        }

        if byte >> 4 == 0 {
            count += 1;
        }
        break;
    }

    count
}

pub fn parse_op_return(script: &ScriptBuf, prefix: &[u8]) -> Option<Vec<u64>> {
    let mut instructions = script.instructions();

    let op_return = instructions.next()?;
    match op_return.ok()? {
        Instruction::Op(opcodes::all::OP_RETURN) => {}
        _ => return None,
    }

    let push = instructions.next()?;
    let data = match push.ok()? {
        Instruction::PushBytes(bytes) => bytes.as_bytes(),
        _ => return None,
    };

    if data.len() < prefix.len() || &data[..prefix.len()] != prefix {
        return None;
    }

    let mut reader = Cursor::new(&data[prefix.len()..]);
    from_reader::<Vec<u64>, _>(&mut reader).ok()
}

pub fn calculate_reward(
    zero_count: u8,
    max_zero_count: u8,
    min_zero_count: u8,
    base_reward: Amount,
) -> Amount {
    if zero_count < min_zero_count {
        return 0;
    }

    let diff = max_zero_count.saturating_sub(zero_count);
    let mut reward = base_reward;

    for _ in 0..diff {
        reward /= 16;
        if reward == 0 {
            break;
        }
    }

    reward
}

/// Checks if an ECDSA signature (DER-encoded + sighash byte) uses SIGHASH_ALL.
fn is_ecdsa_sighash_all(sig_bytes: &[u8]) -> bool {
    EcdsaSignature::from_slice(sig_bytes)
        .map(|sig| sig.sighash_type == EcdsaSighashType::All)
        .unwrap_or(false)
}

/// Checks if a Schnorr signature uses SIGHASH_ALL or SIGHASH_DEFAULT (equivalent for Taproot).
/// Schnorr signatures are 64 bytes (SIGHASH_DEFAULT) or 65 bytes (explicit sighash).
fn is_schnorr_sighash_all(sig_bytes: &[u8]) -> bool {
    SchnorrSignature::from_slice(sig_bytes)
        .map(|sig| {
            // SIGHASH_DEFAULT (0x00) and SIGHASH_ALL (0x01) are both valid for our purposes
            matches!(
                sig.sighash_type,
                TapSighashType::Default | TapSighashType::All
            )
        })
        .unwrap_or(false)
}

/// Extracts ECDSA signatures from a script_sig (for P2PKH and P2SH-multisig).
/// Returns the signature bytes for each push that looks like a DER signature.
fn extract_scriptsig_signatures(script_sig: &bitcoin::Script) -> Vec<&[u8]> {
    let mut signatures = Vec::new();
    for instruction in script_sig.instructions().flatten() {
        if let Instruction::PushBytes(bytes) = instruction {
            let data = bytes.as_bytes();
            // DER signatures are typically 70-73 bytes + 1 sighash byte
            // Minimum: 8 bytes (degenerate) + 1 sighash = 9 bytes
            // Maximum: ~73 bytes + 1 sighash = 74 bytes
            // They start with 0x30 (SEQUENCE tag)
            if data.len() >= 9 && data.len() <= 74 && data.first() == Some(&0x30) {
                signatures.push(data);
            }
        }
    }
    signatures
}

/// Returns true if all inputs are signed with SIGHASH_ALL (or SIGHASH_DEFAULT for Taproot).
/// Returns false if any input uses a different sighash type or if the sighash cannot be determined.
///
/// Supported script types:
/// - P2PKH: Signature in script_sig
/// - P2WPKH: Signature in witness[0]
/// - P2SH-multisig: Multiple signatures in script_sig
/// - P2WSH: Signatures in witness[0..n-1]
/// - P2TR (Taproot): Schnorr signature in witness[0]
pub fn all_inputs_sighash_all(inputs: &[TxIn]) -> bool {
    for input in inputs {
        let has_witness = !input.witness.is_empty();
        let has_scriptsig = !input.script_sig.is_empty();

        if has_witness {
            // SegWit input (P2WPKH, P2WSH, or P2TR)
            let witness_len = input.witness.len();

            // Check if this looks like a Taproot key-path spend (single 64 or 65 byte signature)
            // or Taproot script-path spend (multiple witness elements ending with control block)
            let first_elem = input.witness.nth(0).unwrap_or(&[]);

            if witness_len == 1 && (first_elem.len() == 64 || first_elem.len() == 65) {
                // Taproot key-path spend: single Schnorr signature
                if !is_schnorr_sighash_all(first_elem) {
                    return false;
                }
            } else if witness_len == 2 && (first_elem.len() == 64 || first_elem.len() == 65) {
                // Taproot key-path spend with 2 witness elements
                // (e.g., annex present: witness[0] = Schnorr sig, witness[1] = annex)
                if !is_schnorr_sighash_all(first_elem) {
                    return false;
                }
            } else if witness_len == 2 && looks_like_der_signature(first_elem) {
                // P2WPKH: witness[0] = ECDSA signature, witness[1] = pubkey
                if !is_ecdsa_sighash_all(first_elem) {
                    return false;
                }
            } else if witness_len > 2 {
                // P2WSH or Taproot script-path spend
                // For P2WSH: witness = [OP_0_placeholder, sig1, sig2, ..., redeem_script]
                // For Taproot script-path: witness = [args..., script, control_block]

                // Check if the last element looks like a control block (starts with leaf version)
                let last_elem = input.witness.nth(witness_len - 1).unwrap_or(&[]);

                if !last_elem.is_empty() && (last_elem[0] & 0xfe) == 0xc0 {
                    // Taproot script-path: control block starts with 0xc0 or 0xc1
                    // Signatures are in the witness elements before the script and control block
                    // This is complex to parse generically; check all 64/65 byte elements as Schnorr
                    let mut saw_signature = false;
                    for i in 0..witness_len.saturating_sub(2) {
                        let elem = input.witness.nth(i).unwrap_or(&[]);
                        if elem.len() == 64 || elem.len() == 65 {
                            saw_signature = true;
                            if !is_schnorr_sighash_all(elem) {
                                return false;
                            }
                        }
                    }
                    if !saw_signature {
                        // No recognizable Schnorr signatures found
                        return false;
                    }
                } else {
                    // P2WSH: all elements except the last (redeem script) are signatures or OP_0
                    // Skip empty elements (OP_0 placeholder for CHECKMULTISIG bug)
                    let mut saw_signature = false;
                    for i in 0..witness_len.saturating_sub(1) {
                        let elem = input.witness.nth(i).unwrap_or(&[]);
                        // Skip empty elements (OP_0) and non-signature data
                        if elem.is_empty() {
                            continue;
                        }
                        // Check if it looks like a DER signature and verify sighash
                        if elem.len() >= 9 && elem.first() == Some(&0x30) {
                            saw_signature = true;
                            if !is_ecdsa_sighash_all(elem) {
                                return false;
                            }
                        }
                    }
                    if !saw_signature {
                        // No recognizable DER signatures found
                        return false;
                    }
                }
            } else {
                // Unknown witness structure
                return false;
            }
        } else if has_scriptsig {
            // Legacy input (P2PKH or P2SH)
            let signatures = extract_scriptsig_signatures(&input.script_sig);

            if signatures.is_empty() {
                // No recognizable signatures found
                return false;
            }

            for sig_bytes in signatures {
                if !is_ecdsa_sighash_all(sig_bytes) {
                    return false;
                }
            }
        } else {
            // No witness and no script_sig - cannot determine sighash
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        hashes::Hash, opcodes, script::PushBytesBuf, Network, OutPoint, ScriptBuf, Sequence, Txid,
        Witness,
    };
    use ciborium::ser::into_writer;
    use std::str::FromStr;

    fn txid_from_hex(hex: &str) -> Txid {
        Txid::from_str(hex).expect("invalid txid hex")
    }

    fn txid_from_bytes(bytes: [u8; 32]) -> Txid {
        Txid::from_slice(&bytes).expect("invalid txid bytes")
    }

    fn build_op_return_script(data: &[u8]) -> ScriptBuf {
        let push = PushBytesBuf::try_from(data.to_vec()).expect("invalid push data length");
        ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(push)
            .into_script()
    }

    fn encode_values(values: &[u64]) -> Vec<u8> {
        let mut encoded = Vec::new();
        into_writer(values, &mut encoded).expect("failed to encode cbor");
        encoded
    }

    #[test]
    fn compute_utxo_key_varies_with_inputs() {
        let txid_a =
            txid_from_hex("0101010101010101010101010101010101010101010101010101010101010101");
        let txid_b =
            txid_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        let key_a0 = compute_utxo_key(&txid_a, 0);
        let key_a1 = compute_utxo_key(&txid_a, 1);
        let key_b0 = compute_utxo_key(&txid_b, 0);

        assert_eq!(key_a0.len(), 12);
        assert_ne!(key_a0, key_a1);
        assert_ne!(key_a0, key_b0);
    }

    #[test]
    fn leading_zero_count_handles_full_and_partial_bytes() {
        let all_zero = txid_from_bytes([0u8; 32]);
        assert_eq!(leading_zero_count(&all_zero), 64);

        let mut half = [0xffu8; 32];
        half[31] = 0x0f;
        let half_byte = txid_from_bytes(half);
        assert_eq!(leading_zero_count(&half_byte), 1);

        let mut bytes = [0xffu8; 32];
        bytes[31] = 0xf0;
        let non_zero = txid_from_bytes(bytes);
        assert_eq!(leading_zero_count(&non_zero), 0);
    }

    #[test]
    fn leading_zero_count_ignores_trailing_zero_bytes() {
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0x00;
        let txid = txid_from_bytes(bytes);

        assert_eq!(leading_zero_count(&txid), 0);
    }

    #[test]
    fn parse_op_return_succeeds_with_valid_prefix_and_cbor() {
        const PREFIX: &[u8] = b"ZELD";
        let mut payload = PREFIX.to_vec();
        payload.extend(encode_values(&[1, 2, 3]));
        let script = build_op_return_script(&payload);

        let parsed = parse_op_return(&script, PREFIX).expect("expected values");
        assert_eq!(parsed, vec![1, 2, 3]);
    }

    #[test]
    fn parse_op_return_rejects_missing_op_return() {
        let script = ScriptBuf::builder().push_slice(b"data").into_script();
        assert!(parse_op_return(&script, b"ZELD").is_none());
    }

    #[test]
    fn parse_op_return_rejects_non_push_instruction() {
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_opcode(opcodes::all::OP_ADD)
            .into_script();
        assert!(parse_op_return(&script, b"ZELD").is_none());
    }

    #[test]
    fn parse_op_return_enforces_prefix_length() {
        let script = build_op_return_script(b"\x01");
        assert!(parse_op_return(&script, b"ZELD").is_none());
    }

    #[test]
    fn parse_op_return_enforces_prefix_match() {
        const PREFIX: &[u8] = b"ZELD";
        let mut payload = b"BADP".to_vec();
        payload.extend(encode_values(&[9]));
        let script = build_op_return_script(&payload);

        assert!(parse_op_return(&script, PREFIX).is_none());
    }

    #[test]
    fn parse_op_return_rejects_invalid_cbor() {
        const PREFIX: &[u8] = b"ZELD";
        let mut payload = PREFIX.to_vec();
        payload.extend([0xff, 0x00]);
        let script = build_op_return_script(&payload);

        assert!(parse_op_return(&script, PREFIX).is_none());
    }

    #[test]
    fn parse_op_return_rejects_empty_script() {
        let script = ScriptBuf::new();
        assert!(parse_op_return(&script, b"ZELD").is_none());
    }

    #[test]
    fn parse_op_return_bubbles_error_before_op_return() {
        let bytes = vec![opcodes::all::OP_PUSHDATA1.to_u8(), 0x02];
        let script = ScriptBuf::from_bytes(bytes);
        assert!(parse_op_return(&script, b"ZELD").is_none());
    }

    #[test]
    fn parse_op_return_requires_push_after_op_return() {
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_RETURN)
            .into_script();
        assert!(parse_op_return(&script, b"ZELD").is_none());
    }

    #[test]
    fn parse_op_return_bubbles_error_after_op_return() {
        let bytes = vec![
            opcodes::all::OP_RETURN.to_u8(),
            opcodes::all::OP_PUSHDATA1.to_u8(),
            0x01,
        ];
        let script = ScriptBuf::from_bytes(bytes);
        assert!(parse_op_return(&script, b"ZELD").is_none());
    }

    #[test]
    fn calculate_reward_returns_zero_when_below_min() {
        assert_eq!(calculate_reward(1, 5, 2, 1_000), 0);
    }

    #[test]
    fn calculate_reward_scales_by_zero_difference() {
        let reward = calculate_reward(5, 5, 0, 1_000);
        assert_eq!(reward, 1_000);

        let scaled = calculate_reward(4, 5, 0, 1_000);
        assert_eq!(scaled, 62);
    }

    #[test]
    fn calculate_reward_exhausts_to_zero() {
        let reward = calculate_reward(0, 10, 0, 1);
        assert_eq!(reward, 0);
    }

    // Helper to create a TxIn with a witness
    fn make_witness_input(witness_elements: Vec<Vec<u8>>) -> TxIn {
        let mut witness = Witness::new();
        for elem in witness_elements {
            witness.push(elem);
        }
        TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }
    }

    // Helper to create a TxIn with a script_sig
    fn make_scriptsig_input(script_sig: ScriptBuf) -> TxIn {
        TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    // A valid DER-encoded ECDSA signature with SIGHASH_ALL (0x01)
    // This is a minimal valid DER signature structure
    fn make_ecdsa_sig_sighash_all() -> Vec<u8> {
        // DER signature: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s] [sighash]
        // Using minimal r and s values for testing
        let mut sig = vec![
            0x30, 0x44, // SEQUENCE, length 68
            0x02, 0x20, // INTEGER, length 32 (r)
        ];
        sig.extend([0x01; 32]); // r value (32 bytes)
        sig.extend([
            0x02, 0x20, // INTEGER, length 32 (s)
        ]);
        sig.extend([0x02; 32]); // s value (32 bytes)
        sig.push(0x01); // SIGHASH_ALL
        sig
    }

    // A valid DER-encoded ECDSA signature with SIGHASH_NONE (0x02)
    fn make_ecdsa_sig_sighash_none() -> Vec<u8> {
        let mut sig = make_ecdsa_sig_sighash_all();
        *sig.last_mut().unwrap() = 0x02; // SIGHASH_NONE
        sig
    }

    // A very short but valid DER-encoded ECDSA signature with SIGHASH_ALL (minimal R/S)
    fn make_short_ecdsa_sig_sighash_all() -> Vec<u8> {
        // 0x30 len 0x02 lenR R 0x02 lenS S sighash
        // minimal R/S: single-byte integers >= 0x01
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
    }

    // Malformed short DER (still starts with 0x30 but invalid structure)
    fn make_short_malformed_der() -> Vec<u8> {
        vec![0x30, 0x02, 0x01, 0x01, 0x01] // too short to encode two integers + sighash
    }

    // A Schnorr signature (64 bytes = SIGHASH_DEFAULT)
    fn make_schnorr_sig_default() -> Vec<u8> {
        vec![0x01; 64]
    }

    // A Schnorr signature (65 bytes with explicit SIGHASH_ALL)
    fn make_schnorr_sig_sighash_all() -> Vec<u8> {
        let mut sig = vec![0x01; 64];
        sig.push(0x01); // SIGHASH_ALL
        sig
    }

    // A Schnorr signature (65 bytes with SIGHASH_NONE)
    fn make_schnorr_sig_sighash_none() -> Vec<u8> {
        let mut sig = vec![0x01; 64];
        sig.push(0x02); // SIGHASH_NONE
        sig
    }

    // A 33-byte compressed public key
    fn make_pubkey() -> Vec<u8> {
        let mut pk = vec![0x02]; // compressed pubkey prefix
        pk.extend([0xab; 32]);
        pk
    }

    #[test]
    fn all_inputs_sighash_all_accepts_p2wpkh_with_sighash_all() {
        let sig = make_ecdsa_sig_sighash_all();
        let pubkey = make_pubkey();
        let input = make_witness_input(vec![sig, pubkey]);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_p2wpkh_with_short_valid_der() {
        let sig = make_short_ecdsa_sig_sighash_all();
        let pubkey = make_pubkey();
        let input = make_witness_input(vec![sig, pubkey]);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_p2wpkh_with_short_malformed_der() {
        let sig = make_short_malformed_der();
        let pubkey = make_pubkey();
        let input = make_witness_input(vec![sig, pubkey]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_p2wpkh_with_sighash_none() {
        let sig = make_ecdsa_sig_sighash_none();
        let pubkey = make_pubkey();
        let input = make_witness_input(vec![sig, pubkey]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_taproot_with_sighash_default() {
        let sig = make_schnorr_sig_default();
        let input = make_witness_input(vec![sig]);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_taproot_with_sighash_all() {
        let sig = make_schnorr_sig_sighash_all();
        let input = make_witness_input(vec![sig]);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_taproot_with_sighash_none() {
        let sig = make_schnorr_sig_sighash_none();
        let input = make_witness_input(vec![sig]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_empty_witness() {
        let input = make_witness_input(vec![]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_empty_input() {
        let input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_p2pkh_with_sighash_all() {
        let sig = make_ecdsa_sig_sighash_all();
        let pubkey = make_pubkey();

        // P2PKH script_sig: <sig> <pubkey>
        let script_sig = ScriptBuf::builder()
            .push_slice(PushBytesBuf::try_from(sig).unwrap())
            .push_slice(PushBytesBuf::try_from(pubkey).unwrap())
            .into_script();
        let input = make_scriptsig_input(script_sig);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_p2pkh_with_sighash_none() {
        let sig = make_ecdsa_sig_sighash_none();
        let pubkey = make_pubkey();

        let script_sig = ScriptBuf::builder()
            .push_slice(PushBytesBuf::try_from(sig).unwrap())
            .push_slice(PushBytesBuf::try_from(pubkey).unwrap())
            .into_script();
        let input = make_scriptsig_input(script_sig);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_multiple_valid_inputs() {
        let sig1 = make_ecdsa_sig_sighash_all();
        let pubkey1 = make_pubkey();
        let input1 = make_witness_input(vec![sig1, pubkey1]);

        let sig2 = make_schnorr_sig_default();
        let input2 = make_witness_input(vec![sig2]);

        assert!(all_inputs_sighash_all(&[input1, input2]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_if_any_input_invalid() {
        let sig1 = make_ecdsa_sig_sighash_all();
        let pubkey1 = make_pubkey();
        let input1 = make_witness_input(vec![sig1, pubkey1]);

        let sig2 = make_schnorr_sig_sighash_none();
        let input2 = make_witness_input(vec![sig2]);

        assert!(!all_inputs_sighash_all(&[input1, input2]));
    }

    #[test]
    fn all_inputs_sighash_all_returns_true_for_empty_inputs() {
        // Edge case: no inputs means all (zero) inputs satisfy the condition
        assert!(all_inputs_sighash_all(&[]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_p2wsh_multisig_with_sighash_all() {
        let sig1 = make_ecdsa_sig_sighash_all();
        let sig2 = make_ecdsa_sig_sighash_all();
        let redeem_script = vec![0x52, 0x21]; // OP_2 OP_PUSHBYTES_33 (start of 2-of-3 multisig)

        // P2WSH witness: [OP_0, sig1, sig2, redeem_script]
        let input = make_witness_input(vec![vec![], sig1, sig2, redeem_script]);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_p2wsh_multisig_with_mixed_sighash() {
        let sig1 = make_ecdsa_sig_sighash_all();
        let sig2 = make_ecdsa_sig_sighash_none();
        let redeem_script = vec![0x52, 0x21];

        let input = make_witness_input(vec![vec![], sig1, sig2, redeem_script]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_taproot_with_annex() {
        // Taproot with 2-element witness: signature + annex
        let sig = make_schnorr_sig_sighash_all();
        let annex = vec![0x50, 0x01, 0x02]; // Annex starts with 0x50
        let input = make_witness_input(vec![sig, annex]);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_taproot_with_annex_and_sighash_none() {
        // Taproot with 2-element witness but invalid sighash
        let sig = make_schnorr_sig_sighash_none();
        let annex = vec![0x50, 0x01, 0x02];
        let input = make_witness_input(vec![sig, annex]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_accepts_taproot_script_path_with_valid_sigs() {
        // Taproot script-path: [sig, script, control_block]
        // Control block starts with 0xc0 or 0xc1 (leaf version)
        let sig = make_schnorr_sig_sighash_all();
        let script = vec![0x51]; // OP_TRUE
        let control_block = vec![0xc0, 0x01, 0x02, 0x03]; // Starts with 0xc0

        let input = make_witness_input(vec![sig, script, control_block]);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_taproot_script_path_with_invalid_sig() {
        // Taproot script-path with invalid sighash
        let sig = make_schnorr_sig_sighash_none();
        let script = vec![0x51]; // OP_TRUE
        let control_block = vec![0xc1, 0x01, 0x02, 0x03]; // Starts with 0xc1

        let input = make_witness_input(vec![sig, script, control_block]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_taproot_script_path_without_signatures() {
        // Taproot script-path witness missing any 64/65-byte signature elements
        let stack_value = vec![0x01, 0x02, 0x03]; // Non-signature stack element
        let script = vec![0x51]; // OP_TRUE
        let control_block = vec![0xc0, 0x01, 0x02, 0x03]; // Starts with 0xc0

        let input = make_witness_input(vec![stack_value, script, control_block]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_p2wsh_without_signatures() {
        // P2WSH witness that contains no DER signatures before the redeem script
        let placeholder = vec![]; // OP_0 placeholder
        let data = vec![0x01, 0x02, 0x03]; // Not a DER signature (does not start with 0x30)
        let redeem_script = vec![0x51]; // OP_TRUE redeem script

        let input = make_witness_input(vec![placeholder, data, redeem_script]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_unknown_witness_structure() {
        // Single element witness that's not a valid Schnorr signature size
        let unknown_data = vec![0x01, 0x02, 0x03]; // 3 bytes, not 64 or 65
        let input = make_witness_input(vec![unknown_data]);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_rejects_scriptsig_without_signatures() {
        // Script_sig with only a pubkey push (no signature)
        let pubkey = make_pubkey();
        let script_sig = ScriptBuf::builder()
            .push_slice(PushBytesBuf::try_from(pubkey).unwrap())
            .into_script();
        let input = make_scriptsig_input(script_sig);

        assert!(!all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_ignores_non_signature_pushes_in_scriptsig() {
        // Script_sig with a valid signature followed by non-signature data
        let sig = make_ecdsa_sig_sighash_all();
        let pubkey = make_pubkey();
        let extra_data = vec![0x01, 0x02, 0x03]; // Too short to be a signature

        let script_sig = ScriptBuf::builder()
            .push_slice(PushBytesBuf::try_from(sig).unwrap())
            .push_slice(PushBytesBuf::try_from(pubkey).unwrap())
            .push_slice(PushBytesBuf::try_from(extra_data).unwrap())
            .into_script();
        let input = make_scriptsig_input(script_sig);

        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn all_inputs_sighash_all_handles_scriptsig_with_opcodes() {
        // Script_sig with a valid signature followed by an opcode
        let sig = make_ecdsa_sig_sighash_all();
        let pubkey = make_pubkey();

        // P2SH-like script_sig: <sig> <pubkey> <redeem_script_with_opcodes>
        // The redeem script contains opcodes that are not push instructions
        let script_sig = ScriptBuf::builder()
            .push_slice(PushBytesBuf::try_from(sig).unwrap())
            .push_slice(PushBytesBuf::try_from(pubkey).unwrap())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        let input = make_scriptsig_input(script_sig);

        // Should still work because we found valid signatures
        assert!(all_inputs_sighash_all(&[input]));
    }

    #[test]
    fn extract_address_returns_none_for_op_return() {
        let script = build_op_return_script(b"ZELD");
        assert!(extract_address(&script, Network::Bitcoin).is_none());
    }

    #[test]
    fn extract_address_returns_none_for_unknown_script() {
        // OP_CHECKSIG alone is not a valid address script
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(extract_address(&script, Network::Bitcoin).is_none());
    }

    #[test]
    fn extract_address_returns_address_for_p2pkh() {
        // P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        let hash = [0xab; 20];
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(hash)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        let addr = extract_address(&script, Network::Bitcoin);
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with('1')); // Mainnet P2PKH starts with '1'
    }

    #[test]
    fn extract_address_returns_address_for_p2sh() {
        // P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
        let hash = [0xcd; 20];
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(hash)
            .push_opcode(opcodes::all::OP_EQUAL)
            .into_script();
        let addr = extract_address(&script, Network::Bitcoin);
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with('3')); // Mainnet P2SH starts with '3'
    }

    #[test]
    fn extract_address_returns_address_for_p2wpkh() {
        // P2WPKH: OP_0 <20-byte-hash>
        let hash = [0xef; 20];
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_0)
            .push_slice(hash)
            .into_script();
        let addr = extract_address(&script, Network::Bitcoin);
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with("bc1q")); // Mainnet P2WPKH bech32
    }

    #[test]
    fn extract_address_returns_address_for_p2wsh() {
        // P2WSH: OP_0 <32-byte-hash>
        let hash = [0x12; 32];
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_0)
            .push_slice(hash)
            .into_script();
        let addr = extract_address(&script, Network::Bitcoin);
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with("bc1q")); // Mainnet P2WSH bech32
    }

    #[test]
    fn extract_address_returns_address_for_p2tr() {
        // P2TR: OP_1 <32-byte-x-only-pubkey>
        let pubkey = [0x34; 32];
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_slice(pubkey)
            .into_script();
        let addr = extract_address(&script, Network::Bitcoin);
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with("bc1p")); // Mainnet P2TR bech32m
    }

    #[test]
    fn extract_address_uses_correct_network_prefix() {
        // P2WPKH on testnet
        let hash = [0xef; 20];
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_0)
            .push_slice(hash)
            .into_script();

        let mainnet_addr = extract_address(&script, Network::Bitcoin).unwrap();
        let testnet_addr = extract_address(&script, Network::Testnet4).unwrap();

        assert!(mainnet_addr.starts_with("bc1"));
        assert!(testnet_addr.starts_with("tb1"));
    }
}
