use bitcoin::Block;

use crate::{
    config::ZeldConfig,
    helpers::{
        all_inputs_sighash_all, calculate_reward, compute_utxo_key, extract_address,
        leading_zero_count, parse_op_return,
    },
    store::ZeldStore,
    types::{
        PreProcessedZeldBlock, ProcessedZeldBlock, Reward, ZeldInput, ZeldOutput, ZeldTransaction,
    },
};

/// Entry point used to process blocks according to the ZELD protocol.
#[derive(Debug, Clone, Default)]
pub struct ZeldProtocol {
    config: ZeldConfig,
}

impl ZeldProtocol {
    /// Creates a new protocol instance with the given configuration.
    pub fn new(config: ZeldConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the protocol configuration.
    pub fn config(&self) -> &ZeldConfig {
        &self.config
    }

    /// Pre-processes a Bitcoin block, extracting all ZELD-relevant data.
    ///
    /// This phase is **parallelizable** — you can pre-process multiple blocks concurrently.
    /// The returned [`PreProcessedZeldBlock`] contains all transactions with their computed rewards
    /// and distribution hints.
    pub fn pre_process_block(&self, block: &Block) -> PreProcessedZeldBlock {
        let mut transactions = Vec::with_capacity(block.txdata.len());
        let mut max_zero_count: u8 = 0;

        for tx in &block.txdata {
            // Coinbase transactions can never earn ZELD, so ignore them early.
            if tx.is_coinbase() {
                continue;
            }

            // Track how "nice" (leading zero count) each TXID is for block-wide ranking.
            let txid = tx.compute_txid();
            let zero_count = leading_zero_count(&txid);
            max_zero_count = max_zero_count.max(zero_count);

            // Inputs are only represented by their previous UTXO keys.
            let mut inputs = Vec::with_capacity(tx.input.len());
            for input in &tx.input {
                inputs.push(ZeldInput {
                    utxo_key: compute_utxo_key(
                        &input.previous_output.txid,
                        input.previous_output.vout,
                    ),
                });
            }

            // Collect custom distribution hints from OP_RETURN if present.
            let mut distributions: Option<Vec<u64>> = None;
            let mut outputs = Vec::with_capacity(tx.output.len());
            for (vout, out) in tx.output.iter().enumerate() {
                if out.script_pubkey.is_op_return() {
                    if let Some(values) =
                        parse_op_return(&out.script_pubkey, self.config.zeld_prefix)
                    {
                        // Only keep the last valid OP_RETURN payload, per the spec.
                        distributions = Some(values);
                    }
                    continue;
                }
                // Extract address only for the first non-OP_RETURN output (receives the reward).
                let address = if outputs.is_empty() {
                    extract_address(&out.script_pubkey, self.config.network)
                } else {
                    None
                };
                let value = out.value.to_sat();
                outputs.push(ZeldOutput {
                    utxo_key: compute_utxo_key(&txid, vout as u32),
                    value,
                    reward: 0,
                    distribution: 0,
                    vout: vout as u32,
                    address,
                });
            }

            // Apply OP_RETURN-provided custom ZELD distribution only if all inputs
            // are signed with SIGHASH_ALL (ensures distribution cannot be altered).
            let mut has_op_return_distribution = false;
            if let Some(values) = distributions {
                if all_inputs_sighash_all(&tx.input) {
                    for (i, output) in outputs.iter_mut().enumerate() {
                        output.distribution = *values.get(i).unwrap_or(&0);
                    }
                    has_op_return_distribution = true;
                }
                // If sighash check fails, distribution is ignored (automatic distribution applies)
            }

            transactions.push(ZeldTransaction {
                txid,
                inputs,
                outputs,
                zero_count,
                reward: 0,
                has_op_return_distribution,
            });
        }

        if max_zero_count >= self.config.min_zero_count {
            for tx in &mut transactions {
                // Assign protocol reward tiers relative to the block-best transaction.
                tx.reward = calculate_reward(
                    tx.zero_count,
                    max_zero_count,
                    self.config.min_zero_count,
                    self.config.base_reward,
                );
                if tx.reward > 0 && !tx.outputs.is_empty() {
                    // All mined rewards attach to the first non-OP_RETURN output.
                    tx.outputs[0].reward = tx.reward;
                }
            }
        }

        PreProcessedZeldBlock {
            transactions,
            max_zero_count,
        }
    }

    /// Processes a pre-processed block, updating ZELD balances in the store.
    ///
    /// This phase is **sequential** — blocks must be processed in order, one after another.
    /// For each transaction, this method:
    /// 1. Collects ZELD from spent inputs
    /// 2. Applies rewards and distributions to outputs
    /// 3. Updates the store with new balances
    ///
    /// Returns a [`ProcessedZeldBlock`] containing all rewards and block statistics.
    pub fn process_block<S>(
        &self,
        block: &PreProcessedZeldBlock,
        store: &mut S,
    ) -> ProcessedZeldBlock
    where
        S: ZeldStore,
    {
        let mut rewards = Vec::new();
        let mut total_reward: u64 = 0;
        let mut max_zero_count: u8 = 0;
        let mut nicest_txid = None;
        let mut utxo_spent_count = 0;
        let mut new_utxo_count = 0;

        for tx in &block.transactions {
            // Track the nicest txid (highest zero count).
            if tx.zero_count > max_zero_count || nicest_txid.is_none() {
                max_zero_count = tx.zero_count;
                nicest_txid = Some(tx.txid);
            }

            // Collect rewards for outputs with non-zero rewards.
            for output in &tx.outputs {
                if output.reward > 0 {
                    rewards.push(Reward {
                        txid: tx.txid,
                        vout: output.vout,
                        reward: output.reward,
                        zero_count: tx.zero_count,
                        address: output.address.clone(),
                    });
                    total_reward += output.reward;
                }
            }

            // Initialize the ZELD values for the outputs to the reward values.
            let mut outputs_zeld_values = tx
                .outputs
                .iter()
                .map(|output| output.reward)
                .collect::<Vec<_>>();

            // Calculate the total ZELD input from the inputs.
            let mut total_zeld_input: u64 = 0;
            for input in &tx.inputs {
                let zeld_input = store.get(&input.utxo_key);
                if zeld_input > 0 {
                    let amount = u64::try_from(zeld_input).expect("zeld balance overflow");
                    total_zeld_input = total_zeld_input
                        .checked_add(amount)
                        .expect("zeld input overflow");
                    utxo_spent_count += 1;
                    store.set(input.utxo_key, -zeld_input);
                }
            }

            // If there is a total ZELD input distribute the ZELDs.
            if total_zeld_input > 0 && !tx.outputs.is_empty() {
                let shares = if tx.has_op_return_distribution {
                    let mut requested: Vec<u64> = tx
                        .outputs
                        .iter()
                        .map(|output| output.distribution)
                        .collect();
                    let requested_total: u64 = requested.iter().copied().sum();
                    if requested_total > total_zeld_input {
                        // Invalid request: fall back to sending everything to the first output.
                        let mut shares = vec![0; tx.outputs.len()];
                        shares[0] = total_zeld_input;
                        shares
                    } else {
                        if requested_total < total_zeld_input {
                            requested[0] =
                                requested[0].saturating_add(total_zeld_input - requested_total);
                        }
                        requested
                    }
                } else {
                    let mut shares = vec![0; tx.outputs.len()];
                    shares[0] = total_zeld_input;
                    shares
                };

                for (i, value) in shares.into_iter().enumerate() {
                    outputs_zeld_values[i] = outputs_zeld_values[i].saturating_add(value);
                }
            }

            // Set the ZELD values for the outputs.
            outputs_zeld_values
                .iter()
                .enumerate()
                .for_each(|(i, value)| {
                    if *value > 0 {
                        let balance = i64::try_from(*value).expect("zeld balance overflow");
                        store.set(tx.outputs[i].utxo_key, balance);
                        new_utxo_count += 1;
                    }
                });
        }

        ProcessedZeldBlock {
            rewards,
            total_reward,
            max_zero_count,
            nicest_txid,
            utxo_spent_count,
            new_utxo_count,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use super::*;
    use crate::types::{Amount, Balance, UtxoKey};
    use bitcoin::{
        absolute::LockTime,
        block::{Block as BitcoinBlock, Header as BlockHeader, Version as BlockVersion},
        hashes::Hash,
        opcodes,
        pow::CompactTarget,
        script::PushBytesBuf,
        transaction::Version,
        Amount as BtcAmount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness,
    };
    use ciborium::ser::into_writer;
    use std::collections::HashMap;

    #[cfg(coverage)]
    macro_rules! assert_cov {
        ($cond:expr $(, $($msg:tt)+)? ) => {
            assert!($cond);
        };
    }

    #[cfg(not(coverage))]
    macro_rules! assert_cov {
        ($($tt:tt)+) => {
            assert!($($tt)+);
        };
    }

    #[cfg(coverage)]
    macro_rules! assert_eq_cov {
        ($left:expr, $right:expr $(, $($msg:tt)+)? ) => {
            assert_eq!($left, $right);
        };
    }

    #[cfg(not(coverage))]
    macro_rules! assert_eq_cov {
        ($($tt:tt)+) => {
            assert_eq!($($tt)+);
        };
    }

    fn encode_cbor(values: &[u64]) -> Vec<u8> {
        let mut encoded = Vec::new();
        into_writer(values, &mut encoded).expect("failed to encode cbor");
        encoded
    }

    fn op_return_output_from_payload(payload: Vec<u8>) -> TxOut {
        let push = PushBytesBuf::try_from(payload).expect("invalid op_return payload");
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(push)
            .into_script();
        TxOut {
            value: BtcAmount::from_sat(0),
            script_pubkey: script,
        }
    }

    fn op_return_with_prefix(prefix: &[u8], values: &[u64]) -> TxOut {
        let mut payload = prefix.to_vec();
        payload.extend(encode_cbor(values));
        op_return_output_from_payload(payload)
    }

    fn standard_output(value: u64) -> TxOut {
        TxOut {
            value: BtcAmount::from_sat(value),
            script_pubkey: ScriptBuf::builder()
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script(),
        }
    }

    fn previous_outpoint(byte: u8, vout: u32) -> OutPoint {
        let txid = Txid::from_slice(&[byte; 32]).expect("invalid txid bytes");
        OutPoint { txid, vout }
    }

    // Creates a valid DER-encoded ECDSA signature with SIGHASH_ALL
    fn make_ecdsa_sig_sighash_all() -> Vec<u8> {
        let mut sig = vec![
            0x30, 0x44, // SEQUENCE, length 68
            0x02, 0x20, // INTEGER, length 32 (r)
        ];
        sig.extend([0x01; 32]); // r value
        sig.extend([0x02, 0x20]); // INTEGER, length 32 (s)
        sig.extend([0x02; 32]); // s value
        sig.push(0x01); // SIGHASH_ALL
        sig
    }

    // Creates a 33-byte compressed public key
    fn make_pubkey() -> Vec<u8> {
        let mut pk = vec![0x02];
        pk.extend([0xab; 32]);
        pk
    }

    // Creates a valid DER-encoded ECDSA signature with SIGHASH_NONE
    fn make_ecdsa_sig_sighash_none() -> Vec<u8> {
        let mut sig = make_ecdsa_sig_sighash_all();
        *sig.last_mut().unwrap() = 0x02; // SIGHASH_NONE
        sig
    }

    fn make_inputs(outpoints: Vec<OutPoint>) -> Vec<TxIn> {
        outpoints
            .into_iter()
            .map(|previous_output| {
                // Create a P2WPKH-style witness with SIGHASH_ALL signature
                let mut witness = Witness::new();
                witness.push(make_ecdsa_sig_sighash_all());
                witness.push(make_pubkey());
                TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness,
                }
            })
            .collect()
    }

    fn make_inputs_with_sighash_none(outpoints: Vec<OutPoint>) -> Vec<TxIn> {
        outpoints
            .into_iter()
            .map(|previous_output| {
                // Create a P2WPKH-style witness with SIGHASH_NONE signature
                let mut witness = Witness::new();
                witness.push(make_ecdsa_sig_sighash_none());
                witness.push(make_pubkey());
                TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness,
                }
            })
            .collect()
    }

    fn make_transaction(outpoints: Vec<OutPoint>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: make_inputs(outpoints),
            output: outputs,
        }
    }

    fn make_coinbase_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![standard_output(50)],
        }
    }

    fn build_block(txdata: Vec<Transaction>) -> BitcoinBlock {
        let header = BlockHeader {
            version: BlockVersion::TWO,
            prev_blockhash: BlockHash::from_slice(&[0u8; 32]).expect("valid block hash"),
            merkle_root: TxMerkleNode::from_slice(&[0u8; 32]).expect("valid merkle root"),
            time: 0,
            bits: CompactTarget::default(),
            nonce: 0,
        };
        BitcoinBlock { header, txdata }
    }

    fn deterministic_txid(byte: u8) -> Txid {
        Txid::from_slice(&[byte; 32]).expect("valid txid bytes")
    }

    fn fixed_utxo_key(byte: u8) -> UtxoKey {
        [byte; 12]
    }

    fn amount_to_balance(amount: u64) -> Balance {
        i64::try_from(amount).expect("zeld balance overflow")
    }

    fn make_zeld_output(
        utxo_key: UtxoKey,
        value: Amount,
        reward: Amount,
        distribution: Amount,
        vout: u32,
    ) -> ZeldOutput {
        ZeldOutput {
            utxo_key,
            value,
            reward,
            distribution,
            vout,
            address: None,
        }
    }

    #[derive(Default)]
    struct MockStore {
        balances: HashMap<UtxoKey, Balance>,
    }

    impl MockStore {
        fn with_entries(entries: &[(UtxoKey, Balance)]) -> Self {
            let mut balances = HashMap::new();
            for (key, value) in entries {
                balances.insert(*key, *value);
            }
            Self { balances }
        }

        fn balance(&self, key: &UtxoKey) -> Balance {
            *self.balances.get(key).unwrap_or(&0)
        }
    }

    impl ZeldStore for MockStore {
        fn get(&mut self, key: &UtxoKey) -> Balance {
            *self.balances.get(key).unwrap_or(&0)
        }

        fn set(&mut self, key: UtxoKey, value: Balance) {
            self.balances.insert(key, value);
        }
    }

    #[test]
    fn pre_process_block_ignores_coinbase_and_applies_defaults() {
        let config = ZeldConfig {
            min_zero_count: 65,
            base_reward: 500,
            zeld_prefix: b"ZELD",
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let prev_outs = vec![previous_outpoint(0xAA, 1), previous_outpoint(0xBB, 0)];
        let mut invalid_payload = b"BADP".to_vec();
        invalid_payload.extend(encode_cbor(&[1, 2]));

        let tx_outputs = vec![
            standard_output(1_000),
            op_return_output_from_payload(invalid_payload),
            standard_output(2_000),
        ];

        let tx_inputs_clone = prev_outs.clone();
        let non_coinbase = make_transaction(prev_outs.clone(), tx_outputs);
        let block = build_block(vec![make_coinbase_tx(), non_coinbase.clone()]);

        let processed = protocol.pre_process_block(&block);
        assert_eq_cov!(processed.transactions.len(), 1, "coinbase must be skipped");

        let processed_tx = &processed.transactions[0];
        let below_threshold = processed.max_zero_count < protocol.config().min_zero_count;
        assert_cov!(
            below_threshold,
            "zero count threshold should prevent rewards"
        );
        assert_eq!(processed_tx.reward, 0);
        assert!(processed_tx.outputs.iter().all(|o| o.reward == 0));
        assert_eq!(processed_tx.inputs.len(), tx_inputs_clone.len());

        for (input, expected_outpoint) in processed_tx.inputs.iter().zip(prev_outs.iter()) {
            let expected = compute_utxo_key(&expected_outpoint.txid, expected_outpoint.vout);
            assert_eq!(input.utxo_key, expected);
        }

        let txid = non_coinbase.compute_txid();
        assert_eq_cov!(processed_tx.outputs.len(), 2, "op_return outputs removed");
        assert_eq!(processed_tx.outputs[0].vout, 0);
        assert_eq!(processed_tx.outputs[1].vout, 2);
        assert_eq!(processed_tx.outputs[0].utxo_key, compute_utxo_key(&txid, 0));
        assert_eq!(processed_tx.outputs[1].utxo_key, compute_utxo_key(&txid, 2));
        assert!(processed_tx
            .outputs
            .iter()
            .all(|output| output.distribution == 0));
    }

    #[test]
    fn pre_process_block_returns_empty_when_block_only_has_coinbase() {
        let config = ZeldConfig {
            min_zero_count: 32,
            base_reward: 777,
            zeld_prefix: b"ZELD",
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let block = build_block(vec![make_coinbase_tx()]);
        let processed = protocol.pre_process_block(&block);

        let only_coinbase = processed.transactions.is_empty();
        assert_cov!(
            only_coinbase,
            "no non-coinbase transactions must yield zero ZELD entries"
        );
        let max_zero_is_zero = processed.max_zero_count == 0;
        assert_cov!(
            max_zero_is_zero,
            "with no contenders the block-wide maximum stays at zero"
        );
    }

    #[test]
    fn pre_process_block_assigns_rewards_and_custom_distribution() {
        let prefix = b"ZELD";
        let config = ZeldConfig {
            min_zero_count: 0,
            base_reward: 1_024,
            zeld_prefix: prefix,
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let prev_outs = vec![previous_outpoint(0xCC, 0)];
        let tx_outputs = vec![
            standard_output(4_000),
            standard_output(1_000),
            standard_output(0),
            op_return_with_prefix(prefix, &[7, 8]),
        ];
        let rewarding_tx = make_transaction(prev_outs.clone(), tx_outputs);
        let block = build_block(vec![make_coinbase_tx(), rewarding_tx.clone()]);

        let processed = protocol.pre_process_block(&block);
        assert_eq!(processed.transactions.len(), 1);
        let tx = &processed.transactions[0];

        let single_tx_defines_block_max = processed.max_zero_count == tx.zero_count;
        assert_cov!(
            single_tx_defines_block_max,
            "single tx must define block max"
        );
        let rewarded = tx.reward > 0;
        assert_cov!(
            rewarded,
            "reward must be granted when min_zero_count is zero"
        );

        let expected_reward = calculate_reward(
            tx.zero_count,
            processed.max_zero_count,
            protocol.config().min_zero_count,
            protocol.config().base_reward,
        );
        assert_eq!(tx.reward, expected_reward);

        assert_eq!(tx.outputs[0].reward, expected_reward);
        assert!(tx.outputs.iter().skip(1).all(|output| output.reward == 0));

        let op_return_distributions: Vec<_> = tx.outputs.iter().map(|o| o.distribution).collect();
        let matches_hints = op_return_distributions == vec![7, 8, 0];
        assert_cov!(
            matches_hints,
            "distribution hints must map to outputs with defaults"
        );
        assert_cov!(
            tx.has_op_return_distribution,
            "OP_RETURN distribution flag must be set when sighash check passes"
        );

        let txid = rewarding_tx.compute_txid();
        for output in &tx.outputs {
            assert_eq!(output.utxo_key, compute_utxo_key(&txid, output.vout));
        }
    }

    #[test]
    fn pre_process_block_ignores_op_return_with_wrong_prefix() {
        let config = ZeldConfig {
            min_zero_count: 0,
            base_reward: 512,
            zeld_prefix: b"ZELD",
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let prev_outs = vec![previous_outpoint(0xAB, 0)];
        let tx_outputs = vec![
            standard_output(3_000),
            op_return_with_prefix(b"ALT", &[5, 6, 7]),
            standard_output(1_500),
        ];
        let block = build_block(vec![
            make_coinbase_tx(),
            make_transaction(prev_outs, tx_outputs),
        ]);

        let processed = protocol.pre_process_block(&block);
        assert_eq!(processed.transactions.len(), 1);
        let tx = &processed.transactions[0];

        let ignored_prefix = !tx.has_op_return_distribution;
        assert_cov!(
            ignored_prefix,
            "non-matching OP_RETURN prefixes must be ignored"
        );
        let default_distributions = tx.outputs.iter().all(|output| output.distribution == 0);
        assert_cov!(
            default_distributions,
            "mismatched hints must leave outputs at default distributions"
        );
    }

    #[test]
    fn pre_process_block_keeps_last_valid_op_return() {
        let prefix = b"ZELD";
        let config = ZeldConfig {
            min_zero_count: 0,
            base_reward: 1_024,
            zeld_prefix: prefix,
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let prev_outs = vec![previous_outpoint(0xAC, 0)];
        let tx_outputs = vec![
            standard_output(2_000),
            standard_output(3_000),
            op_return_with_prefix(prefix, &[5, 6]),
            // Trailing invalid OP_RETURN must not override the last valid payload.
            op_return_output_from_payload(b"BAD!".to_vec()),
        ];
        let block = build_block(vec![
            make_coinbase_tx(),
            make_transaction(prev_outs, tx_outputs),
        ]);

        let processed = protocol.pre_process_block(&block);
        assert_eq_cov!(processed.transactions.len(), 1);
        let tx = &processed.transactions[0];

        assert_cov!(
            tx.has_op_return_distribution,
            "valid OP_RETURN must be retained"
        );
        let distributions: Vec<_> = tx.outputs.iter().map(|o| o.distribution).collect();
        assert_eq_cov!(
            distributions,
            vec![5, 6],
            "last valid payload drives distribution"
        );
    }

    #[test]
    fn pre_process_block_handles_transactions_with_only_op_return_outputs() {
        let prefix = b"ZELD";
        let config = ZeldConfig {
            min_zero_count: 0,
            base_reward: 2_048,
            zeld_prefix: prefix,
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let prev_outs = vec![previous_outpoint(0xEF, 1)];
        let op_return_only_tx = make_transaction(
            prev_outs,
            vec![op_return_with_prefix(prefix, &[42, 43, 44])],
        );
        let block = build_block(vec![make_coinbase_tx(), op_return_only_tx]);

        let processed = protocol.pre_process_block(&block);
        assert_eq!(processed.transactions.len(), 1);
        let tx = &processed.transactions[0];

        let op_return_only = tx.outputs.is_empty();
        assert_cov!(
            op_return_only,
            "OP_RETURN-only transactions should not produce spendable outputs"
        );
        let defines_block_max = processed.max_zero_count == tx.zero_count;
        assert_cov!(
            defines_block_max,
            "single ZELD candidate defines the block-wide zero count"
        );
        let matches_base_reward = tx.reward == protocol.config().base_reward;
        assert_cov!(
            matches_base_reward,
            "eligible OP_RETURN-only transactions still earn ZELD"
        );
        let inputs_tracked = tx.inputs.iter().all(|input| input.utxo_key != [0; 12]);
        assert_cov!(
            inputs_tracked,
            "inputs must still be tracked even without spendable outputs"
        );
    }

    #[test]
    fn pre_process_block_ignores_op_return_distribution_when_sighash_invalid() {
        let prefix = b"ZELD";
        let config = ZeldConfig {
            min_zero_count: 0,
            base_reward: 512,
            zeld_prefix: prefix,
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        // Transaction with valid OP_RETURN but SIGHASH_NONE signature
        let prev_outs = vec![previous_outpoint(0xAD, 0)];
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: make_inputs_with_sighash_none(prev_outs),
            output: vec![
                standard_output(3_000),
                standard_output(2_000),
                op_return_with_prefix(prefix, &[100, 200]),
            ],
        };
        let block = build_block(vec![make_coinbase_tx(), tx]);

        let processed = protocol.pre_process_block(&block);
        assert_eq!(processed.transactions.len(), 1);
        let tx = &processed.transactions[0];

        // OP_RETURN distribution should be ignored due to invalid sighash
        let ignored_distribution = !tx.has_op_return_distribution;
        assert_cov!(
            ignored_distribution,
            "OP_RETURN distribution must be ignored when sighash check fails"
        );

        // All distributions should be zero (default)
        let default_distributions = tx.outputs.iter().all(|o| o.distribution == 0);
        assert_cov!(
            default_distributions,
            "distributions must remain at default when sighash check fails"
        );
    }

    #[test]
    fn pre_process_block_runs_reward_loop_without_payouts_when_base_is_zero() {
        let config = ZeldConfig {
            min_zero_count: 0,
            base_reward: 0,
            zeld_prefix: b"ZELD",
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let prev_outs = vec![previous_outpoint(0xDD, 0)];
        let tx_outputs = vec![standard_output(10_000), standard_output(5_000)];
        let block = build_block(vec![
            make_coinbase_tx(),
            make_transaction(prev_outs, tx_outputs),
        ]);

        let processed = protocol.pre_process_block(&block);
        assert_eq!(processed.transactions.len(), 1);
        let tx = &processed.transactions[0];
        assert_cov!(
            processed.max_zero_count >= protocol.config().min_zero_count,
            "block max should respect the configured threshold"
        );
        assert_eq_cov!(tx.reward, 0, "zero base reward must lead to zero payouts");
        assert!(tx.outputs.iter().all(|o| o.reward == 0));
        let default_distribution = tx.outputs.iter().all(|o| o.distribution == 0);
        assert_cov!(
            default_distribution,
            "no OP_RETURN hints means default distribution"
        );
    }

    #[test]
    fn pre_process_block_only_rewards_transactions_meeting_threshold() {
        let mut best: Option<(Transaction, u8)> = None;
        let mut worst: Option<(Transaction, u8)> = None;

        for byte in 0u8..=200 {
            for vout in 0..=2 {
                let prev = previous_outpoint(byte, vout);
                let tx = make_transaction(
                    vec![prev],
                    vec![standard_output(12_500), standard_output(7_500)],
                );
                let zero_count = leading_zero_count(&tx.compute_txid());

                if best
                    .as_ref()
                    .map(|(_, current)| zero_count > *current)
                    .unwrap_or(true)
                {
                    best = Some((tx.clone(), zero_count));
                }

                if worst
                    .as_ref()
                    .map(|(_, current)| zero_count < *current)
                    .unwrap_or(true)
                {
                    worst = Some((tx.clone(), zero_count));
                }
            }
        }

        let (best_tx, best_zeroes) = best.expect("search must yield at least one candidate");
        let (worst_tx, worst_zeroes) = worst.expect("search must yield at least one candidate");
        let zero_counts_differ = best_zeroes > worst_zeroes;
        assert_cov!(
            zero_counts_differ,
            "search must uncover distinct zero counts"
        );

        let config = ZeldConfig {
            min_zero_count: best_zeroes,
            base_reward: 4_096,
            zeld_prefix: b"ZELD",
            network: Network::Bitcoin,
        };
        let protocol = ZeldProtocol::new(config);

        let best_txid = best_tx.compute_txid();
        let worst_txid = worst_tx.compute_txid();
        let block = build_block(vec![make_coinbase_tx(), best_tx, worst_tx]);

        let processed = protocol.pre_process_block(&block);
        assert_eq!(processed.transactions.len(), 2);
        let block_max_matches_best = processed.max_zero_count == best_zeroes;
        assert_cov!(
            block_max_matches_best,
            "block-wide max must reflect top contender"
        );

        let best_entry = processed
            .transactions
            .iter()
            .find(|tx| tx.txid == best_txid)
            .expect("best transaction must be present");
        let worst_entry = processed
            .transactions
            .iter()
            .find(|tx| tx.txid == worst_txid)
            .expect("worst transaction must be present");

        assert_eq!(best_entry.zero_count, best_zeroes);
        assert_eq!(worst_entry.zero_count, worst_zeroes);

        let best_rewarded = best_entry.reward > 0;
        assert_cov!(
            best_rewarded,
            "threshold-satisfying transaction must get a reward"
        );
        let worst_has_zero_reward = worst_entry.reward == 0;
        assert_cov!(
            worst_has_zero_reward,
            "transactions below the threshold should not earn ZELD"
        );
        let worst_outputs_unrewarded = worst_entry.outputs.iter().all(|out| out.reward == 0);
        assert_cov!(
            worst_outputs_unrewarded,
            "zero-reward transactions must not distribute rewards to outputs"
        );
    }

    #[test]
    fn process_block_distributes_inputs_without_custom_shares() {
        let protocol = ZeldProtocol::new(ZeldConfig::default());

        let input_a = fixed_utxo_key(0x01);
        let input_b = fixed_utxo_key(0x02);
        let mut store = MockStore::with_entries(&[(input_a, 60), (input_b, 0)]);

        let output_a = fixed_utxo_key(0x10);
        let output_b = fixed_utxo_key(0x11);
        let outputs = vec![
            make_zeld_output(output_a, 4_000, 10, 0, 0),
            make_zeld_output(output_b, 1_000, 5, 0, 1),
        ];

        let tx = ZeldTransaction {
            txid: deterministic_txid(0xAA),
            inputs: vec![
                ZeldInput { utxo_key: input_a },
                ZeldInput { utxo_key: input_b },
            ],
            outputs: outputs.clone(),
            zero_count: 0,
            reward: outputs.iter().map(|o| o.reward).sum(),
            has_op_return_distribution: false,
        };

        let block = PreProcessedZeldBlock {
            transactions: vec![tx],
            max_zero_count: 0,
        };

        let result = protocol.process_block(&block, &mut store);

        assert_eq!(store.balance(&input_a), -60);
        assert_eq!(store.balance(&input_b), 0);

        assert_eq!(
            store.get(&output_a),
            amount_to_balance(outputs[0].reward + 60)
        );
        assert_eq!(store.get(&output_b), amount_to_balance(outputs[1].reward));

        // Verify ProcessedZeldBlock fields
        // input_a has 60, input_b has 0, so only 1 is counted as spent
        assert_eq!(result.utxo_spent_count, 1);
        assert_eq!(result.new_utxo_count, outputs.len() as u64);
        assert_eq!(
            result.total_reward,
            outputs.iter().map(|o| o.reward).sum::<u64>()
        );
        assert_eq!(result.max_zero_count, 0);
        assert!(result.nicest_txid.is_some());
    }

    #[test]
    fn process_block_respects_custom_distribution_requests() {
        let protocol = ZeldProtocol::new(ZeldConfig::default());

        let capped_input = fixed_utxo_key(0x80);
        let exact_input = fixed_utxo_key(0x81);
        let remainder_input = fixed_utxo_key(0x82);
        let mut store = MockStore::with_entries(&[
            (capped_input, 50),
            (exact_input, 25),
            (remainder_input, 50),
        ]);

        let capped_output_a = fixed_utxo_key(0x20);
        let capped_output_b = fixed_utxo_key(0x21);
        let capped_outputs = vec![
            make_zeld_output(capped_output_a, 4_000, 2, 40, 0),
            make_zeld_output(capped_output_b, 1_000, 3, 30, 1),
        ];

        let exact_output_a = fixed_utxo_key(0x22);
        let exact_output_b = fixed_utxo_key(0x23);
        let exact_outputs = vec![
            make_zeld_output(exact_output_a, 2_000, 5, 10, 0),
            make_zeld_output(exact_output_b, 3_000, 1, 15, 1),
        ];
        let exact_requested: Vec<_> = exact_outputs.iter().map(|o| o.distribution).collect();

        let remainder_output_a = fixed_utxo_key(0x24);
        let remainder_output_b = fixed_utxo_key(0x25);
        let remainder_outputs = vec![
            make_zeld_output(remainder_output_a, 5_000, 7, 20, 0),
            make_zeld_output(remainder_output_b, 1_000, 0, 10, 1),
        ];

        let capped_tx = ZeldTransaction {
            txid: deterministic_txid(0x01),
            inputs: vec![ZeldInput {
                utxo_key: capped_input,
            }],
            outputs: capped_outputs.clone(),
            zero_count: 0,
            reward: 0,
            has_op_return_distribution: true,
        };
        let exact_tx = ZeldTransaction {
            txid: deterministic_txid(0x02),
            inputs: vec![ZeldInput {
                utxo_key: exact_input,
            }],
            outputs: exact_outputs.clone(),
            zero_count: 0,
            reward: 0,
            has_op_return_distribution: true,
        };
        let remainder_tx = ZeldTransaction {
            txid: deterministic_txid(0x03),
            inputs: vec![ZeldInput {
                utxo_key: remainder_input,
            }],
            outputs: remainder_outputs.clone(),
            zero_count: 0,
            reward: 0,
            has_op_return_distribution: true,
        };

        let block = PreProcessedZeldBlock {
            transactions: vec![capped_tx, exact_tx, remainder_tx],
            max_zero_count: 0,
        };

        let result = protocol.process_block(&block, &mut store);

        assert_eq_cov!(
            store.balance(&capped_input),
            -50,
            "inputs must be marked as spent"
        );
        assert_eq_cov!(
            store.balance(&exact_input),
            -25,
            "inputs must be marked as spent"
        );
        assert_eq_cov!(
            store.balance(&remainder_input),
            -50,
            "inputs must be marked as spent"
        );

        // Verify ProcessedZeldBlock fields
        assert_eq_cov!(
            result.utxo_spent_count,
            3,
            "all 3 inputs had non-zero balances"
        );
        let expected_new_utxos =
            capped_outputs.len() + exact_outputs.len() + remainder_outputs.len();
        assert_eq_cov!(result.new_utxo_count, expected_new_utxos as u64);

        let capped_first_balance = store.balance(&capped_output_a);
        assert_eq_cov!(
            capped_first_balance,
            amount_to_balance(capped_outputs[0].reward + 50)
        );
        let capped_second_balance = store.balance(&capped_output_b);
        assert_eq_cov!(
            capped_second_balance,
            amount_to_balance(capped_outputs[1].reward)
        );

        for (output, requested) in exact_outputs.iter().zip(exact_requested.iter()) {
            let balance = store.balance(&output.utxo_key);
            assert_eq_cov!(
                balance,
                amount_to_balance(output.reward + requested),
                "exact requests must be honored"
            );
        }

        let remainder_first_balance = store.balance(&remainder_output_a);
        assert_eq_cov!(
            remainder_first_balance,
            amount_to_balance(remainder_outputs[0].reward + 40)
        );
        let remainder_second_balance = store.balance(&remainder_output_b);
        assert_eq_cov!(
            remainder_second_balance,
            amount_to_balance(remainder_outputs[1].reward + 10)
        );
    }

    #[test]
    fn process_block_keeps_rewards_on_first_output_with_custom_distribution() {
        let protocol = ZeldProtocol::new(ZeldConfig::default());

        // Inputs carry ZELD; custom distribution requests some for the second output,
        // but mining rewards must stay on the first output.
        let input_key = fixed_utxo_key(0x90);
        let mut store = MockStore::with_entries(&[(input_key, 50)]);

        let reward_output = fixed_utxo_key(0xA0);
        let secondary_output = fixed_utxo_key(0xA1);
        let outputs = vec![
            make_zeld_output(reward_output, 0, 100, 0, 0),
            make_zeld_output(secondary_output, 0, 0, 20, 1),
        ];

        let tx = ZeldTransaction {
            txid: deterministic_txid(0x55),
            inputs: vec![ZeldInput {
                utxo_key: input_key,
            }],
            outputs: outputs.clone(),
            zero_count: 0,
            reward: 100,
            has_op_return_distribution: true,
        };

        let block = PreProcessedZeldBlock {
            transactions: vec![tx],
            max_zero_count: 0,
        };

        let result = protocol.process_block(&block, &mut store);

        // Requested 20 to the second output; remainder (30) stays with the first,
        // which already carried the mining reward (100).
        assert_eq_cov!(store.balance(&reward_output), amount_to_balance(130));
        assert_eq_cov!(store.balance(&secondary_output), amount_to_balance(20));
        assert_eq_cov!(result.total_reward, 100);
        assert_eq_cov!(result.utxo_spent_count, 1);
        assert_eq_cov!(result.new_utxo_count, 2);
    }

    #[test]
    fn process_block_falls_back_when_custom_requests_exceed_inputs() {
        let protocol = ZeldProtocol::new(ZeldConfig::default());

        let input_key = fixed_utxo_key(0x91);
        let mut store = MockStore::with_entries(&[(input_key, 25)]);

        let reward_output = fixed_utxo_key(0xA2);
        let secondary_output = fixed_utxo_key(0xA3);
        let outputs = vec![
            make_zeld_output(reward_output, 0, 64, 40, 0),
            make_zeld_output(secondary_output, 0, 0, 30, 1),
        ];

        let tx = ZeldTransaction {
            txid: deterministic_txid(0x56),
            inputs: vec![ZeldInput {
                utxo_key: input_key,
            }],
            outputs: outputs.clone(),
            zero_count: 0,
            reward: 64,
            has_op_return_distribution: true,
        };

        let block = PreProcessedZeldBlock {
            transactions: vec![tx],
            max_zero_count: 0,
        };

        let result = protocol.process_block(&block, &mut store);

        // Requested 70 while only 25 are available; everything (25) falls back to the first
        // output, which already carries the mining reward (64).
        assert_eq_cov!(store.balance(&reward_output), amount_to_balance(89));
        assert_eq_cov!(store.balance(&secondary_output), 0);
        assert_eq_cov!(result.total_reward, 64);
        assert_eq_cov!(result.utxo_spent_count, 1);
        assert_eq_cov!(result.new_utxo_count, 1);
    }

    #[test]
    fn process_block_skips_zero_valued_outputs() {
        let protocol = ZeldProtocol::new(ZeldConfig::default());

        // Input exists but holds no ZELD.
        let zero_input = fixed_utxo_key(0xA0);
        let mut store = MockStore::with_entries(&[(zero_input, 0)]);

        let zero_output_a = fixed_utxo_key(0xB0);
        let zero_output_b = fixed_utxo_key(0xB1);
        let zero_outputs = vec![
            make_zeld_output(zero_output_a, 1_000, 0, 0, 0),
            make_zeld_output(zero_output_b, 2_000, 0, 0, 1),
        ];

        let zero_output_tx = ZeldTransaction {
            txid: deterministic_txid(0x44),
            inputs: vec![ZeldInput {
                utxo_key: zero_input,
            }],
            outputs: zero_outputs.clone(),
            zero_count: 0,
            reward: 0,
            has_op_return_distribution: false,
        };

        let block = PreProcessedZeldBlock {
            transactions: vec![zero_output_tx],
            max_zero_count: 0,
        };

        let result = protocol.process_block(&block, &mut store);

        assert_eq_cov!(
            result.new_utxo_count,
            0,
            "zero-valued outputs must not create store entries"
        );
        assert_eq_cov!(
            result.total_reward,
            0,
            "zero-valued outputs leave block totals unchanged"
        );
        assert_eq_cov!(
            result.utxo_spent_count,
            0,
            "inputs with zero balance should not be counted as spent"
        );

        for output in zero_outputs {
            assert_eq_cov!(
                store.balance(&output.utxo_key),
                0,
                "store must ignore outputs that hold zero ZELD"
            );
        }
        assert_eq_cov!(
            store.balance(&zero_input),
            0,
            "input should remain zero when it carries no ZELD"
        );
    }

    #[test]
    fn process_block_ignores_already_spent_inputs() {
        let protocol = ZeldProtocol::new(ZeldConfig::default());

        let spent_input = fixed_utxo_key(0xC0);
        let mut store = MockStore::with_entries(&[(spent_input, -40)]);

        let reward_output = fixed_utxo_key(0xC1);
        let outputs = vec![make_zeld_output(reward_output, 0, 10, 0, 0)];

        let tx = ZeldTransaction {
            txid: deterministic_txid(0x66),
            inputs: vec![ZeldInput {
                utxo_key: spent_input,
            }],
            outputs: outputs.clone(),
            zero_count: 0,
            reward: 10,
            has_op_return_distribution: false,
        };

        let block = PreProcessedZeldBlock {
            transactions: vec![tx],
            max_zero_count: 0,
        };

        let result = protocol.process_block(&block, &mut store);

        assert_eq_cov!(
            store.balance(&spent_input),
            -40,
            "already spent inputs must remain untouched"
        );
        assert_eq_cov!(
            store.balance(&reward_output),
            amount_to_balance(outputs[0].reward),
            "rewards still attach to outputs"
        );
        assert_eq_cov!(result.utxo_spent_count, 0);
        assert_eq_cov!(result.new_utxo_count, 1);
        assert_eq_cov!(result.total_reward, 10);
    }

    #[test]
    fn process_block_handles_zero_inputs_and_missing_outputs() {
        let protocol = ZeldProtocol::new(ZeldConfig::default());

        let zero_input = fixed_utxo_key(0x90);
        let producing_input = fixed_utxo_key(0x91);
        let mut store = MockStore::with_entries(&[(zero_input, 0), (producing_input, 25)]);

        let reward_output_a = fixed_utxo_key(0x30);
        let reward_output_b = fixed_utxo_key(0x31);
        let reward_only_outputs = vec![
            make_zeld_output(reward_output_a, 1_000, 11, 0, 0),
            make_zeld_output(reward_output_b, 2_000, 22, 0, 1),
        ];

        let zero_input_tx = ZeldTransaction {
            txid: deterministic_txid(0x10),
            inputs: vec![ZeldInput {
                utxo_key: zero_input,
            }],
            outputs: reward_only_outputs.clone(),
            zero_count: 0,
            reward: 0,
            has_op_return_distribution: false,
        };
        let empty_outputs_tx = ZeldTransaction {
            txid: deterministic_txid(0x11),
            inputs: vec![ZeldInput {
                utxo_key: producing_input,
            }],
            outputs: Vec::new(),
            zero_count: 0,
            reward: 0,
            has_op_return_distribution: true,
        };

        let block = PreProcessedZeldBlock {
            transactions: vec![zero_input_tx, empty_outputs_tx],
            max_zero_count: 0,
        };

        let result = protocol.process_block(&block, &mut store);

        for output in &reward_only_outputs {
            let balance = store.balance(&output.utxo_key);
            assert_eq_cov!(
                balance,
                amount_to_balance(output.reward),
                "no input keeps rewards untouched"
            );
        }

        assert_eq!(store.balance(&zero_input), 0);
        assert_eq!(store.balance(&producing_input), -25);
        let store_entries = store.balances.len();
        assert_eq_cov!(
            store_entries,
            reward_only_outputs.len() + 2,
            "spent inputs must remain as tombstones"
        );

        // Verify ProcessedZeldBlock fields
        // zero_input has 0 balance so it doesn't count as spent, producing_input has 25 so it counts
        assert_eq_cov!(
            result.utxo_spent_count,
            1,
            "only producing_input had non-zero balance"
        );
        // reward_only_outputs has 2 outputs, empty_outputs_tx has 0 outputs
        assert_eq_cov!(result.new_utxo_count, reward_only_outputs.len() as u64);
        // Verify total_reward comes from reward_only_outputs
        let expected_total_reward: u64 = reward_only_outputs.iter().map(|o| o.reward).sum();
        assert_eq_cov!(result.total_reward, expected_total_reward);
    }
}
