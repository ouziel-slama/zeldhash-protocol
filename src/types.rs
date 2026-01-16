use bitcoin::Txid;

/// 12-byte key identifying a UTXO, derived from txid and vout via xxh3-128.
pub type UtxoKey = [u8; 12];

/// ZELD balance type (unsigned 64-bit integer).
pub type Amount = u64;

/// Represents a transaction output with ZELD-relevant data.
#[derive(Debug, Clone)]
pub struct ZeldOutput {
    /// Unique key identifying this UTXO.
    pub utxo_key: UtxoKey,
    /// Satoshi value of this output.
    pub value: Amount,
    /// ZELD reward assigned to this output.
    pub reward: Amount,
    /// Custom distribution amount from OP_RETURN (if any).
    pub distribution: Amount,
    /// Output index within the transaction.
    pub vout: u32,
    /// Bitcoin address for the reward-carrying output only (first non-OP_RETURN),
    /// if determinable. `None` for non-standard scripts (e.g., bare multisig),
    /// or for non-reward outputs where no address is stored.
    pub address: Option<String>,
}

/// Represents a transaction input with ZELD-relevant data.
#[derive(Debug, Clone)]
pub struct ZeldInput {
    /// Key of the UTXO being spent.
    pub utxo_key: UtxoKey,
}

/// Pre-processed transaction with all ZELD-relevant fields.
#[derive(Debug, Clone)]
pub struct ZeldTransaction {
    /// Transaction ID.
    pub txid: Txid,
    /// Transaction inputs.
    pub inputs: Vec<ZeldInput>,
    /// Transaction outputs (excluding OP_RETURN).
    pub outputs: Vec<ZeldOutput>,
    /// Number of leading zeros in the txid.
    pub zero_count: u8,
    /// Total ZELD reward for this transaction.
    pub reward: Amount,
    /// Whether custom distribution was specified via OP_RETURN.
    pub has_op_return_distribution: bool,
}

/// Pre-processed block with all ZELD-relevant transactions.
#[derive(Debug, Clone)]
pub struct PreProcessedZeldBlock {
    /// Transactions in the block (excluding coinbase).
    pub transactions: Vec<ZeldTransaction>,
    /// Highest leading zero count among all transactions.
    pub max_zero_count: u8,
}

/// Reward information for a single rewarded output.
#[derive(Debug, Clone)]
pub struct Reward {
    /// Transaction ID that produced the reward.
    pub txid: Txid,
    /// Output index carrying the reward.
    pub vout: u32,
    /// ZELD reward granted to the output.
    pub reward: Amount,
    /// Leading zero count of the transaction ID.
    pub zero_count: u8,
    /// Bitcoin address for the reward-carrying output only (first non-OP_RETURN),
    /// if determinable. `None` for non-standard scripts (e.g., bare multisig),
    /// or for non-reward outputs where no address is stored.
    pub address: Option<String>,
}

/// Fully processed block statistics and reward set.
#[derive(Debug, Clone)]
pub struct ProcessedZeldBlock {
    /// All rewards generated within the block.
    pub rewards: Vec<Reward>,
    /// Sum of all rewards in the block.
    pub total_reward: Amount,
    /// Highest leading zero count observed in the block.
    pub max_zero_count: u8,
    /// TXID of the transaction with the highest zero count.
    pub nicest_txid: Option<Txid>,
    /// Number of previously existing UTXOs spent in the block.
    pub utxo_spent_count: u64,
    /// Number of new UTXOs created in the block.
    pub new_utxo_count: u64,
}
