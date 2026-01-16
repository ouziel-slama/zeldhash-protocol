use crate::types::{Balance, UtxoKey};

/// Abstraction over the persistence layer used by `ZeldProtocol`.
///
/// Any backend that can read and write ZELD balances using the provided key can
/// be used. Higher-level lifecycle management (transactions, staging, etc.) is
/// left to concrete implementations.
pub trait ZeldStore {
    /// Fetches the stored ZELD balance attached to a given UTXO key.
    ///
    /// Positive values represent spendable ZELD, negative values are spent tombstones,
    /// and `0` means either no entry or an empty balance.
    fn get(&mut self, key: &UtxoKey) -> Balance;

    /// Sets the stored ZELD balance assigned to a UTXO key.
    /// Use negative values to mark spent UTXOs.
    fn set(&mut self, key: UtxoKey, value: Balance);
}
