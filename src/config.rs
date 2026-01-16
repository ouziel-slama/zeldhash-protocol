use bitcoin::Network;

use crate::types::Amount;

/// Static parameters that describe how the ZELD protocol behaves on a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeldConfig {
    /// Minimum leading zeros required for a transaction to earn ZELD.
    pub min_zero_count: u8,
    /// Base reward for the best transaction in a block.
    pub base_reward: Amount,
    /// Prefix bytes for custom distribution OP_RETURN data.
    pub zeld_prefix: &'static [u8],
    /// Bitcoin network (used for address encoding).
    pub network: Network,
}

/// Bitcoin networks supported by the ZELD protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeldNetwork {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

impl ZeldConfig {
    /// ZELD parameters for Bitcoin mainnet.
    pub const MAINNET: Self = Self {
        min_zero_count: 6,
        base_reward: 4_096 * 10u64.pow(8),
        zeld_prefix: b"ZELD",
        network: Network::Bitcoin,
    };

    /// ZELD parameters for Bitcoin testnet4.
    pub const TESTNET4: Self = Self {
        min_zero_count: 2,
        base_reward: 4_096 * 10u64.pow(8),
        zeld_prefix: b"ZELD",
        network: Network::Testnet4,
    };

    /// ZELD parameters for Bitcoin signet.
    pub const SIGNET: Self = Self {
        min_zero_count: 2,
        base_reward: 4_096 * 10u64.pow(8),
        zeld_prefix: b"ZELD",
        network: Network::Signet,
    };

    /// ZELD parameters for Bitcoin regtest.
    pub const REGTEST: Self = Self {
        min_zero_count: 2,
        base_reward: 4_096 * 10u64.pow(8),
        zeld_prefix: b"ZELD",
        network: Network::Regtest,
    };

    /// Returns the configuration associated with the provided Bitcoin network.
    pub const fn for_network(network: ZeldNetwork) -> Self {
        match network {
            ZeldNetwork::Mainnet => Self::MAINNET,
            ZeldNetwork::Testnet4 => Self::TESTNET4,
            ZeldNetwork::Signet => Self::SIGNET,
            ZeldNetwork::Regtest => Self::REGTEST,
        }
    }
}

impl Default for ZeldConfig {
    fn default() -> Self {
        Self::MAINNET
    }
}

impl From<ZeldNetwork> for ZeldConfig {
    fn from(network: ZeldNetwork) -> Self {
        Self::for_network(network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_config(
        config: ZeldConfig,
        min_zero_count: u8,
        base_reward: Amount,
        prefix: &'static [u8],
        network: Network,
    ) {
        assert_eq!(config.min_zero_count, min_zero_count);
        assert_eq!(config.base_reward, base_reward);
        assert_eq!(config.zeld_prefix, prefix);
        assert_eq!(config.network, network);
    }

    #[test]
    fn constants_expose_expected_parameters() {
        let base_reward = 4_096 * 10u64.pow(8);
        assert_config(
            ZeldConfig::MAINNET,
            6,
            base_reward,
            b"ZELD",
            Network::Bitcoin,
        );
        assert_config(
            ZeldConfig::TESTNET4,
            2,
            base_reward,
            b"ZELD",
            Network::Testnet4,
        );
        assert_config(ZeldConfig::SIGNET, 2, base_reward, b"ZELD", Network::Signet);
        assert_config(
            ZeldConfig::REGTEST,
            2,
            base_reward,
            b"ZELD",
            Network::Regtest,
        );
    }

    #[test]
    fn for_network_routes_to_correct_constants() {
        assert_eq!(
            ZeldConfig::for_network(ZeldNetwork::Mainnet),
            ZeldConfig::MAINNET
        );
        assert_eq!(
            ZeldConfig::for_network(ZeldNetwork::Testnet4),
            ZeldConfig::TESTNET4
        );
        assert_eq!(
            ZeldConfig::for_network(ZeldNetwork::Signet),
            ZeldConfig::SIGNET
        );
        assert_eq!(
            ZeldConfig::for_network(ZeldNetwork::Regtest),
            ZeldConfig::REGTEST
        );
    }

    #[test]
    fn from_network_matches_for_network() {
        let networks = [
            ZeldNetwork::Mainnet,
            ZeldNetwork::Testnet4,
            ZeldNetwork::Signet,
            ZeldNetwork::Regtest,
        ];

        for network in networks {
            assert_eq!(ZeldConfig::from(network), ZeldConfig::for_network(network));
        }
    }

    #[test]
    fn default_matches_mainnet() {
        assert_eq!(ZeldConfig::default(), ZeldConfig::MAINNET);
    }
}
