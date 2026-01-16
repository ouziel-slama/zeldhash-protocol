# zeldhash-protocol

[![Tests](https://github.com/ouziel-slama/zeldhash-protocol/actions/workflows/tests.yml/badge.svg)](https://github.com/ouziel-slama/zeldhash-protocol/actions/workflows/tests.yml)
[![Coverage](https://codecov.io/github/ouziel-slama/zeldhash-protocol/graph/badge.svg?token=SP00JHYPV1)](https://codecov.io/github/ouziel-slama/zeldhash-protocol)
[![Format](https://github.com/ouziel-slama/zeldhash-protocol/actions/workflows/fmt.yml/badge.svg)](https://github.com/ouziel-slama/zeldhash-protocol/actions/workflows/fmt.yml)
[![Clippy](https://github.com/ouziel-slama/zeldhash-protocol/actions/workflows/clippy.yml/badge.svg)](https://github.com/ouziel-slama/zeldhash-protocol/actions/workflows/clippy.yml)
[![Crates.io](https://img.shields.io/crates/v/zeldhash-protocol.svg)](https://crates.io/crates/zeldhash-protocol)
[![Docs.rs](https://docs.rs/zeldhash-protocol/badge.svg)](https://docs.rs/zeldhash-protocol)

A Rust implementation of the [**ZELDHASH (ZELD)**](https://zeldhash.com/) protocol — a system that rewards Bitcoin transactions with aesthetically pleasing transaction IDs (those starting with leading zeros).

## Overview

This library provides a database-agnostic and block parser-agnostic implementation of the ZELD protocol. It focuses purely on the protocol logic, allowing you to integrate it with any Bitcoin block source and any storage backend.

For the complete protocol specification, see [docs/protocol.pdf](docs/protocol.pdf).

## Key Features

- **Storage Agnostic**: Bring your own database by implementing the `ZeldStore` trait
- **Block Parser Agnostic**: Works with any source of `bitcoin::Block` data
- **Parallel Pre-processing**: `pre_process_block` can be executed in parallel across multiple blocks
- **Sequential Processing**: `process_block` must be called sequentially, block after block

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
zeldhash-protocol = "0.1"
bitcoin = "0.32"
```

## Usage

### Two-Phase Block Processing

The protocol processes blocks in two phases:

1. **Pre-processing** (`pre_process_block`): Extracts all ZELD-relevant data from a Bitcoin block. This phase is **parallelizable** — you can pre-process multiple blocks concurrently.

2. **Processing** (`process_block`): Updates ZELD balances in the store. This phase is **sequential** — blocks must be processed in order, one after another.

```rust
use zeldhash_protocol::{ZeldProtocol, ZeldConfig, ZeldNetwork, ZeldStore, Balance, UtxoKey};

// Implement your own store
struct MyStore { /* ... */ }

impl ZeldStore for MyStore {
    fn get(&mut self, key: &UtxoKey) -> Balance {
        // Fetch stored balance (positive = spendable, negative = spent tombstone)
    }

    fn set(&mut self, key: UtxoKey, value: Balance) {
        // Store balance for the given UTXO key
    }
}

fn main() {
    // Create protocol instance with mainnet parameters
    let protocol = ZeldProtocol::new(ZeldConfig::for_network(ZeldNetwork::Mainnet));
    let mut store = MyStore::new();
    
    // Fetch blocks from your Bitcoin source
    let blocks: Vec<bitcoin::Block> = fetch_blocks();
    
    // Phase 1: Pre-process blocks (can be parallelized)
    let zeld_blocks: Vec<_> = blocks
        .par_iter()  // Using rayon for parallelism
        .map(|block| protocol.pre_process_block(block))
        .collect();
    
    // Phase 2: Process blocks sequentially
    for zeld_block in &zeld_blocks {
        protocol.process_block(zeld_block, &mut store);
    }
}
```

### Configuration

```rust
use zeldhash_protocol::{ZeldConfig, ZeldNetwork};

// Use one of the built-in network constants.
let mainnet = ZeldConfig::MAINNET;
let testnet = ZeldConfig::for_network(ZeldNetwork::Testnet4);

// Or describe a fully custom configuration.
let custom = ZeldConfig {
    min_zero_count: 8,
    base_reward: 8_192,
    zeld_prefix: b"ZELD",
    network: bitcoin::Network::Bitcoin,
};
```

## Protocol Summary

### Mining ZELD

- Broadcast a Bitcoin transaction whose txid starts with at least 6 zeros
- The best transaction in a block (most leading zeros) earns 4096 ZELD
- Each fewer zero reduces the reward by 16x (256, 16, 1, ...)
- Coinbase transactions are not eligible

### Distribution

When ZELD is earned or transferred:

- By default, all ZELD goes to the first non-OP_RETURN output
- Newly mined rewards always attach to the first non-OP_RETURN output
- If a transaction has only OP_RETURN outputs, any ZELD is burned

### Custom Distribution

Include an OP_RETURN output with:
- 4-byte prefix: `ZELD`
- CBOR-encoded array of `u64` specifying exact amounts per non-OP_RETURN output
- Extra entries are ignored; missing entries default to 0
- If the requested sum exceeds the available ZELD, the custom plan is ignored and everything goes to the first non-OP_RETURN output
- If the requested sum is below the available ZELD, the remainder is added to the first non-OP_RETURN output
- Only the last valid OP_RETURN payload is considered
- **Important**: All inputs must be signed with `SIGHASH_ALL` (or `SIGHASH_DEFAULT` for Taproot) for the custom distribution to apply. This ensures the distribution cannot be altered after signing. Supported script types: P2PKH, P2WPKH, P2SH-multisig, P2WSH, and P2TR.

## Types

| Type | Description |
|------|-------------|
| `ZeldProtocol` | Main entry point for processing blocks |
| `ZeldConfig` | Protocol configuration parameters (per network) |
| `ZeldNetwork` | Supported Bitcoin networks for ZELD constants |
| `ZeldStore` | Trait for storage backend implementation |
| `PreProcessedZeldBlock` | Pre-processed block data |
| `ZeldTransaction` | Transaction with ZELD-relevant fields |
| `UtxoKey` | 12-byte key identifying a UTXO (`[u8; 12]`) |
| `Amount` | ZELD balance type (`u64`) |
| `Balance` | Stored balance type (`i64`); values outside `i64` will panic during processing |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

