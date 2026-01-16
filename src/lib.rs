//! # zeldhash-protocol
//!
//! A Rust implementation of the **ZELDHASH(ZELD)** protocol — a system
//! that rewards Bitcoin transactions with aesthetically pleasing transaction IDs
//! (those starting with leading zeros).
//!
//! ## Overview
//!
//! This library provides a database-agnostic and block parser-agnostic
//! implementation of the ZELD protocol. It focuses purely on the protocol logic,
//! allowing you to integrate it with any Bitcoin block source and any storage backend.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use zeldhash_protocol::{ZeldProtocol, ZeldConfig, ZeldStore};
//!
//! let protocol = ZeldProtocol::new(ZeldConfig::default());
//!
//! // Pre-process blocks (parallelizable)
//! let zeld_block = protocol.pre_process_block(&bitcoin_block);
//!
//! // Process blocks sequentially
//! protocol.process_block(&zeld_block, &mut store);
//! ```

/// Protocol configuration.
pub mod config;
/// Helper functions for ZELD protocol operations.
pub mod helpers;
/// Core protocol implementation.
pub mod protocol;
/// Storage trait abstraction.
pub mod store;
/// Core types used by the protocol.
pub mod types;

pub use config::{ZeldConfig, ZeldNetwork};
pub use protocol::ZeldProtocol;
pub use store::ZeldStore;
pub use types::{
    Amount, Balance, PreProcessedZeldBlock, UtxoKey, ZeldInput, ZeldOutput, ZeldTransaction,
};
