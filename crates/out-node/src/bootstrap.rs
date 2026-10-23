//! Pinned testnet/devnet genesis and storage bootstrap factories.

use std::path::Path;

use out_codec::{Block, BlockBody, BlockHeader, DecodeError, EncodeError};
use out_consensus::chain::{
    validate_pinned_genesis_header, GenesisHeaderValidationFailure, ValidatedHeaderMetadata,
};
use out_primitives::{BlockId, Hash32, TransactionRoot};
use out_state::{compute_state_root, StateTreeError};
use out_storage::redb_backend::{RedbConsensusStore, RedbStorageError};
use out_storage::rocksdb_backend::{RocksdbConsensusStore, RocksdbStorageError};
use out_storage::{InMemoryConsensusStore, InMemoryMutationError, InMemoryReadError};

use crate::{Node, NodeConfig, NodeOpenError, SupportedNetwork};

const TESTNET_HEADER_HEX: &str = "000000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c4000000022a0cd6921865d4514f264cd96ed3f8fb05dba505747f7412e403560a72a7ebe600000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a93728000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec431403d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c2147000000000008364e";
const DEVNET_HEADER_HEX: &str = "000000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a937280000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec431403d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c21470000000000000ac5";
const TESTNET_BLOCK_ID_HEX: &str =
    "15a4d51b737a4e3887218b004389f5245d9a2423af17145aa4686862f050c5cb";
const DEVNET_BLOCK_ID_HEX: &str =
    "bd31ae362fa769dab143ef308f7706a7bea9ae671c8fe21793cd8200d73135c9";
const TESTNET_POW_HASH_HEX: &str =
    "00000dc9b459d2a3bd21cdcefe38e24665b6ca94a2075d3f8f0e4a529049c0b6";
const DEVNET_POW_HASH_HEX: &str =
    "00089b59cde9abecc6421d2cfd06f2abcba5c07dfcb9f3ab1c62e7c22b6b71c5";
const EMPTY_TRANSACTION_ROOT_HEX: &str =
    "da2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec43140";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenesisProfileError {
    EmbeddedHexLength(&'static str),
    EmbeddedHexDigit { field: &'static str, index: u16 },
    HeaderDecode(DecodeError),
    HeaderValidation(GenesisHeaderValidationFailure),
    BlockEncode(EncodeError),
    BlockDecode(DecodeError),
    BlockRoundTrip,
    BlockIdMismatch,
    PowHashMismatch,
    TransactionRootMismatch,
    StateTree(StateTreeError),
    StateRootMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedGenesis {
    pub network: SupportedNetwork,
    pub block: Block,
    pub metadata: ValidatedHeaderMetadata,
    pub canonical_block_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootstrapError<StorageError, ReadError> {
    Genesis(GenesisProfileError),
    Storage(StorageError),
    Node(NodeOpenError<ReadError>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeBootstrap {
    pub network: SupportedNetwork,
    pub maximum_reorganization_blocks: u64,
}

impl NodeBootstrap {
    pub fn pinned_genesis(self) -> Result<PinnedGenesis, GenesisProfileError> {
        pinned_genesis(self.network)
    }

    pub fn create_in_memory(
        self,
    ) -> Result<
        Node<InMemoryConsensusStore>,
        BootstrapError<InMemoryMutationError, InMemoryReadError>,
    > {
        let genesis = self.pinned_genesis().map_err(BootstrapError::Genesis)?;
        let storage = InMemoryConsensusStore::new(genesis.block, genesis.metadata, &[], 0)
            .map_err(BootstrapError::Storage)?;
        Node::new(storage, self.node_config()).map_err(BootstrapError::Node)
    }

    pub fn create_redb(
        self,
        path: impl AsRef<Path>,
    ) -> Result<Node<RedbConsensusStore>, BootstrapError<RedbStorageError, RedbStorageError>> {
        let genesis = self.pinned_genesis().map_err(BootstrapError::Genesis)?;
        let storage = RedbConsensusStore::create(
            path,
            genesis.block,
            genesis.metadata,
            &[],
            0,
            self.network.validation_parameters(),
        )
        .map_err(BootstrapError::Storage)?;
        Node::new(storage, self.node_config()).map_err(BootstrapError::Node)
    }

    pub fn open_redb(
        self,
        path: impl AsRef<Path>,
    ) -> Result<Node<RedbConsensusStore>, BootstrapError<RedbStorageError, RedbStorageError>> {
        let genesis = self.pinned_genesis().map_err(BootstrapError::Genesis)?;
        let storage = RedbConsensusStore::open(
            path,
            genesis.block,
            genesis.metadata,
            &[],
            0,
            self.network.validation_parameters(),
        )
        .map_err(BootstrapError::Storage)?;
        Node::new(storage, self.node_config()).map_err(BootstrapError::Node)
    }

    pub fn create_rocksdb(
        self,
        path: impl AsRef<Path>,
    ) -> Result<Node<RocksdbConsensusStore>, BootstrapError<RocksdbStorageError, RocksdbStorageError>>
    {
        let genesis = self.pinned_genesis().map_err(BootstrapError::Genesis)?;
        let storage = RocksdbConsensusStore::create(
            path,
            genesis.block,
            genesis.metadata,
            &[],
            0,
            self.network.validation_parameters(),
        )
        .map_err(BootstrapError::Storage)?;
        Node::new(storage, self.node_config()).map_err(BootstrapError::Node)
    }

    pub fn open_rocksdb(
        self,
        path: impl AsRef<Path>,
    ) -> Result<Node<RocksdbConsensusStore>, BootstrapError<RocksdbStorageError, RocksdbStorageError>>
    {
        let genesis = self.pinned_genesis().map_err(BootstrapError::Genesis)?;
        let storage = RocksdbConsensusStore::open(
            path,
            genesis.block,
            genesis.metadata,
            &[],
            0,
            self.network.validation_parameters(),
        )
        .map_err(BootstrapError::Storage)?;
        Node::new(storage, self.node_config()).map_err(BootstrapError::Node)
    }

    const fn node_config(self) -> NodeConfig {
        NodeConfig {
            network: self.network,
            maximum_reorganization_blocks: self.maximum_reorganization_blocks,
        }
    }
}

pub fn pinned_genesis(network: SupportedNetwork) -> Result<PinnedGenesis, GenesisProfileError> {
    let (header_hex, block_id_hex, pow_hash_hex) = match network {
        SupportedNetwork::Testnet => (
            TESTNET_HEADER_HEX,
            TESTNET_BLOCK_ID_HEX,
            TESTNET_POW_HASH_HEX,
        ),
        SupportedNetwork::Devnet => (DEVNET_HEADER_HEX, DEVNET_BLOCK_ID_HEX, DEVNET_POW_HASH_HEX),
    };
    let header_bytes = decode_hex_array::<223>("header", header_hex)?;
    let header =
        BlockHeader::decode_exact(&header_bytes).map_err(GenesisProfileError::HeaderDecode)?;
    let metadata =
        validate_pinned_genesis_header(header, header, network.validation_parameters().header)
            .map_err(GenesisProfileError::HeaderValidation)?;

    let expected_block_id = BlockId::new(decode_hex_array("block_id", block_id_hex)?);
    if metadata.block_id() != expected_block_id {
        return Err(GenesisProfileError::BlockIdMismatch);
    }
    let expected_pow_hash = Hash32::new(decode_hex_array("pow_hash", pow_hash_hex)?);
    if metadata.pow_hash() != expected_pow_hash {
        return Err(GenesisProfileError::PowHashMismatch);
    }
    let expected_transaction_root = TransactionRoot::new(decode_hex_array(
        "empty_transaction_root",
        EMPTY_TRANSACTION_ROOT_HEX,
    )?);
    if header.transaction_root != expected_transaction_root {
        return Err(GenesisProfileError::TransactionRootMismatch);
    }
    let expected_state_root = compute_state_root(&[]).map_err(GenesisProfileError::StateTree)?;
    if header.state_root != expected_state_root {
        return Err(GenesisProfileError::StateRootMismatch);
    }

    let block = Block {
        header,
        body: BlockBody {
            transactions: Vec::new(),
        },
    };
    let canonical_block_bytes = block
        .encode_genesis()
        .map_err(GenesisProfileError::BlockEncode)?;
    let decoded = Block::decode_genesis_exact(&canonical_block_bytes)
        .map_err(GenesisProfileError::BlockDecode)?;
    if decoded != block {
        return Err(GenesisProfileError::BlockRoundTrip);
    }
    Ok(PinnedGenesis {
        network,
        block,
        metadata,
        canonical_block_bytes,
    })
}

fn decode_hex_array<const N: usize>(
    field: &'static str,
    input: &str,
) -> Result<[u8; N], GenesisProfileError> {
    if input.len()
        != N.checked_mul(2)
            .ok_or(GenesisProfileError::EmbeddedHexLength(field))?
    {
        return Err(GenesisProfileError::EmbeddedHexLength(field));
    }
    let mut output = [0_u8; N];
    let bytes = input.as_bytes();
    for (index, byte) in output.iter_mut().enumerate() {
        let high_index = index
            .checked_mul(2)
            .ok_or(GenesisProfileError::EmbeddedHexLength(field))?;
        let low_index = high_index
            .checked_add(1)
            .ok_or(GenesisProfileError::EmbeddedHexLength(field))?;
        let high = decode_nibble(bytes[high_index]).ok_or_else(|| {
            GenesisProfileError::EmbeddedHexDigit {
                field,
                index: u16::try_from(high_index).unwrap_or(u16::MAX),
            }
        })?;
        let low = decode_nibble(bytes[low_index]).ok_or_else(|| {
            GenesisProfileError::EmbeddedHexDigit {
                field,
                index: u16::try_from(low_index).unwrap_or(u16::MAX),
            }
        })?;
        *byte = (high << 4) | low;
    }
    Ok(output)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use out_consensus::{DEVNET_GENESIS_COMMITMENT, TESTNET_GENESIS_COMMITMENT};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "out-bootstrap-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn bootstrap(network: SupportedNetwork) -> NodeBootstrap {
        NodeBootstrap {
            network,
            maximum_reorganization_blocks: 100,
        }
    }

    #[test]
    fn both_pinned_profiles_recompute_verified_artifacts() {
        let testnet = pinned_genesis(SupportedNetwork::Testnet).expect("testnet");
        assert_eq!(
            testnet.block.header.genesis_commitment,
            TESTNET_GENESIS_COMMITMENT
        );
        assert_eq!(
            testnet.metadata.block_id().as_bytes(),
            &decode_hex_array::<32>("testnet_id", TESTNET_BLOCK_ID_HEX).expect("id")
        );
        assert_eq!(testnet.canonical_block_bytes.len(), 235);

        let devnet = pinned_genesis(SupportedNetwork::Devnet).expect("devnet");
        assert_eq!(
            devnet.block.header.genesis_commitment,
            DEVNET_GENESIS_COMMITMENT
        );
        assert_eq!(
            devnet.metadata.block_id().as_bytes(),
            &decode_hex_array::<32>("devnet_id", DEVNET_BLOCK_ID_HEX).expect("id")
        );
        assert_eq!(devnet.canonical_block_bytes.len(), 235);
    }

    #[test]
    fn in_memory_factory_opens_both_frozen_networks() {
        for network in [SupportedNetwork::Testnet, SupportedNetwork::Devnet] {
            let node = bootstrap(network).create_in_memory().expect("node");
            let expected = pinned_genesis(network)
                .expect("genesis")
                .metadata
                .block_id();
            assert_eq!(node.canonical_tip().expect("tip").block_id, expected);
        }
    }

    #[test]
    fn redb_factory_create_and_open_use_the_same_pinned_genesis() {
        let path = temporary_path("redb").with_extension("redb");
        let expected = pinned_genesis(SupportedNetwork::Devnet)
            .expect("genesis")
            .metadata
            .block_id();
        let node = bootstrap(SupportedNetwork::Devnet)
            .create_redb(&path)
            .expect("create");
        assert_eq!(node.canonical_tip().expect("tip").block_id, expected);
        drop(node);
        let node = bootstrap(SupportedNetwork::Devnet)
            .open_redb(&path)
            .expect("open");
        assert_eq!(node.canonical_tip().expect("tip").block_id, expected);
        drop(node);
        fs::remove_file(path).expect("remove redb test database");
    }

    #[test]
    fn rocksdb_factory_create_and_open_use_the_same_pinned_genesis() {
        let path = temporary_path("rocksdb");
        let expected = pinned_genesis(SupportedNetwork::Testnet)
            .expect("genesis")
            .metadata
            .block_id();
        let node = bootstrap(SupportedNetwork::Testnet)
            .create_rocksdb(&path)
            .expect("create");
        assert_eq!(node.canonical_tip().expect("tip").block_id, expected);
        drop(node);
        let node = bootstrap(SupportedNetwork::Testnet)
            .open_rocksdb(&path)
            .expect("open");
        assert_eq!(node.canonical_tip().expect("tip").block_id, expected);
        drop(node);
        fs::remove_dir_all(path).expect("remove rocksdb test database");
    }

    #[test]
    fn wrong_network_cannot_open_an_existing_database() {
        let path = temporary_path("network-mismatch").with_extension("redb");
        let node = bootstrap(SupportedNetwork::Devnet)
            .create_redb(&path)
            .expect("create");
        drop(node);
        assert!(bootstrap(SupportedNetwork::Testnet)
            .open_redb(&path)
            .is_err());
        fs::remove_file(path).expect("remove redb test database");
    }

    #[test]
    fn embedded_hex_decoder_is_lowercase_exact_and_bounded() {
        assert_eq!(decode_hex_array::<2>("ok", "00af"), Ok([0x00, 0xaf]));
        assert!(matches!(
            decode_hex_array::<2>("short", "00"),
            Err(GenesisProfileError::EmbeddedHexLength("short"))
        ));
        assert!(matches!(
            decode_hex_array::<1>("upper", "AF"),
            Err(GenesisProfileError::EmbeddedHexDigit { field: "upper", .. })
        ));
    }
}
