#![forbid(unsafe_code)]

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar, traits::Identity};
use ed25519_dalek::{Signature, VerifyingKey};
use out_primitives::Hash32;

pub const TX_SIGN_CONTEXT: &str = "OUT Consensus v0 2026-08-30 transaction signing digest";
pub const TX_ID_CONTEXT: &str = "OUT Consensus v0 2026-08-30 transaction identifier";
pub const BLOCK_ID_CONTEXT: &str = "OUT Consensus v0 2026-08-30 block identifier";
pub const POW_CONTEXT: &str = "OUT Consensus v0 2026-08-30 proof of work header";
pub const ACCOUNT_KEY_CONTEXT: &str = "OUT Consensus v0 2026-08-30 account key";
pub const STATE_LEAF_CONTEXT: &str = "OUT Consensus v0 2026-08-30 state leaf";
pub const STATE_NODE_CONTEXT: &str = "OUT Consensus v0 2026-08-30 state internal node";
pub const TX_MERKLE_LEAF_CONTEXT: &str = "OUT Consensus v0 2026-08-30 transaction Merkle leaf";
pub const TX_MERKLE_NODE_CONTEXT: &str =
    "OUT Consensus v0 2026-08-30 transaction Merkle internal node";
pub const GENESIS_CONTEXT: &str = "OUT Consensus v0 2026-08-30 genesis commitment";
pub const SNAPSHOT_CONTEXT: &str = "OUT Consensus v0 2026-08-30 snapshot commitment";
pub const P2P_CHECKSUM_CONTEXT: &str = "OUT Protocol v0 2026-08-30 P2P message checksum";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusDomain {
    TransactionSigning,
    TransactionId,
    BlockId,
    ProofOfWork,
    AccountKey,
    StateLeaf,
    StateNode,
    TransactionMerkleLeaf,
    TransactionMerkleNode,
    Genesis,
    Snapshot,
    P2pChecksum,
}

impl ConsensusDomain {
    pub const fn context(self) -> &'static str {
        match self {
            Self::TransactionSigning => TX_SIGN_CONTEXT,
            Self::TransactionId => TX_ID_CONTEXT,
            Self::BlockId => BLOCK_ID_CONTEXT,
            Self::ProofOfWork => POW_CONTEXT,
            Self::AccountKey => ACCOUNT_KEY_CONTEXT,
            Self::StateLeaf => STATE_LEAF_CONTEXT,
            Self::StateNode => STATE_NODE_CONTEXT,
            Self::TransactionMerkleLeaf => TX_MERKLE_LEAF_CONTEXT,
            Self::TransactionMerkleNode => TX_MERKLE_NODE_CONTEXT,
            Self::Genesis => GENESIS_CONTEXT,
            Self::Snapshot => SNAPSHOT_CONTEXT,
            Self::P2pChecksum => P2P_CHECKSUM_CONTEXT,
        }
    }
}

/// Consensus requires BLAKE3 derive-key mode. A closed domain enum prevents
/// callers from selecting an unratified or attacker-controlled context.
pub trait ConsensusHasher {
    fn hash_32(&self, domain: ConsensusDomain, material: &[u8]) -> Hash32;
}

/// The consensus BLAKE3 implementation. The context is restricted to a
/// hard-coded static string so network-controlled data cannot become a domain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Blake3Hasher;

impl ConsensusHasher for Blake3Hasher {
    fn hash_32(&self, domain: ConsensusDomain, material: &[u8]) -> Hash32 {
        Hash32::new(blake3::derive_key(domain.context(), material))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    MalformedPublicKey,
    WeakPublicKey,
    MalformedSignature,
    NonCanonicalScalar,
    WeakRPoint,
    EquationMismatch,
}

/// No default verifier is provided until a dependency is proven to enforce
/// all strict verification rules in consensus-v0.md section 4.
pub trait StrictEd25519Verifier {
    fn verify_strict(
        &self,
        public_key: &[u8; 32],
        message_digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), SignatureError>;
}

/// Consensus verifier for pure Ed25519. It adds OUT's full prime-subgroup and
/// canonical-reencoding requirements before the library's uncofactored strict
/// verification equation. Batch and legacy-compatibility features are absent.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DalekStrictVerifier;

impl DalekStrictVerifier {
    pub fn validate_public_key(public_key: &[u8; 32]) -> Result<(), SignatureError> {
        validate_point(public_key, PointRole::PublicKey)
    }

    pub fn validate_signature_encoding(signature: &[u8; 64]) -> Result<(), SignatureError> {
        let mut r_bytes = [0_u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        validate_point(&r_bytes, PointRole::SignatureR)?;

        let mut s_bytes = [0_u8; 32];
        s_bytes.copy_from_slice(&signature[32..]);
        if bool::from(Scalar::from_canonical_bytes(s_bytes).is_none()) {
            return Err(SignatureError::NonCanonicalScalar);
        }
        Ok(())
    }
}

impl StrictEd25519Verifier for DalekStrictVerifier {
    fn verify_strict(
        &self,
        public_key: &[u8; 32],
        message_digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), SignatureError> {
        Self::validate_public_key(public_key)?;
        Self::validate_signature_encoding(signature)?;

        let verifying_key =
            VerifyingKey::from_bytes(public_key).map_err(|_| SignatureError::MalformedPublicKey)?;
        let parsed_signature = Signature::from_bytes(signature);
        verifying_key
            .verify_strict(message_digest, &parsed_signature)
            .map_err(|_| SignatureError::EquationMismatch)
    }
}

#[derive(Clone, Copy)]
enum PointRole {
    PublicKey,
    SignatureR,
}

fn validate_point(bytes: &[u8; 32], role: PointRole) -> Result<(), SignatureError> {
    let point = CompressedEdwardsY(*bytes).decompress().ok_or(match role {
        PointRole::PublicKey => SignatureError::MalformedPublicKey,
        PointRole::SignatureR => SignatureError::MalformedSignature,
    })?;

    if point.compress().to_bytes() != *bytes {
        return Err(match role {
            PointRole::PublicKey => SignatureError::MalformedPublicKey,
            PointRole::SignatureR => SignatureError::MalformedSignature,
        });
    }

    if point == curve25519_dalek::edwards::EdwardsPoint::identity() || !point.is_torsion_free() {
        return Err(match role {
            PointRole::PublicKey => SignatureError::WeakPublicKey,
            PointRole::SignatureR => SignatureError::WeakRPoint,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        let mut output = [0_u8; N];
        for (index, pair) in input.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = char::from(pair[0]).to_digit(16).expect("valid hex");
            let low = char::from(pair[1]).to_digit(16).expect("valid hex");
            output[index] = u8::try_from((high << 4) | low).expect("hex byte");
        }
        output
    }

    #[test]
    fn blake3_signing_digest_matches_verified_vector() {
        let material = hex::<195>("000000000000bc0000fb2651b3fba992e8836d846280745eb7a21d4962d4306858bbfb42690bde49c400000003baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a70003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000000000000000029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd700000000075bcd1500000000000003e8000000000000000100000000000003e8000a4f555420766563746f72");
        let expected =
            hex::<32>("cd232a5f2e62648203b9c1acba9865e6459f210c8bf7a3c90805f698ac6d2c7e");
        assert_eq!(
            Blake3Hasher
                .hash_32(ConsensusDomain::TransactionSigning, &material)
                .into_bytes(),
            expected
        );
    }

    #[test]
    fn verified_transaction_signature_is_accepted() {
        let public_key =
            hex::<32>("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        let digest = hex::<32>("cd232a5f2e62648203b9c1acba9865e6459f210c8bf7a3c90805f698ac6d2c7e");
        let signature = hex::<64>("4db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b");
        assert_eq!(
            DalekStrictVerifier.verify_strict(&public_key, &digest, &signature),
            Ok(())
        );
    }

    #[test]
    fn changed_digest_is_rejected() {
        let public_key =
            hex::<32>("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        let mut digest =
            hex::<32>("cd232a5f2e62648203b9c1acba9865e6459f210c8bf7a3c90805f698ac6d2c7e");
        digest[0] ^= 1;
        let signature = hex::<64>("4db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b");
        assert_eq!(
            DalekStrictVerifier.verify_strict(&public_key, &digest, &signature),
            Err(SignatureError::EquationMismatch)
        );
    }

    #[test]
    fn identity_and_mixed_order_keys_are_rejected() {
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        assert_eq!(
            DalekStrictVerifier::validate_public_key(&identity),
            Err(SignatureError::WeakPublicKey)
        );

        let mixed_order = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        assert_eq!(
            DalekStrictVerifier::validate_public_key(&mixed_order),
            Err(SignatureError::WeakPublicKey)
        );
    }

    #[test]
    fn malformed_and_negative_zero_keys_are_rejected() {
        assert_eq!(
            DalekStrictVerifier::validate_public_key(&[0xff; 32]),
            Err(SignatureError::MalformedPublicKey)
        );

        let mut negative_zero = [0_u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert_eq!(
            DalekStrictVerifier::validate_public_key(&negative_zero),
            Err(SignatureError::MalformedPublicKey)
        );
    }

    #[test]
    fn identity_and_mixed_order_r_are_rejected() {
        let public_key =
            hex::<32>("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        let digest = hex::<32>("cd232a5f2e62648203b9c1acba9865e6459f210c8bf7a3c90805f698ac6d2c7e");
        let mut signature = hex::<64>("4db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b");

        signature[..32].fill(0);
        signature[0] = 1;
        assert_eq!(
            DalekStrictVerifier.verify_strict(&public_key, &digest, &signature),
            Err(SignatureError::WeakRPoint)
        );

        signature[..32].copy_from_slice(
            &(ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
                .compress()
                .to_bytes(),
        );
        assert_eq!(
            DalekStrictVerifier.verify_strict(&public_key, &digest, &signature),
            Err(SignatureError::WeakRPoint)
        );
    }

    #[test]
    fn noncanonical_scalar_is_rejected_before_equation() {
        let public_key =
            hex::<32>("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        let digest = hex::<32>("cd232a5f2e62648203b9c1acba9865e6459f210c8bf7a3c90805f698ac6d2c7e");
        let mut signature = hex::<64>("4db0b309e83e23461a59160d12f3a37386b6a4487fc1c0e0686ed031ba34a001bf24e6a71333e0a4f4df223d388623b0ec8b07ebc79ad9d67aecb4c52981ec0b");
        signature[32..].copy_from_slice(&hex::<32>(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ));
        assert_eq!(
            DalekStrictVerifier.verify_strict(&public_key, &digest, &signature),
            Err(SignatureError::NonCanonicalScalar)
        );
    }
}
