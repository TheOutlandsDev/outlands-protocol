#![forbid(unsafe_code)]

use core::fmt;
use crypto_bigint::{CheckedAdd, NonZero, U256, U512};

pub const OUT_CHAIN_ID: ChainId = ChainId::new([
    0xfb, 0x26, 0x51, 0xb3, 0xfb, 0xa9, 0x92, 0xe8, 0x83, 0x6d, 0x84, 0x62, 0x80, 0x74, 0x5e, 0xb7,
    0xa2, 0x1d, 0x49, 0x62, 0xd4, 0x30, 0x68, 0x58, 0xbb, 0xfb, 0x42, 0x69, 0x0b, 0xde, 0x49, 0xc4,
]);
pub const MAX_MONEY: u64 = 2_102_400_000_000_000;
pub const MAINNET_NETWORK_ID: NetworkId = NetworkId::new(1);
pub const TESTNET_NETWORK_ID: NetworkId = NetworkId::new(2);
pub const DEVNET_NETWORK_ID: NetworkId = NetworkId::new(3);

macro_rules! fixed_32 {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

fixed_32!(ChainId);
fixed_32!(GenesisCommitment);
fixed_32!(BlockId);
fixed_32!(TransactionId);
fixed_32!(TransactionRoot);
fixed_32!(StateRoot);
fixed_32!(Hash32);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkId(u32);

impl NetworkId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Recipient([u8; 33]);

impl Recipient {
    pub const VERSION_V0: u8 = 0;

    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, RecipientError> {
        if bytes[0] != Self::VERSION_V0 {
            return Err(RecipientError::UnsupportedVersion(bytes[0]));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
    pub const fn into_bytes(self) -> [u8; 33] {
        self.0
    }
    pub fn payload_bytes(self) -> [u8; 32] {
        let mut output = [0_u8; 32];
        output.copy_from_slice(&self.0[1..]);
        output
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Recipient").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientError {
    UnsupportedVersion(u8),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
    pub fn checked_add(self, other: Self) -> Result<Self, MoneyError> {
        let sum = u128::from(self.0)
            .checked_add(u128::from(other.0))
            .ok_or(MoneyError::ArithmeticOverflow)?;
        if sum > u128::from(MAX_MONEY) {
            return Err(MoneyError::MaximumExceeded);
        }
        let narrowed = u64::try_from(sum).map_err(|_| MoneyError::ArithmeticOverflow)?;
        Ok(Self(narrowed))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Nonce(u64);

impl Nonce {
    pub const ZERO: Self = Self(0);
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
    pub fn checked_increment(self) -> Result<Self, NonceError> {
        self.0.checked_add(1).map(Self).ok_or(NonceError::Overflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoneyError {
    ArithmeticOverflow,
    MaximumExceeded,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceError {
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct U256Be([u8; 32]);

impl U256Be {
    pub const ZERO: Self = Self([0; 32]);
    pub const ONE: Self = Self([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    pub const MAX: Self = Self([0xff; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Checked unsigned 256-bit addition. The result never wraps or saturates.
    pub fn checked_add(self, other: Self) -> Result<Self, U256ArithmeticError> {
        let sum = self
            .to_uint()
            .checked_add(&other.to_uint())
            .into_option()
            .ok_or(U256ArithmeticError::Overflow)?;
        Ok(Self::from_uint(sum))
    }

    /// Exact OUT block work: floor((2^256 - 1) / (target + 1)) + 1.
    pub fn exact_work(self) -> Result<Self, U256ArithmeticError> {
        if self.is_zero() {
            return Err(U256ArithmeticError::ZeroTarget);
        }
        if self == Self::MAX {
            return Ok(Self::ONE);
        }

        let denominator = self
            .to_uint()
            .checked_add(&U256::ONE)
            .into_option()
            .ok_or(U256ArithmeticError::Overflow)?;
        let nonzero = NonZero::new(denominator)
            .into_option()
            .ok_or(U256ArithmeticError::DivisionByZero)?;
        let quotient = U256::MAX.div_rem_vartime(&nonzero).0;
        let work = quotient
            .checked_add(&U256::ONE)
            .into_option()
            .ok_or(U256ArithmeticError::Overflow)?;
        Ok(Self::from_uint(work))
    }

    /// Computes floor(self * multiplier / divisor) with a 512-bit intermediate.
    pub fn checked_mul_div_u128(
        self,
        multiplier: u128,
        divisor: u128,
    ) -> Result<Self, U256ArithmeticError> {
        if divisor == 0 {
            return Err(U256ArithmeticError::DivisionByZero);
        }

        let wide_value: U512 = self.to_uint().resize();
        let product = wide_value
            .checked_mul(&U512::from_u128(multiplier))
            .into_option()
            .ok_or(U256ArithmeticError::Overflow)?;
        let denominator = NonZero::new(U512::from_u128(divisor))
            .into_option()
            .ok_or(U256ArithmeticError::DivisionByZero)?;
        let quotient = product.div_rem_vartime(&denominator).0;
        let narrowed: U256 = quotient
            .resize_checked()
            .into_option()
            .ok_or(U256ArithmeticError::NarrowingOverflow)?;
        Ok(Self::from_uint(narrowed))
    }

    fn to_uint(self) -> U256 {
        U256::from_be_slice(&self.0)
    }

    fn from_uint(value: U256) -> Self {
        Self(value.to_be_bytes().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum U256ArithmeticError {
    ZeroTarget,
    DivisionByZero,
    Overflow,
    NarrowingOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_big_endian_order_matches_numeric_order() {
        let mut low = [0_u8; 32];
        low[31] = 1;
        let mut high = [0_u8; 32];
        high[30] = 1;
        assert!(U256Be::new(low) < U256Be::new(high));
    }

    #[test]
    fn exact_work_matches_boundary_values() {
        let mut target_one = [0_u8; 32];
        target_one[31] = 1;
        let mut two_to_255 = [0_u8; 32];
        two_to_255[0] = 0x80;
        assert_eq!(
            U256Be::new(target_one).exact_work(),
            Ok(U256Be::new(two_to_255))
        );
        assert_eq!(U256Be::MAX.exact_work(), Ok(U256Be::ONE));
        assert_eq!(
            U256Be::ZERO.exact_work(),
            Err(U256ArithmeticError::ZeroTarget)
        );
    }

    #[test]
    fn devnet_target_has_exact_work_4096() {
        let target = U256Be::new([
            0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]);
        let mut expected = [0_u8; 32];
        expected[30..].copy_from_slice(&4096_u16.to_be_bytes());
        assert_eq!(target.exact_work(), Ok(U256Be::new(expected)));
    }

    #[test]
    fn cumulative_work_addition_is_checked() {
        assert_eq!(
            U256Be::ONE
                .checked_add(U256Be::ONE)
                .expect("sum")
                .as_bytes()[31],
            2
        );
        assert_eq!(
            U256Be::MAX.checked_add(U256Be::ONE),
            Err(U256ArithmeticError::Overflow)
        );
    }

    #[test]
    fn wide_multiply_divide_does_not_truncate_before_division() {
        assert_eq!(U256Be::MAX.checked_mul_div_u128(4, 4), Ok(U256Be::MAX));
        assert_eq!(
            U256Be::ONE.checked_mul_div_u128(1, 0),
            Err(U256ArithmeticError::DivisionByZero)
        );
    }

    #[test]
    fn nonce_does_not_wrap() {
        assert_eq!(
            Nonce::new(u64::MAX).checked_increment(),
            Err(NonceError::Overflow)
        );
    }

    #[test]
    fn money_does_not_exceed_cap() {
        assert_eq!(
            Amount::new(MAX_MONEY).checked_add(Amount::new(1)),
            Err(MoneyError::MaximumExceeded)
        );
    }
}
