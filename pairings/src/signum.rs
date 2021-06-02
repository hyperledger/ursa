/*!
Signum trait: sgn0 for field elements
*/

use ff::Field;
use std::ops::BitXor;

/// Result of Sgn0
#[derive(Debug, PartialEq, Eq)]
pub enum Sgn0Result {
    /// Either 0 or positive
    NonNegative,
    /// Neither 0 nor positive
    Negative,
}

impl BitXor for Sgn0Result {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        if self == rhs {
            Sgn0Result::NonNegative
        } else {
            Sgn0Result::Negative
        }
    }
}

/// Signum computations and conditional in-place negation
pub trait Signum0: Field {
    /// Returns either Negative or NonNegative
    fn sgn0(&self) -> Sgn0Result;

    /// Negate if the argument is Negative
    fn negate_if(&mut self, sgn: Sgn0Result) {
        if sgn == Sgn0Result::Negative {
            self.negate();
        }
    }
}

#[test]
#[allow(clippy::eq_op)]
fn test_sgn0result_xor() {
    assert_eq!(
        Sgn0Result::Negative ^ Sgn0Result::Negative,
        Sgn0Result::NonNegative
    );
    assert_eq!(
        Sgn0Result::Negative ^ Sgn0Result::NonNegative,
        Sgn0Result::Negative
    );
    assert_eq!(
        Sgn0Result::NonNegative ^ Sgn0Result::Negative,
        Sgn0Result::Negative
    );
    assert_eq!(
        Sgn0Result::NonNegative ^ Sgn0Result::NonNegative,
        Sgn0Result::NonNegative
    );
}
