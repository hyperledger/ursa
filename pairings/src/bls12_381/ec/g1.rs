use super::g2::G2Affine;
use crate::{
    bls12_381::{Bls12, Fq, Fq12, FqRepr, Fr, FrRepr},
    CurveAffine, CurveProjective, EncodedPoint, Engine, GroupDecodingError, SubgroupCheck,
};
use ff::{BitIterator, Field, PrimeField, PrimeFieldRepr, SqrtField};
use std::fmt;
curve_impl!(
    "G1",
    G1,
    G1Affine,
    G1Prepared,
    Fq,
    Fr,
    G1Uncompressed,
    G1Compressed,
    G2Affine
);

#[derive(Copy, Clone)]
pub struct G1Uncompressed([u8; 96]);

impl AsRef<[u8]> for G1Uncompressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G1Uncompressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G1Uncompressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G1Uncompressed {
    type Affine = G1Affine;

    fn empty() -> Self {
        G1Uncompressed([0; 96])
    }
    fn size() -> usize {
        96
    }
    fn into_affine(&self) -> Result<G1Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        if !affine.is_on_curve() {
            Err(GroupDecodingError::NotOnCurve)
        } else if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G1Affine, GroupDecodingError> {
        // Create a copy of this representation.
        let mut copy = self.0;

        if copy[0] & (1 << 7) != 0 {
            // Distinguisher bit is set, but this should be uncompressed!
            return Err(GroupDecodingError::UnexpectedCompressionMode);
        }

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G1Affine::zero())
            } else {
                Err(GroupDecodingError::UnexpectedInformation)
            }
        } else {
            if copy[0] & (1 << 5) != 0 {
                // The bit indicating the y-coordinate should be lexicographically
                // largest is set, but this is an uncompressed element.
                return Err(GroupDecodingError::UnexpectedInformation);
            }

            // Unset the three most significant bits.
            copy[0] &= 0x1f;

            let mut x = FqRepr([0; 6]);
            let mut y = FqRepr([0; 6]);

            {
                let mut reader = &copy[..];

                x.read_be(&mut reader).unwrap();
                y.read_be(&mut reader).unwrap();
            }

            Ok(G1Affine {
                x: Fq::from_repr(x)
                    .map_err(|e| GroupDecodingError::CoordinateDecodingError("x coordinate", e))?,
                y: Fq::from_repr(y)
                    .map_err(|e| GroupDecodingError::CoordinateDecodingError("y coordinate", e))?,
                infinity: false,
            })
        }
    }
    fn from_affine(affine: G1Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            let mut writer = &mut res.0[..];

            affine.x.into_repr().write_be(&mut writer).unwrap();
            affine.y.into_repr().write_be(&mut writer).unwrap();
        }

        res
    }
}

#[derive(Copy, Clone)]
pub struct G1Compressed([u8; 48]);

impl AsRef<[u8]> for G1Compressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G1Compressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G1Compressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G1Compressed {
    type Affine = G1Affine;

    fn empty() -> Self {
        G1Compressed([0; 48])
    }
    fn size() -> usize {
        48
    }
    fn into_affine(&self) -> Result<G1Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        // NB: Decompression guarantees that it is on the curve already.

        if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G1Affine, GroupDecodingError> {
        // Create a copy of this representation.
        let mut copy = self.0;

        if copy[0] & (1 << 7) == 0 {
            // Distinguisher bit isn't set.
            return Err(GroupDecodingError::UnexpectedCompressionMode);
        }

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G1Affine::zero())
            } else {
                Err(GroupDecodingError::UnexpectedInformation)
            }
        } else {
            // Determine if the intended y coordinate must be greater
            // lexicographically.
            let greatest = copy[0] & (1 << 5) != 0;

            // Unset the three most significant bits.
            copy[0] &= 0x1f;

            let mut x = FqRepr([0; 6]);

            {
                let mut reader = &copy[..];

                x.read_be(&mut reader).unwrap();
            }

            // Interpret as Fq element.
            let x = Fq::from_repr(x)
                .map_err(|e| GroupDecodingError::CoordinateDecodingError("x coordinate", e))?;

            G1Affine::get_point_from_x(x, greatest).ok_or(GroupDecodingError::NotOnCurve)
        }
    }
    fn from_affine(affine: G1Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            {
                let mut writer = &mut res.0[..];

                affine.x.into_repr().write_be(&mut writer).unwrap();
            }

            let mut negy = affine.y;
            negy.negate();

            // Set the third most significant bit if the correct y-coordinate
            // is lexicographically largest.
            if affine.y > negy {
                res.0[0] |= 1 << 5;
            }
        }

        // Set highest bit to distinguish this as a compressed element.
        res.0[0] |= 1 << 7;

        res
    }
}

impl G1Affine {
    fn scale_by_cofactor(&self) -> G1 {
        // G1 cofactor = (x - 1)^2 / 3  = 76329603384216526031706109802092473003
        let cofactor = BitIterator::new([0x8c00aaab0000aaab, 0x396c8c005555e156]);
        self.mul_bits(cofactor)
    }

    fn get_generator() -> Self {
        G1Affine {
            x: super::super::fq::G1_GENERATOR_X,
            y: super::super::fq::G1_GENERATOR_Y,
            infinity: false,
        }
    }

    fn get_coeff_b() -> Fq {
        super::super::fq::B_COEFF
    }

    fn perform_pairing(&self, other: &G2Affine) -> Fq12 {
        super::super::Bls12::pairing(*self, *other)
    }
}

impl G1 {
    fn empirical_recommended_wnaf_for_scalar(scalar: FrRepr) -> usize {
        let num_bits = scalar.num_bits() as usize;

        if num_bits >= 130 {
            4
        } else if num_bits >= 34 {
            3
        } else {
            2
        }
    }

    fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        const RECOMMENDATIONS: [usize; 12] =
            [1, 3, 7, 20, 43, 120, 273, 563, 1630, 3128, 7933, 62569];

        let mut ret = 4;
        for r in &RECOMMENDATIONS {
            if num_scalars > *r {
                ret += 1;
            } else {
                break;
            }
        }

        ret
    }
}

#[derive(Clone, Debug)]
pub struct G1Prepared(pub(crate) G1Affine);

impl G1Prepared {
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn from_affine(p: G1Affine) -> Self {
        G1Prepared(p)
    }
}

mod subgroup_check {

    use super::G1Affine;
    #[cfg(test)]
    use super::G1;
    use crate::SubgroupCheck;
    #[cfg(test)]
    use crate::{CurveAffine, CurveProjective};
    #[cfg(test)]
    use rand_core::SeedableRng;

    impl SubgroupCheck for G1Affine {
        fn in_subgroup(&self) -> bool {
            self.is_on_curve() && self.is_in_correct_subgroup_assuming_on_curve()
        }
    }

    #[test]
    fn test_g1_subgroup_check() {
        use crate::bls12_381::ClearH;
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..32 {
            let p = G1::random(&mut rng).into_affine();
            assert_eq!(
                p.in_subgroup(),
                p.is_in_correct_subgroup_assuming_on_curve()
            );

            let mut pp = p.into_projective();
            pp.clear_h();
            let p = pp.into_affine();
            assert!(p.in_subgroup() && p.is_in_correct_subgroup_assuming_on_curve());
        }
    }
}

#[test]
fn g1_generator() {
    use SqrtField;

    let mut x = Fq::zero();
    let mut i = 0;
    loop {
        // y^2 = x^3 + b
        let mut rhs = x;
        rhs.square();
        rhs.mul_assign(&x);
        rhs.add_assign(&G1Affine::get_coeff_b());

        if let Some(y) = rhs.sqrt() {
            let yrepr = y.into_repr();
            let mut negy = y;
            negy.negate();
            let negyrepr = negy.into_repr();

            let p = G1Affine {
                x,
                y: if yrepr < negyrepr { y } else { negy },
                infinity: false,
            };
            assert!(!p.in_subgroup());

            let g1 = p.scale_by_cofactor();
            if !g1.is_zero() {
                assert_eq!(i, 4);
                let g1 = G1Affine::from(g1);

                assert!(g1.in_subgroup());

                assert_eq!(g1, G1Affine::one());
                break;
            }
        }

        i += 1;
        x.add_assign(&Fq::one());
    }
}

#[test]
fn g1_test_is_valid() {
    // Reject point on isomorphic twist (b = 24)
    {
        let p = G1Affine {
            x: Fq::from_repr(FqRepr([
                0xc58d887b66c035dc,
                0x10cbfd301d553822,
                0xaf23e064f1131ee5,
                0x9fe83b1b4a5d648d,
                0xf583cc5a508f6a40,
                0xc3ad2aefde0bb13,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x60aa6f9552f03aae,
                0xecd01d5181300d35,
                0x8af1cdb8aa8ce167,
                0xe760f57922998c9d,
                0x953703f5795a39e5,
                0xfe3ae0922df702c,
            ]))
            .unwrap(),
            infinity: false,
        };
        assert!(!p.is_on_curve());
    }

    // Reject point on a twist (b = 3)
    {
        let p = G1Affine {
            x: Fq::from_repr(FqRepr([
                0xee6adf83511e15f5,
                0x92ddd328f27a4ba6,
                0xe305bd1ac65adba7,
                0xea034ee2928b30a8,
                0xbd8833dc7c79a7f7,
                0xe45c9f0c0438675,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x3b450eb1ab7b5dad,
                0xa65cb81e975e8675,
                0xaa548682b21726e5,
                0x753ddf21a2601d20,
                0x532d0b640bd3ff8b,
                0x118d2c543f031102,
            ]))
            .unwrap(),
            infinity: false,
        };
        assert!(!p.is_on_curve());
        assert!(!p.in_subgroup());
    }

    // Reject point in an invalid subgroup
    // There is only one r-order subgroup, as r does not divide the cofactor.
    {
        let p = G1Affine {
            x: Fq::from_repr(FqRepr([
                0x76e1c971c6db8fe8,
                0xe37e1a610eff2f79,
                0x88ae9c499f46f0c0,
                0xf35de9ce0d6b4e84,
                0x265bddd23d1dec54,
                0x12a8778088458308,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x8a22defa0d526256,
                0xc57ca55456fcb9ae,
                0x1ba194e89bab2610,
                0x921beef89d4f29df,
                0x5b6fda44ad85fa78,
                0xed74ab9f302cbe0,
            ]))
            .unwrap(),
            infinity: false,
        };
        assert!(p.is_on_curve());
        assert!(!p.in_subgroup());
    }
}

#[test]
fn test_g1_addition_correctness() {
    let mut p = G1 {
        x: Fq::from_repr(FqRepr([
            0x47fd1f891d6e8bbf,
            0x79a3b0448f31a2aa,
            0x81f3339e5f9968f,
            0x485e77d50a5df10d,
            0x4c6fcac4b55fd479,
            0x86ed4d9906fb064,
        ]))
        .unwrap(),
        y: Fq::from_repr(FqRepr([
            0xd25ee6461538c65,
            0x9f3bbb2ecd3719b9,
            0xa06fd3f1e540910d,
            0xcefca68333c35288,
            0x570c8005f8573fa6,
            0x152ca696fe034442,
        ]))
        .unwrap(),
        z: Fq::one(),
    };

    p.add_assign(&G1 {
        x: Fq::from_repr(FqRepr([
            0xeec78f3096213cbf,
            0xa12beb1fea1056e6,
            0xc286c0211c40dd54,
            0x5f44314ec5e3fb03,
            0x24e8538737c6e675,
            0x8abd623a594fba8,
        ]))
        .unwrap(),
        y: Fq::from_repr(FqRepr([
            0x6b0528f088bb7044,
            0x2fdeb5c82917ff9e,
            0x9a5181f2fac226ad,
            0xd65104c6f95a872a,
            0x1f2998a5a9c61253,
            0xe74846154a9e44,
        ]))
        .unwrap(),
        z: Fq::one(),
    });

    let p = G1Affine::from(p);

    assert_eq!(
        p,
        G1Affine {
            x: Fq::from_repr(FqRepr([
                0x6dd3098f22235df,
                0xe865d221c8090260,
                0xeb96bb99fa50779f,
                0xc4f9a52a428e23bb,
                0xd178b28dd4f407ef,
                0x17fb8905e9183c69
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0xd0de9d65292b7710,
                0xf6a05f2bcf1d9ca7,
                0x1040e27012f20b64,
                0xeec8d1a5b7466c58,
                0x4bc362649dce6376,
                0x430cbdc5455b00a
            ]))
            .unwrap(),
            infinity: false,
        }
    );
}

#[test]
fn test_g1_doubling_correctness() {
    let mut p = G1 {
        x: Fq::from_repr(FqRepr([
            0x47fd1f891d6e8bbf,
            0x79a3b0448f31a2aa,
            0x81f3339e5f9968f,
            0x485e77d50a5df10d,
            0x4c6fcac4b55fd479,
            0x86ed4d9906fb064,
        ]))
        .unwrap(),
        y: Fq::from_repr(FqRepr([
            0xd25ee6461538c65,
            0x9f3bbb2ecd3719b9,
            0xa06fd3f1e540910d,
            0xcefca68333c35288,
            0x570c8005f8573fa6,
            0x152ca696fe034442,
        ]))
        .unwrap(),
        z: Fq::one(),
    };

    p.double();

    let p = G1Affine::from(p);

    assert_eq!(
        p,
        G1Affine {
            x: Fq::from_repr(FqRepr([
                0xf939ddfe0ead7018,
                0x3b03942e732aecb,
                0xce0e9c38fdb11851,
                0x4b914c16687dcde0,
                0x66c8baf177d20533,
                0xaf960cff3d83833
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x3f0675695f5177a8,
                0x2b6d82ae178a1ba0,
                0x9096380dd8e51b11,
                0x1771a65b60572f4e,
                0x8b547c1313b27555,
                0x135075589a687b1e
            ]))
            .unwrap(),
            infinity: false,
        }
    );
}

#[test]
fn test_g1_same_y() {
    // Test the addition of two points with different x coordinates
    // but the same y coordinate.

    // x1 = 128100205326445210408953809171070606737678357140298133325128175840781723996595026100005714405541449960643523234125
    // x2 = 3821408151224848222394078037104966877485040835569514006839342061575586899845797797516352881516922679872117658572470
    // y = 2291134451313223670499022936083127939567618746216464377735567679979105510603740918204953301371880765657042046687078

    let a = G1Affine {
        x: Fq::from_repr(FqRepr([
            0xea431f2cc38fc94d,
            0x3ad2354a07f5472b,
            0xfe669f133f16c26a,
            0x71ffa8021531705,
            0x7418d484386d267,
            0xd5108d8ff1fbd6,
        ]))
        .unwrap(),
        y: Fq::from_repr(FqRepr([
            0xa776ccbfe9981766,
            0x255632964ff40f4a,
            0xc09744e650b00499,
            0x520f74773e74c8c3,
            0x484c8fc982008f0,
            0xee2c3d922008cc6,
        ]))
        .unwrap(),
        infinity: false,
    };

    let b = G1Affine {
        x: Fq::from_repr(FqRepr([
            0xe06cdb156b6356b6,
            0xd9040b2d75448ad9,
            0xe702f14bb0e2aca5,
            0xc6e05201e5f83991,
            0xf7c75910816f207c,
            0x18d4043e78103106,
        ]))
        .unwrap(),
        y: Fq::from_repr(FqRepr([
            0xa776ccbfe9981766,
            0x255632964ff40f4a,
            0xc09744e650b00499,
            0x520f74773e74c8c3,
            0x484c8fc982008f0,
            0xee2c3d922008cc6,
        ]))
        .unwrap(),
        infinity: false,
    };

    // Expected
    // x = 52901198670373960614757979459866672334163627229195745167587898707663026648445040826329033206551534205133090753192
    // y = 1711275103908443722918766889652776216989264073722543507596490456144926139887096946237734327757134898380852225872709
    let c = G1Affine {
        x: Fq::from_repr(FqRepr([
            0xef4f05bdd10c8aa8,
            0xad5bf87341a2df9,
            0x81c7424206b78714,
            0x9676ff02ec39c227,
            0x4c12c15d7e55b9f3,
            0x57fd1e317db9bd,
        ]))
        .unwrap(),
        y: Fq::from_repr(FqRepr([
            0x1288334016679345,
            0xf955cd68615ff0b5,
            0xa6998dbaa600f18a,
            0x1267d70db51049fb,
            0x4696deb9ab2ba3e7,
            0xb1e4e11177f59d4,
        ]))
        .unwrap(),
        infinity: false,
    };

    assert!(a.is_on_curve() && a.in_subgroup());
    assert!(b.is_on_curve() && b.in_subgroup());
    assert!(c.is_on_curve() && c.in_subgroup());

    let mut tmp1 = a.into_projective();
    tmp1.add_assign(&b.into_projective());
    assert_eq!(tmp1.into_affine(), c);
    assert_eq!(tmp1, c.into_projective());

    let mut tmp2 = a.into_projective();
    tmp2.add_assign_mixed(&b);
    assert_eq!(tmp2.into_affine(), c);
    assert_eq!(tmp2, c.into_projective());
}

#[test]
fn g1_curve_tests() {
    crate::tests::curve::curve_tests::<G1>();
}
