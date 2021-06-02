use super::super::{Bls12, Fq, Fq12, Fq2, FqRepr, Fr, FrRepr};
use super::g1::G1Affine;
use crate::{
    CurveAffine, CurveProjective, EncodedPoint, Engine, GroupDecodingError, SubgroupCheck,
};
use ff::{BitIterator, Field, PrimeField, PrimeFieldRepr, SqrtField};
use std::fmt;

curve_impl!(
    "G2",
    G2,
    G2Affine,
    G2Prepared,
    Fq2,
    Fr,
    G2Uncompressed,
    G2Compressed,
    G1Affine
);

#[derive(Copy, Clone)]
pub struct G2Uncompressed([u8; 192]);

impl AsRef<[u8]> for G2Uncompressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G2Uncompressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G2Uncompressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G2Uncompressed {
    type Affine = G2Affine;

    fn empty() -> Self {
        G2Uncompressed([0; 192])
    }
    fn size() -> usize {
        192
    }
    fn into_affine(&self) -> Result<G2Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        if !affine.is_on_curve() {
            Err(GroupDecodingError::NotOnCurve)
        } else if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G2Affine, GroupDecodingError> {
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
                Ok(G2Affine::zero())
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

            let mut x_c0 = FqRepr([0; 6]);
            let mut x_c1 = FqRepr([0; 6]);
            let mut y_c0 = FqRepr([0; 6]);
            let mut y_c1 = FqRepr([0; 6]);

            {
                let mut reader = &copy[..];

                x_c1.read_be(&mut reader).unwrap();
                x_c0.read_be(&mut reader).unwrap();
                y_c1.read_be(&mut reader).unwrap();
                y_c0.read_be(&mut reader).unwrap();
            }

            Ok(G2Affine {
                x: Fq2 {
                    c0: Fq::from_repr(x_c0).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("x coordinate (c0)", e)
                    })?,
                    c1: Fq::from_repr(x_c1).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("x coordinate (c1)", e)
                    })?,
                },
                y: Fq2 {
                    c0: Fq::from_repr(y_c0).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("y coordinate (c0)", e)
                    })?,
                    c1: Fq::from_repr(y_c1).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("y coordinate (c1)", e)
                    })?,
                },
                infinity: false,
            })
        }
    }
    fn from_affine(affine: G2Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            let mut writer = &mut res.0[..];

            affine.x.c1.into_repr().write_be(&mut writer).unwrap();
            affine.x.c0.into_repr().write_be(&mut writer).unwrap();
            affine.y.c1.into_repr().write_be(&mut writer).unwrap();
            affine.y.c0.into_repr().write_be(&mut writer).unwrap();
        }

        res
    }
}

#[derive(Copy, Clone)]
pub struct G2Compressed([u8; 96]);

impl AsRef<[u8]> for G2Compressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G2Compressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G2Compressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G2Compressed {
    type Affine = G2Affine;

    fn empty() -> Self {
        G2Compressed([0; 96])
    }
    fn size() -> usize {
        96
    }
    fn into_affine(&self) -> Result<G2Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        // NB: Decompression guarantees that it is on the curve already.

        if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G2Affine, GroupDecodingError> {
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
                Ok(G2Affine::zero())
            } else {
                Err(GroupDecodingError::UnexpectedInformation)
            }
        } else {
            // Determine if the intended y coordinate must be greater
            // lexicographically.
            let greatest = copy[0] & (1 << 5) != 0;

            // Unset the three most significant bits.
            copy[0] &= 0x1f;

            let mut x_c1 = FqRepr([0; 6]);
            let mut x_c0 = FqRepr([0; 6]);

            {
                let mut reader = &copy[..];

                x_c1.read_be(&mut reader).unwrap();
                x_c0.read_be(&mut reader).unwrap();
            }

            // Interpret as Fq element.
            let x = Fq2 {
                c0: Fq::from_repr(x_c0).map_err(|e| {
                    GroupDecodingError::CoordinateDecodingError("x coordinate (c0)", e)
                })?,
                c1: Fq::from_repr(x_c1).map_err(|e| {
                    GroupDecodingError::CoordinateDecodingError("x coordinate (c1)", e)
                })?,
            };

            G2Affine::get_point_from_x(x, greatest).ok_or(GroupDecodingError::NotOnCurve)
        }
    }
    fn from_affine(affine: G2Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            {
                let mut writer = &mut res.0[..];

                affine.x.c1.into_repr().write_be(&mut writer).unwrap();
                affine.x.c0.into_repr().write_be(&mut writer).unwrap();
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

impl G2Affine {
    fn get_generator() -> Self {
        G2Affine {
            x: Fq2 {
                c0: super::super::fq::G2_GENERATOR_X_C0,
                c1: super::super::fq::G2_GENERATOR_X_C1,
            },
            y: Fq2 {
                c0: super::super::fq::G2_GENERATOR_Y_C0,
                c1: super::super::fq::G2_GENERATOR_Y_C1,
            },
            infinity: false,
        }
    }

    fn get_coeff_b() -> Fq2 {
        Fq2 {
            c0: super::super::fq::B_COEFF,
            c1: super::super::fq::B_COEFF,
        }
    }

    fn scale_by_cofactor(&self) -> G2 {
        // G2 cofactor = (x^8 - 4 x^7 + 5 x^6) - (4 x^4 + 6 x^3 - 4 x^2 - 4 x + 13) // 9
        // 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5
        let cofactor = BitIterator::new([
            0xcf1c38e31c7238e5,
            0x1616ec6e786f0c70,
            0x21537e293a6691ae,
            0xa628f1cb4d9e82ef,
            0xa68a205b2e5a7ddf,
            0xcd91de4547085aba,
            0x91d50792876a202,
            0x5d543a95414e7f1,
        ]);
        self.mul_bits(cofactor)
    }

    fn perform_pairing(&self, other: &G1Affine) -> Fq12 {
        super::super::Bls12::pairing(*other, *self)
    }
}

impl G2 {
    fn empirical_recommended_wnaf_for_scalar(scalar: FrRepr) -> usize {
        let num_bits = scalar.num_bits() as usize;

        if num_bits >= 103 {
            4
        } else if num_bits >= 37 {
            3
        } else {
            2
        }
    }

    fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        const RECOMMENDATIONS: [usize; 11] = [1, 3, 8, 20, 47, 126, 260, 826, 1501, 4555, 84071];

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
pub struct G2Prepared {
    pub(crate) coeffs: Vec<(Fq2, Fq2, Fq2)>,
    pub(crate) infinity: bool,
}

mod subgroup_check {
    use super::G2Affine;
    #[cfg(test)]
    use crate::CurveAffine;
    use crate::SubgroupCheck;
    #[cfg(test)]
    use rand_core::SeedableRng;

    impl SubgroupCheck for G2Affine {
        fn in_subgroup(&self) -> bool {
            self.is_on_curve() && self.is_in_correct_subgroup_assuming_on_curve()
        }
    }

    #[test]
    fn test_g2_subgroup_check() {
        use crate::{
            bls12_381::{ClearH, G2},
            CurveProjective,
        };
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..32 {
            let p = G2::random(&mut rng).into_affine();
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
fn g2_generator() {
    use SqrtField;

    let mut x = Fq2::zero();
    let mut i = 0;
    loop {
        // y^2 = x^3 + b
        let mut rhs = x;
        rhs.square();
        rhs.mul_assign(&x);
        rhs.add_assign(&G2Affine::get_coeff_b());

        if let Some(y) = rhs.sqrt() {
            let mut negy = y;
            negy.negate();

            let p = G2Affine {
                x,
                y: if y < negy { y } else { negy },
                infinity: false,
            };

            assert!(!p.in_subgroup());

            let g2 = p.scale_by_cofactor();
            if !g2.is_zero() {
                assert_eq!(i, 2);
                let g2 = G2Affine::from(g2);

                assert!(g2.in_subgroup());
                assert_eq!(g2, G2Affine::one());
                break;
            }
        }

        i += 1;
        x.add_assign(&Fq2::one());
    }
}

#[test]
fn g2_test_is_valid() {
    // Reject point on isomorphic twist (b = 3 * (u + 1))
    {
        let p = G2Affine {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0xa757072d9fa35ba9,
                    0xae3fb2fb418f6e8a,
                    0xc1598ec46faa0c7c,
                    0x7a17a004747e3dbe,
                    0xcc65406a7c2e5a73,
                    0x10b8c03d64db4d0c,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0xd30e70fe2f029778,
                    0xda30772df0f5212e,
                    0x5b47a9ff9a233a50,
                    0xfb777e5b9b568608,
                    0x789bac1fec71a2b9,
                    0x1342f02e2da54405,
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0xfe0812043de54dca,
                    0xe455171a3d47a646,
                    0xa493f36bc20be98a,
                    0x663015d9410eb608,
                    0x78e82a79d829a544,
                    0x40a00545bb3c1e,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x4709802348e79377,
                    0xb5ac4dc9204bcfbd,
                    0xda361c97d02f42b2,
                    0x15008b1dc399e8df,
                    0x68128fd0548a3829,
                    0x16a613db5c873aaa,
                ]))
                .unwrap(),
            },
            infinity: false,
        };
        assert!(!p.is_on_curve());
    }

    // Reject point on a twist (b = 2 * (u + 1))
    {
        let p = G2Affine {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0xf4fdfe95a705f917,
                    0xc2914df688233238,
                    0x37c6b12cca35a34b,
                    0x41abba710d6c692c,
                    0xffcc4b2b62ce8484,
                    0x6993ec01b8934ed,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0xb94e92d5f874e26,
                    0x44516408bc115d95,
                    0xe93946b290caa591,
                    0xa5a0c2b7131f3555,
                    0x83800965822367e7,
                    0x10cf1d3ad8d90bfa,
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0xbf00334c79701d97,
                    0x4fe714f9ff204f9a,
                    0xab70b28002f3d825,
                    0x5a9171720e73eb51,
                    0x38eb4fd8d658adb7,
                    0xb649051bbc1164d,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x9225814253d7df75,
                    0xc196c2513477f887,
                    0xe05e2fbd15a804e0,
                    0x55f2b8efad953e04,
                    0x7379345eda55265e,
                    0x377f2e6208fd4cb,
                ]))
                .unwrap(),
            },
            infinity: false,
        };
        assert!(!p.is_on_curve());
        assert!(!p.in_subgroup());
    }

    // Reject point in an invalid subgroup
    // There is only one r-order subgroup, as r does not divide the cofactor.
    {
        let p = G2Affine {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x262cea73ea1906c,
                    0x2f08540770fabd6,
                    0x4ceb92d0a76057be,
                    0x2199bc19c48c393d,
                    0x4a151b732a6075bf,
                    0x17762a3b9108c4a7,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x26f461e944bbd3d1,
                    0x298f3189a9cf6ed6,
                    0x74328ad8bc2aa150,
                    0x7e147f3f9e6e241,
                    0x72a9b63583963fff,
                    0x158b0083c000462,
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x91fb0b225ecf103b,
                    0x55d42edc1dc46ba0,
                    0x43939b11997b1943,
                    0x68cad19430706b4d,
                    0x3ccfb97b924dcea8,
                    0x1660f93434588f8d,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0xaaed3985b6dcb9c7,
                    0xc1e985d6d898d9f4,
                    0x618bd2ac3271ac42,
                    0x3940a2dbb914b529,
                    0xbeb88137cf34f3e7,
                    0x1699ee577c61b694,
                ]))
                .unwrap(),
            },
            infinity: false,
        };
        assert!(p.is_on_curve());
        assert!(!p.in_subgroup());
    }
}

#[test]
fn test_g2_addition_correctness() {
    let mut p = G2 {
        x: Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x6c994cc1e303094e,
                0xf034642d2c9e85bd,
                0x275094f1352123a9,
                0x72556c999f3707ac,
                0x4617f2e6774e9711,
                0x100b2fe5bffe030b,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x7a33555977ec608,
                0xe23039d1fe9c0881,
                0x19ce4678aed4fcb5,
                0x4637c4f417667e2e,
                0x93ebe7c3e41f6acc,
                0xde884f89a9a371b,
            ]))
            .unwrap(),
        },
        y: Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xe073119472e1eb62,
                0x44fb3391fe3c9c30,
                0xaa9b066d74694006,
                0x25fd427b4122f231,
                0xd83112aace35cae,
                0x191b2432407cbb7f,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xf68ae82fe97662f5,
                0xe986057068b50b7d,
                0x96c30f0411590b48,
                0x9eaa6d19de569196,
                0xf6a03d31e2ec2183,
                0x3bdafaf7ca9b39b,
            ]))
            .unwrap(),
        },
        z: Fq2::one(),
    };

    p.add_assign(&G2 {
        x: Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xa8c763d25910bdd3,
                0x408777b30ca3add4,
                0x6115fcc12e2769e,
                0x8e73a96b329ad190,
                0x27c546f75ee1f3ab,
                0xa33d27add5e7e82,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x93b1ebcd54870dfe,
                0xf1578300e1342e11,
                0x8270dca3a912407b,
                0x2089faf462438296,
                0x828e5848cd48ea66,
                0x141ecbac1deb038b,
            ]))
            .unwrap(),
        },
        y: Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xf5d2c28857229c3f,
                0x8c1574228757ca23,
                0xe8d8102175f5dc19,
                0x2767032fc37cc31d,
                0xd5ee2aba84fd10fe,
                0x16576ccd3dd0a4e8,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x4da9b6f6a96d1dd2,
                0x9657f7da77f1650e,
                0xbc150712f9ffe6da,
                0x31898db63f87363a,
                0xabab040ddbd097cc,
                0x11ad236b9ba02990,
            ]))
            .unwrap(),
        },
        z: Fq2::one(),
    });

    let p = G2Affine::from(p);

    assert_eq!(
        p,
        G2Affine {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0xcde7ee8a3f2ac8af,
                    0xfc642eb35975b069,
                    0xa7de72b7dd0e64b7,
                    0xf1273e6406eef9cc,
                    0xababd760ff05cb92,
                    0xd7c20456617e89
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0xd1a50b8572cbd2b8,
                    0x238f0ac6119d07df,
                    0x4dbe924fe5fd6ac2,
                    0x8b203284c51edf6b,
                    0xc8a0b730bbb21f5e,
                    0x1a3b59d29a31274
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x9e709e78a8eaa4c9,
                    0xd30921c93ec342f4,
                    0x6d1ef332486f5e34,
                    0x64528ab3863633dc,
                    0x159384333d7cba97,
                    0x4cb84741f3cafe8
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x242af0dc3640e1a4,
                    0xe90a73ad65c66919,
                    0x2bd7ca7f4346f9ec,
                    0x38528f92b689644d,
                    0xb6884deec59fb21f,
                    0x3c075d3ec52ba90
                ]))
                .unwrap(),
            },
            infinity: false,
        }
    );
}

#[test]
fn test_g2_doubling_correctness() {
    let mut p = G2 {
        x: Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x6c994cc1e303094e,
                0xf034642d2c9e85bd,
                0x275094f1352123a9,
                0x72556c999f3707ac,
                0x4617f2e6774e9711,
                0x100b2fe5bffe030b,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x7a33555977ec608,
                0xe23039d1fe9c0881,
                0x19ce4678aed4fcb5,
                0x4637c4f417667e2e,
                0x93ebe7c3e41f6acc,
                0xde884f89a9a371b,
            ]))
            .unwrap(),
        },
        y: Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xe073119472e1eb62,
                0x44fb3391fe3c9c30,
                0xaa9b066d74694006,
                0x25fd427b4122f231,
                0xd83112aace35cae,
                0x191b2432407cbb7f,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xf68ae82fe97662f5,
                0xe986057068b50b7d,
                0x96c30f0411590b48,
                0x9eaa6d19de569196,
                0xf6a03d31e2ec2183,
                0x3bdafaf7ca9b39b,
            ]))
            .unwrap(),
        },
        z: Fq2::one(),
    };

    p.double();

    let p = G2Affine::from(p);

    assert_eq!(
        p,
        G2Affine {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x91ccb1292727c404,
                    0x91a6cb182438fad7,
                    0x116aee59434de902,
                    0xbcedcfce1e52d986,
                    0x9755d4a3926e9862,
                    0x18bab73760fd8024
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x4e7c5e0a2ae5b99e,
                    0x96e582a27f028961,
                    0xc74d1cf4ef2d5926,
                    0xeb0cf5e610ef4fe7,
                    0x7b4c2bae8db6e70b,
                    0xf136e43909fca0
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x954d4466ab13e58,
                    0x3ee42eec614cf890,
                    0x853bb1d28877577e,
                    0xa5a2a51f7fde787b,
                    0x8b92866bc6384188,
                    0x81a53fe531d64ef
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x4c5d607666239b34,
                    0xeddb5f48304d14b3,
                    0x337167ee6e8e3cb6,
                    0xb271f52f12ead742,
                    0x244e6c2015c83348,
                    0x19e2deae6eb9b441
                ]))
                .unwrap(),
            },
            infinity: false,
        }
    );
}

#[test]
fn g2_curve_tests() {
    crate::tests::curve::curve_tests::<G2>();
}
