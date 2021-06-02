/*!
Constants for OSSWU map for G2
*/

use super::chain::chain_p2m9div16;
use super::{osswu_help, OSSWUMap};
use crate::bls12_381::{Fq, Fq2, FqRepr, G2};
use crate::signum::Signum0;
use ff::Field;

pub(super) const ELLP_A: Fq2 = Fq2 {
    c0: Fq(FqRepr([
        0x0000000000000000u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
    ])),
    c1: Fq(FqRepr([
        0xe53a000003135242u64,
        0x01080c0fdef80285u64,
        0xe7889edbe340f6bdu64,
        0x0b51375126310601u64,
        0x02d6985717c744abu64,
        0x1220b4e979ea5467u64,
    ])),
};

pub(super) const ELLP_B: Fq2 = Fq2 {
    c0: Fq(FqRepr([
        0x22ea00000cf89db2u64,
        0x6ec832df71380aa4u64,
        0x6e1b94403db5a66eu64,
        0x75bf3c53a79473bau64,
        0x3dd3a569412c0a34u64,
        0x125cdb5e74dc4fd1u64,
    ])),
    c1: Fq(FqRepr([
        0x22ea00000cf89db2u64,
        0x6ec832df71380aa4u64,
        0x6e1b94403db5a66eu64,
        0x75bf3c53a79473bau64,
        0x3dd3a569412c0a34u64,
        0x125cdb5e74dc4fd1u64,
    ])),
};

const XI: Fq2 = Fq2 {
    c0: Fq(FqRepr([
        0x87ebfffffff9555cu64,
        0x656fffe5da8ffffau64,
        0xfd0749345d33ad2u64,
        0xd951e663066576f4u64,
        0xde291a3d41e980d3u64,
        0x815664c7dfe040du64,
    ])),
    c1: Fq(FqRepr([
        0x43f5fffffffcaaaeu64,
        0x32b7fff2ed47fffdu64,
        0x7e83a49a2e99d69u64,
        0xeca8f3318332bb7au64,
        0xef148d1ea0f4c069u64,
        0x40ab3263eff0206u64,
    ])),
};

const ETAS: [Fq2; 4] = [
    Fq2 {
        c0: Fq(FqRepr([
            0x5e514668ac736d2u64,
            0x9089b4d6b84f3ea5u64,
            0x603c384c224a8b32u64,
            0xf3257909536afea6u64,
            0x5c5cdbabae656d81u64,
            0x75bfa0863c987e9u64,
        ])),
        c1: Fq(FqRepr([
            0x338d9bfe08087330u64,
            0x7b8e48b2bd83cefeu64,
            0x530dad5d306b5be7u64,
            0x5a4d7e8e6c408b6du64,
            0x6258f7a6232cab9bu64,
            0xb985811cce14db5u64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x86716401f7f7377bu64,
            0xa31db74bf3d03101u64,
            0x14232543c6459a3cu64,
            0xa29ccf687448752u64,
            0xe8c2b010201f013cu64,
            0xe68b9d86c9e98e4u64,
        ])),
        c1: Fq(FqRepr([
            0x5e514668ac736d2u64,
            0x9089b4d6b84f3ea5u64,
            0x603c384c224a8b32u64,
            0xf3257909536afea6u64,
            0x5c5cdbabae656d81u64,
            0x75bfa0863c987e9u64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x718fdad24ee1d90fu64,
            0xa58c025bed8276afu64,
            0xc3a10230ab7976fu64,
            0xf0c54df5c8f275e1u64,
            0x4ec2478c28baf465u64,
            0x1129373a90c508e6u64,
        ])),
        c1: Fq(FqRepr([
            0x19af5f980a3680cu64,
            0x4ed7da0e66063afau64,
            0x600354723b5d9972u64,
            0x8b2f958b20d09d72u64,
            0x474938f02d461dbu64,
            0xdcf8b9e0684ab1cu64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0xb8640a067f5c429fu64,
            0xcfd425f04b4dc505u64,
            0x72d7e2ebb535cb1u64,
            0xd947b5f9d2b4754du64,
            0x46a7142740774afbu64,
            0xc31864c32fb3b7eu64,
        ])),
        c1: Fq(FqRepr([
            0x718fdad24ee1d90fu64,
            0xa58c025bed8276afu64,
            0xc3a10230ab7976fu64,
            0xf0c54df5c8f275e1u64,
            0x4ec2478c28baf465u64,
            0x1129373a90c508e6u64,
        ])),
    },
];

pub(crate) const ROOTS_OF_UNITY: [Fq2; 4] = [
    Fq2 {
        c0: Fq(FqRepr([
            0x760900000002fffdu64,
            0xebf4000bc40c0002u64,
            0x5f48985753c758bau64,
            0x77ce585370525745u64,
            0x5c071a97a256ec6du64,
            0x15f65ec3fa80e493u64,
        ])),
        c1: Fq(FqRepr([
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
            0x0000000000000000u64,
        ])),
        c1: Fq(FqRepr([
            0x760900000002fffdu64,
            0xebf4000bc40c0002u64,
            0x5f48985753c758bau64,
            0x77ce585370525745u64,
            0x5c071a97a256ec6du64,
            0x15f65ec3fa80e493u64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x7bcfa7a25aa30fdau64,
            0xdc17dec12a927e7cu64,
            0x2f088dd86b4ebef1u64,
            0xd1ca2087da74d4a7u64,
            0x2da2596696cebc1du64,
            0x0e2b7eedbbfd87d2u64,
        ])),
        c1: Fq(FqRepr([
            0x7bcfa7a25aa30fdau64,
            0xdc17dec12a927e7cu64,
            0x2f088dd86b4ebef1u64,
            0xd1ca2087da74d4a7u64,
            0x2da2596696cebc1du64,
            0x0e2b7eedbbfd87d2u64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x7bcfa7a25aa30fdau64,
            0xdc17dec12a927e7cu64,
            0x2f088dd86b4ebef1u64,
            0xd1ca2087da74d4a7u64,
            0x2da2596696cebc1du64,
            0x0e2b7eedbbfd87d2u64,
        ])),
        c1: Fq(FqRepr([
            0x3e2f585da55c9ad1u64,
            0x4294213d86c18183u64,
            0x382844c88b623732u64,
            0x92ad2afd19103e18u64,
            0x1d794e4fac7cf0b9u64,
            0x0bd592fc7d825ec8u64,
        ])),
    },
];

impl OSSWUMap for G2 {
    fn osswu_map(u: &Fq2) -> G2 {
        // compute x0 and g(x0)
        let [usq, xi_usq, xi2_u4, x0_num, x0_den, gx0_num, gx0_den] =
            osswu_help(u, &XI, &ELLP_A, &ELLP_B);

        // compute g(x0(u)) ^ ((p - 9) // 16)
        let sqrt_candidate = {
            let mut tmp1 = gx0_den; // v
            tmp1.square(); // v^2
            let mut tmp2 = tmp1;
            tmp1.square(); // v^4
            tmp2.mul_assign(&tmp1); // v^6
            tmp2.mul_assign(&gx0_den); // v^7
            tmp2.mul_assign(&gx0_num); // u v^7
            tmp1.square(); // v^8
            tmp1.mul_assign(&tmp2); // u v^15
            let tmp3 = tmp1;
            chain_p2m9div16(&mut tmp1, &tmp3); // (u v^15) ^ ((p - 9) // 16)
            tmp1.mul_assign(&tmp2); // u v^7 (u v^15) ^ ((p - 9) // 16)
            tmp1
        };

        for root in &ROOTS_OF_UNITY[..] {
            let mut y0 = *root;
            y0.mul_assign(&sqrt_candidate);

            let mut tmp = y0;
            tmp.square();
            tmp.mul_assign(&gx0_den);
            if tmp == gx0_num {
                let sgn0_y_xor_u = y0.sgn0() ^ u.sgn0();
                y0.negate_if(sgn0_y_xor_u);
                y0.mul_assign(&gx0_den); // y * x0_den^3 / x0_den^3 = y

                tmp = x0_num;
                tmp.mul_assign(&x0_den); // x0_num * x0_den / x0_den^2 = x0_num / x0_den

                return G2 {
                    x: tmp,
                    y: y0,
                    z: x0_den,
                };
            }
        }

        // If we've gotten here, g(X0(u)) is not square. Use X1 instead.
        let x1_num = {
            let mut tmp = x0_num;
            tmp.mul_assign(&xi_usq);
            tmp
        };
        let gx1_num = {
            let mut tmp = xi2_u4;
            tmp.mul_assign(&xi_usq); // xi^3 u^6
            tmp.mul_assign(&gx0_num);
            tmp
        };
        let sqrt_candidate = {
            let mut tmp = sqrt_candidate;
            tmp.mul_assign(&usq);
            tmp.mul_assign(u);
            tmp
        };
        for eta in &ETAS[..] {
            let mut y1 = *eta;
            y1.mul_assign(&sqrt_candidate);

            let mut tmp = y1;
            tmp.square();
            tmp.mul_assign(&gx0_den);
            if tmp == gx1_num {
                let sgn0_y_xor_u = y1.sgn0() ^ u.sgn0();
                y1.negate_if(sgn0_y_xor_u);
                y1.mul_assign(&gx0_den); // y * x0_den^3 / x0_den^3 = y

                tmp = x1_num;
                tmp.mul_assign(&x0_den); // x1_num * x0_den / x0_den^2 = x1_num / x0_den

                return G2 {
                    x: tmp,
                    y: y1,
                    z: x0_den,
                };
            }
        }

        panic!("Failed to find square root in G2 osswu_map");
    }
}
