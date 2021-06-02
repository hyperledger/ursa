/*!
Constants for OSSWU map for G1
*/

use super::chain::chain_pm3div4;
use super::{osswu_help, OSSWUMap};
use crate::bls12_381::{Fq, FqRepr, G1};
use crate::signum::Signum0;
use ff::Field;

pub(super) const ELLP_A: Fq = Fq(FqRepr([
    0x2f65aa0e9af5aa51u64,
    0x86464c2d1e8416c3u64,
    0xb85ce591b7bd31e2u64,
    0x27e11c91b5f24e7cu64,
    0x28376eda6bfc1835u64,
    0x155455c3e5071d85u64,
]));

pub(super) const ELLP_B: Fq = Fq(FqRepr([
    0xfb996971fe22a1e0u64,
    0x9aa93eb35b742d6fu64,
    0x8c476013de99c5c4u64,
    0x873e27c3a221e571u64,
    0xca72b5e45a52d888u64,
    0x06824061418a386bu64,
]));

const XI: Fq = Fq(FqRepr([
    0x886c00000023ffdcu64,
    0xf70008d3090001du64,
    0x77672417ed5828c3u64,
    0x9dac23e943dc1740u64,
    0x50553f1b9c131521u64,
    0x78c712fbe0ab6e8u64,
]));

const SQRT_M_XI_CUBED: Fq = Fq(FqRepr([
    0x43b571cad3215f1fu64,
    0xccb460ef1c702dc2u64,
    0x742d884f4f97100bu64,
    0xdb2c3e3238a3382bu64,
    0xe40f3fa13fce8f88u64,
    0x73a2af9892a2ffu64,
]));

impl OSSWUMap for G1 {
    fn osswu_map(u: &Fq) -> G1 {
        // compute x0 and g(x0)
        let [usq, xi_usq, _, x0_num, x0_den, gx0_num, gx0_den] =
            osswu_help(u, &XI, &ELLP_A, &ELLP_B);

        // compute g(X0(u)) ^ ((p - 3) // 4)
        let sqrt_candidate = {
            let mut tmp1 = gx0_num;
            tmp1.mul_assign(&gx0_den); // u * v
            let mut tmp2 = gx0_den;
            tmp2.square(); // v^2
            tmp2.mul_assign(&tmp1); // u * v^3
            let tmp3 = tmp2;
            chain_pm3div4(&mut tmp2, &tmp3); // (u v^3) ^ ((p - 3) // 4)
            tmp2.mul_assign(&tmp1); // u v (u v^3) ^ ((p - 3) // 4)
            tmp2
        };

        // select correct values for y and for x numerator
        let (mut x_num, mut y) = {
            let mut test_cand = sqrt_candidate;
            test_cand.square();
            test_cand.mul_assign(&gx0_den);
            if test_cand == gx0_num {
                (x0_num, sqrt_candidate) // g(x0) is square
            } else {
                let mut x1_num = x0_num; // g(x1) is square
                x1_num.mul_assign(&xi_usq); // x1 = xi u^2 g(x0)
                let mut y1 = usq; // y1 = sqrt(-xi**3) * u^3 g(x0) ^ ((p - 1) // 4)
                y1.mul_assign(&u);
                y1.mul_assign(&sqrt_candidate);
                y1.mul_assign(&SQRT_M_XI_CUBED);
                (x1_num, y1)
            }
        };

        // make sure sign of y and sign of u agree
        let sgn0_y_xor_u = y.sgn0() ^ u.sgn0();
        y.negate_if(sgn0_y_xor_u);

        // convert to projective
        x_num.mul_assign(&x0_den); // x_num * x_den / x_den^2 = x_num / x_den
        y.mul_assign(&gx0_den); // y * x_den^3 / x_den^3 = y

        G1 {
            x: x_num,
            y,
            z: x0_den,
        }
    }
}
