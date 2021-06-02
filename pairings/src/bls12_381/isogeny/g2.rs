/*!
Constants for G2 isogeny.
*/

use super::{eval_iso, IsogenyMap};
use crate::bls12_381::{Fq, Fq2, FqRepr, G2};

/// Coefficients of the 3-isogeny x map's numerator
const XNUM: [Fq2; 4] = [
    Fq2 {
        c0: Fq(FqRepr([
            0x47f671c71ce05e62u64,
            0x06dd57071206393eu64,
            0x7c80cd2af3fd71a2u64,
            0x048103ea9e6cd062u64,
            0xc54516acc8d037f6u64,
            0x13808f550920ea41u64,
        ])),
        c1: Fq(FqRepr([
            0x47f671c71ce05e62u64,
            0x06dd57071206393eu64,
            0x7c80cd2af3fd71a2u64,
            0x048103ea9e6cd062u64,
            0xc54516acc8d037f6u64,
            0x13808f550920ea41u64,
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
            0x5fe55555554c71d0u64,
            0x873fffdd236aaaa3u64,
            0x6a6b4619b26ef918u64,
            0x21c2888408874945u64,
            0x2836cda7028cabc5u64,
            0x0ac73310a7fd5abdu64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x0a0c5555555971c3u64,
            0xdb0c00101f9eaaaeu64,
            0xb1fb2f941d797997u64,
            0xd3960742ef416e1cu64,
            0xb70040e2c20556f4u64,
            0x149d7861e581393bu64,
        ])),
        c1: Fq(FqRepr([
            0xaff2aaaaaaa638e8u64,
            0x439fffee91b55551u64,
            0xb535a30cd9377c8cu64,
            0x90e144420443a4a2u64,
            0x941b66d3814655e2u64,
            0x0563998853fead5eu64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x40aac71c71c725edu64,
            0x190955557a84e38eu64,
            0xd817050a8f41abc3u64,
            0xd86485d4c87f6fb1u64,
            0x696eb479f885d059u64,
            0x198e1a74328002d2u64,
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
];

/// Coefficients of the 3-isogeny x map's denominator
const XDEN: [Fq2; 3] = [
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
            0x1f3affffff13ab97u64,
            0xf25bfc611da3ff3eu64,
            0xca3757cb3819b208u64,
            0x3e6427366f8cec18u64,
            0x03977bc86095b089u64,
            0x04f69db13f39a952u64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x447600000027552eu64,
            0xdcb8009a43480020u64,
            0x6f7ee9ce4a6e8b59u64,
            0xb10330b7c0a95bc6u64,
            0x6140b1fcfb1e54b7u64,
            0x0381be097f0bb4e1u64,
        ])),
        c1: Fq(FqRepr([
            0x7588ffffffd8557du64,
            0x41f3ff646e0bffdfu64,
            0xf7b1e8d2ac426acau64,
            0xb3741acd32dbb6f8u64,
            0xe9daf5b9482d581fu64,
            0x167f53e0ba7431b8u64,
        ])),
    },
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
];

/// Coefficients of the 3-isogeny y map's numerator
const YNUM: [Fq2; 4] = [
    Fq2 {
        c0: Fq(FqRepr([
            0x96d8f684bdfc77beu64,
            0xb530e4f43b66d0e2u64,
            0x184a88ff379652fdu64,
            0x57cb23ecfae804e1u64,
            0x0fd2e39eada3eba9u64,
            0x08c8055e31c5d5c3u64,
        ])),
        c1: Fq(FqRepr([
            0x96d8f684bdfc77beu64,
            0xb530e4f43b66d0e2u64,
            0x184a88ff379652fdu64,
            0x57cb23ecfae804e1u64,
            0x0fd2e39eada3eba9u64,
            0x08c8055e31c5d5c3u64,
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
            0xbf0a71c71c91b406u64,
            0x4d6d55d28b7638fdu64,
            0x9d82f98e5f205aeeu64,
            0xa27aa27b1d1a18d5u64,
            0x02c3b2b2d2938e86u64,
            0x0c7d13420b09807fu64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0xd7f9555555531c74u64,
            0x21cffff748daaaa8u64,
            0x5a9ad1866c9bbe46u64,
            0x4870a2210221d251u64,
            0x4a0db369c0a32af1u64,
            0x02b1ccc429ff56afu64,
        ])),
        c1: Fq(FqRepr([
            0xe205aaaaaaac8e37u64,
            0xfcdc000768795556u64,
            0x0c96011a8a1537ddu64,
            0x1c06a963f163406eu64,
            0x010df44c82a881e6u64,
            0x174f45260f808febu64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0xa470bda12f67f35cu64,
            0xc0fe38e23327b425u64,
            0xc9d3d0f2c6f0678du64,
            0x1c55c9935b5a982eu64,
            0x27f6c0e2f0746764u64,
            0x117c5e6e28aa9054u64,
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
];

/// Coefficients of the 3-isogeny y map's denominator
const YDEN: [Fq2; 4] = [
    Fq2 {
        c0: Fq(FqRepr([
            0x0162fffffa765adfu64,
            0x8f7bea480083fb75u64,
            0x561b3c2259e93611u64,
            0x11e19fc1a9c875d5u64,
            0xca713efc00367660u64,
            0x03c6a03d41da1151u64,
        ])),
        c1: Fq(FqRepr([
            0x0162fffffa765adfu64,
            0x8f7bea480083fb75u64,
            0x561b3c2259e93611u64,
            0x11e19fc1a9c875d5u64,
            0xca713efc00367660u64,
            0x03c6a03d41da1151u64,
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
            0x5db0fffffd3b02c5u64,
            0xd713f52358ebfdbau64,
            0x5ea60761a84d161au64,
            0xbb2c75a34ea6c44au64,
            0x0ac6735921c1119bu64,
            0x0ee3d913bdacfbf6u64,
        ])),
    },
    Fq2 {
        c0: Fq(FqRepr([
            0x66b10000003affc5u64,
            0xcb1400e764ec0030u64,
            0xa73e5eb56fa5d106u64,
            0x8984c913a0fe09a9u64,
            0x11e10afb78ad7f13u64,
            0x05429d0e3e918f52u64,
        ])),
        c1: Fq(FqRepr([
            0x534dffffffc4aae6u64,
            0x5397ff174c67ffcfu64,
            0xbff273eb870b251du64,
            0xdaf2827152870915u64,
            0x393a9cbaca9e2dc3u64,
            0x14be74dbfaee5748u64,
        ])),
    },
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
];

impl IsogenyMap for G2 {
    fn isogeny_map(&mut self) {
        eval_iso(self, [&XNUM[..], &XDEN[..], &YNUM[..], &YDEN[..]]);
    }
}
