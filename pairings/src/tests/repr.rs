use ff::{PrimeField, PrimeFieldRepr};
use rand_core::SeedableRng;

pub fn random_repr_tests<F: PrimeField, R: PrimeFieldRepr>() {
    random_encoding_tests::<F, R>();
    random_shl_tests::<F>();
    random_shr_tests::<F>();
}

fn random_encoding_tests<F: PrimeField, R: PrimeFieldRepr>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _ in 0..1000 {
        let r = F::random(&mut rng).into_repr();

        // Big endian
        {
            let mut rdecoded = R::default();

            let mut v: Vec<u8> = vec![];
            r.write_be(&mut v).unwrap();
            rdecoded.read_be(&v[0..]).unwrap();

            assert_eq!(r.as_ref(), rdecoded.as_ref());
        }

        // Little endian
        {
            let mut rdecoded = R::default();

            let mut v: Vec<u8> = vec![];
            r.write_le(&mut v).unwrap();
            rdecoded.read_le(&v[0..]).unwrap();

            assert_eq!(r.as_ref(), rdecoded.as_ref());
        }

        {
            let mut rdecoded_le = R::default();
            let mut rdecoded_be_flip = R::default();

            let mut v: Vec<u8> = vec![];
            r.write_le(&mut v).unwrap();

            // This reads in little-endian, so we are done.
            rdecoded_le.read_le(&v[..]).unwrap();

            // This reads in big-endian, so we perform a swap of the
            // bytes beforehand.
            let v: Vec<u8> = v.into_iter().rev().collect();
            rdecoded_be_flip.read_be(&v[..]).unwrap();

            assert_eq!(rdecoded_le, rdecoded_be_flip);
        }
    }
}

fn random_shl_tests<F: PrimeField>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _ in 0..100 {
        let r = F::random(&mut rng).into_repr();

        for shift in 0..=r.num_bits() {
            let mut r1 = r;
            let mut r2 = r;

            for _ in 0..shift {
                r1.mul2();
            }

            r2.shl(shift);

            assert_eq!(r1, r2);
        }
    }
}

fn random_shr_tests<F: PrimeField>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _ in 0..100 {
        let r = F::random(&mut rng).into_repr();

        for shift in 0..=r.num_bits() {
            let mut r1 = r;
            let mut r2 = r;

            for _ in 0..shift {
                r1.div2();
            }

            r2.shr(shift);

            assert_eq!(r1, r2);
        }
    }
}
