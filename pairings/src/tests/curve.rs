use crate::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use ff::{BitIterator, Field, PrimeField};
use rand_core::SeedableRng;

pub fn curve_tests<G: CurveProjective>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    // Negation edge case with zero.
    {
        let mut z = G::zero();
        z.negate();
        assert!(z.is_zero());
    }

    // Doubling edge case with zero.
    {
        let mut z = G::zero();
        z.double();
        assert!(z.is_zero());
    }

    // Addition edge cases with zero
    {
        let mut r = G::random(&mut rng);
        let rcopy = r;
        r.add_assign(&G::zero());
        assert_eq!(r, rcopy);
        r.add_assign_mixed(&G::Affine::zero());
        assert_eq!(r, rcopy);

        let mut z = G::zero();
        z.add_assign(&G::zero());
        assert!(z.is_zero());
        z.add_assign_mixed(&G::Affine::zero());
        assert!(z.is_zero());

        let mut z2 = z;
        z2.add_assign(&r);

        z.add_assign_mixed(&r.into_affine());

        assert_eq!(z, z2);
        assert_eq!(z, r);
    }

    // Transformations
    {
        let a = G::random(&mut rng);
        let b = a.into_affine().into_projective();
        let c = a
            .into_affine()
            .into_projective()
            .into_affine()
            .into_projective();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    random_addition_tests::<G>();
    random_multiplication_tests::<G>();
    random_doubling_tests::<G>();
    random_negation_tests::<G>();
    // random_transformation_tests::<G>();
    random_wnaf_tests::<G>();
    random_encoding_tests::<G::Affine>();
    random_batch_norm_tests::<G>();
}

fn random_batch_norm_tests<G: CurveProjective>() {
    const SAMPLE: usize = 10;
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let mut base_proj: Vec<G> = vec![];
    for _ in 0..SAMPLE {
        let mut g = G::random(&mut rng);
        let r = G::Scalar::random(&mut rng);
        g.mul_assign(r);
        base_proj.push(g);
    }
    let mut res = base_proj.clone();
    G::batch_normalization(&mut res);
    for i in 0..SAMPLE {
        assert!(res[i].is_normalized());
        assert_eq!(res[i].into_affine(), base_proj[i].into_affine());
    }
}

fn random_wnaf_tests<G: CurveProjective>() {
    use crate::wnaf::*;

    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    {
        let mut table = vec![];
        let mut wnaf = vec![];

        for w in 2..14 {
            for _ in 0..100 {
                let g = G::random(&mut rng);
                let s = G::Scalar::random(&mut rng).into_repr();
                let mut g1 = g;
                g1.mul_assign(s);

                wnaf_table(&mut table, g, w);
                wnaf_form(&mut wnaf, s, w);
                let g2 = wnaf_exp(&table, &wnaf);

                assert_eq!(g1, g2);
            }
        }
    }

    {
        fn only_compiles_if_send<S: Send>(_: &S) {}

        for _ in 0..100 {
            let g = G::random(&mut rng);
            let s = G::Scalar::random(&mut rng).into_repr();
            let mut g1 = g;
            g1.mul_assign(s);

            let g2 = {
                let mut wnaf = Wnaf::new();
                wnaf.base(g, 1).scalar(s)
            };
            let g3 = {
                let mut wnaf = Wnaf::new();
                wnaf.scalar(s).base(g)
            };
            let g4 = {
                let mut wnaf = Wnaf::new();
                let mut shared = wnaf.base(g, 1).shared();

                only_compiles_if_send(&shared);

                shared.scalar(s)
            };
            let g5 = {
                let mut wnaf = Wnaf::new();
                let mut shared = wnaf.scalar(s).shared();

                only_compiles_if_send(&shared);

                shared.base(g)
            };

            let g6 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                wnaf.base(g, 1).scalar(s)
            };
            let g7 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                wnaf.scalar(s).base(g)
            };
            let g8 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                let mut shared = wnaf.base(g, 1).shared();

                only_compiles_if_send(&shared);

                shared.scalar(s)
            };
            let g9 = {
                let mut wnaf = Wnaf::new();
                {
                    // Populate the vectors.
                    wnaf.base(G::random(&mut rng), 1)
                        .scalar(G::Scalar::random(&mut rng).into_repr());
                }
                let mut shared = wnaf.scalar(s).shared();

                only_compiles_if_send(&shared);

                shared.base(g)
            };

            assert_eq!(g1, g2);
            assert_eq!(g1, g3);
            assert_eq!(g1, g4);
            assert_eq!(g1, g5);
            assert_eq!(g1, g6);
            assert_eq!(g1, g7);
            assert_eq!(g1, g8);
            assert_eq!(g1, g9);
        }
    }
}

fn random_negation_tests<G: CurveProjective>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let r = G::random(&mut rng);

        let s = G::Scalar::random(&mut rng);
        let mut sneg = s;
        sneg.negate();

        let mut t1 = r;
        t1.mul_assign(s);

        let mut t2 = r;
        t2.mul_assign(sneg);

        let mut t3 = t1;
        t3.add_assign(&t2);
        assert!(t3.is_zero());

        let mut t4 = t1;
        t4.add_assign_mixed(&t2.into_affine());
        assert!(t4.is_zero());

        t1.negate();
        assert_eq!(t1, t2);
    }
}

fn random_doubling_tests<G: CurveProjective>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let mut a = G::random(&mut rng);
        let mut b = G::random(&mut rng);

        // 2(a + b)
        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.double();

        // 2a + 2b
        a.double();
        b.double();

        let mut tmp2 = a;
        tmp2.add_assign(&b);

        let mut tmp3 = a;
        tmp3.add_assign_mixed(&b.into_affine());

        assert_eq!(tmp1, tmp2);
        assert_eq!(tmp1, tmp3);
    }
}

fn random_multiplication_tests<G: CurveProjective>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let mut a = G::random(&mut rng);
        let mut b = G::random(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();

        let s = G::Scalar::random(&mut rng);

        // s ( a + b )
        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.mul_assign(s);

        // sa + sb
        a.mul_assign(s);
        b.mul_assign(s);

        let mut tmp2 = a;
        tmp2.add_assign(&b);

        // Affine multiplication
        let mut tmp3 = a_affine.mul(s);
        tmp3.add_assign(&b_affine.mul(s));

        assert_eq!(tmp1, tmp2);
        assert_eq!(tmp1, tmp3);
    }
}

fn random_addition_tests<G: CurveProjective>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _ in 0..1000 {
        let a = G::random(&mut rng);
        let b = G::random(&mut rng);
        let c = G::random(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();
        let c_affine = c.into_affine();

        // a + a should equal the doubling
        {
            let mut aplusa = a;
            aplusa.add_assign(&a);

            let mut aplusamixed = a;
            aplusamixed.add_assign_mixed(&a.into_affine());

            let mut adouble = a;
            adouble.double();

            assert_eq!(aplusa, adouble);
            assert_eq!(aplusa, aplusamixed);
        }

        let mut tmp = vec![G::zero(); 6];

        // (a + b) + c
        tmp[0] = a;
        tmp[0].add_assign(&b);
        tmp[0].add_assign(&c);

        // a + (b + c)
        tmp[1] = b;
        tmp[1].add_assign(&c);
        tmp[1].add_assign(&a);

        // (a + c) + b
        tmp[2] = a;
        tmp[2].add_assign(&c);
        tmp[2].add_assign(&b);

        // Mixed addition

        // (a + b) + c
        tmp[3] = a_affine.into_projective();
        tmp[3].add_assign_mixed(&b_affine);
        tmp[3].add_assign_mixed(&c_affine);

        // a + (b + c)
        tmp[4] = b_affine.into_projective();
        tmp[4].add_assign_mixed(&c_affine);
        tmp[4].add_assign_mixed(&a_affine);

        // (a + c) + b
        tmp[5] = a_affine.into_projective();
        tmp[5].add_assign_mixed(&c_affine);
        tmp[5].add_assign_mixed(&b_affine);

        // Comparisons
        for i in 0..6 {
            for j in 0..6 {
                assert_eq!(tmp[i], tmp[j]);
                assert_eq!(tmp[i].into_affine(), tmp[j].into_affine());
            }

            assert!(tmp[i] != a);
            assert!(tmp[i] != b);
            assert!(tmp[i] != c);

            assert!(a != tmp[i]);
            assert!(b != tmp[i]);
            assert!(c != tmp[i]);
        }
    }
}

// fn random_transformation_tests<G: CurveProjective>() {
//     let mut rng = rand_xorshift::XorShiftRng::from_seed([
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
//         0xe5,
//     ]);
//
//     for _ in 0..1000 {
//         let g = G::rand(&mut rng);
//         let g_affine = g.into_affine();
//         let g_projective = g_affine.into_projective();
//         assert_eq!(g, g_projective);
//     }
//
//     // Batch normalization
//     for _ in 0..10 {
//         let mut v = (0..1000).map(|_| G::rand(&mut rng)).collect::<Vec<_>>();
//
//         for i in &v {
//             assert!(!i.is_normalized());
//         }
//
//         use rand::distributions::{IndependentSample, Range};
//         let between = Range::new(0, 1000);
//         // Sprinkle in some normalized points
//         for _ in 0..5 {
//             v[between.ind_sample(&mut rng)] = G::zero();
//         }
//         for _ in 0..5 {
//             let s = between.ind_sample(&mut rng);
//             v[s] = v[s].into_affine().into_projective();
//         }
//
//         let expected_v = v
//             .iter()
//             .map(|v| v.into_affine().into_projective())
//             .collect::<Vec<_>>();
//         G::batch_normalization(&mut v);
//
//         for i in &v {
//             assert!(i.is_normalized());
//         }
//
//         assert_eq!(v, expected_v);
//     }
// }

fn random_encoding_tests<G: CurveAffine>() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    assert_eq!(
        G::zero().into_uncompressed().into_affine().unwrap(),
        G::zero()
    );

    assert_eq!(
        G::zero().into_compressed().into_affine().unwrap(),
        G::zero()
    );

    for _ in 0..1000 {
        let mut r = G::Projective::random(&mut rng).into_affine();

        let uncompressed = r.into_uncompressed();
        let de_uncompressed = uncompressed.into_affine().unwrap();
        assert_eq!(de_uncompressed, r);

        let compressed = r.into_compressed();
        let de_compressed = compressed.into_affine().unwrap();
        assert_eq!(de_compressed, r);

        r.negate();

        let compressed = r.into_compressed();
        let de_compressed = compressed.into_affine().unwrap();
        assert_eq!(de_compressed, r);
    }
}

#[test]
fn test_g1_mul() {
    const ZERO_ONE_TESTS: usize = 10;
    const SAMPLES: usize = 100;

    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let mut pre_3 = [G1Affine::zero(); 3];
    let mut pre_256 = [G1Affine::zero(); 256];

    for _ in 0..ZERO_ONE_TESTS {
        // test multiplication by 0 and by 1
        let test_point = G1::random(&mut rng);
        let affine_test_point = test_point.into_affine();
        affine_test_point.precomp_3(&mut pre_3);
        affine_test_point.precomp_256(&mut pre_256);

        let mut test_point_copy = test_point;
        test_point_copy.mul_assign(Fr::zero());
        assert_eq!(test_point_copy, G1::zero(), "G1 mul by 0 is not correct");

        let res0 = affine_test_point.mul(Fr::zero());
        assert_eq!(res0, G1::zero(), "G1 affine mul by 0 is not correct");

        let res03 = affine_test_point.mul_precomp_3(Fr::zero(), &pre_3);
        assert_eq!(res03, G1::zero(), "G1 mul_precomp_3 by 0 is not correct");
        let res0256 = affine_test_point.mul_precomp_256(Fr::zero(), &pre_256);
        assert_eq!(
            res0256,
            G1::zero(),
            "G1 mul_precomp_256 by 0 is not correct"
        );

        test_point_copy = test_point;
        test_point_copy.mul_assign(Fr::one());
        assert_eq!(
            test_point_copy.into_affine(),
            affine_test_point,
            "G1 mul by 1 is not correct"
        );

        let res1 = affine_test_point.mul(Fr::one());
        assert_eq!(res1, test_point, "G1 affine mul by 1 is not correct");

        let res13 = affine_test_point.mul_precomp_3(Fr::one(), &pre_3);
        assert_eq!(res13, test_point, "G1 mul_precomp_3 by 1 is not correct");

        let res1256 = affine_test_point.mul_precomp_256(Fr::one(), &pre_256);
        assert_eq!(
            res1256, test_point,
            "G1 mul_precomp_256 by 1 is not correct"
        );
    }

    // test random multiplications
    for _ in 0..SAMPLES {
        let test_point = G1::random(&mut rng);
        let affine_test_point = test_point.into_affine();

        affine_test_point.precomp_3(&mut pre_3);
        affine_test_point.precomp_256(&mut pre_256);

        let s = Fr::random(&mut rng);

        // perform a basic square and multiply to compare against
        let mut correct_res = G1::zero();
        for i in BitIterator::new(s.into_repr()) {
            correct_res.double();
            if i {
                correct_res.add_assign(&test_point);
            }
        }

        let mut test_point_copy = test_point;
        test_point_copy.mul_assign(s);
        assert_eq!(test_point_copy, correct_res, "G1 mul_assign is not correct");

        let res = affine_test_point.mul(s);
        assert_eq!(res, correct_res, "G1 affine mul is not correct");

        let res3 = affine_test_point.mul_precomp_3(s, &pre_3);
        assert_eq!(res3, correct_res, "G1 mul_precomp_3 is not correct");

        let res256 = affine_test_point.mul_precomp_256(s, &pre_256);
        assert_eq!(res256, correct_res, "G1 mul_precomp_256 is not correct");
    }
}

#[test]
fn test_pippinger_window() {
    for i in 1..1000000 {
        assert_eq!(
            G1Affine::find_pippinger_window(i),
            G1Affine::find_pippinger_window_via_estimate(i)
        );
    }
}

#[test]
fn test_g1_sum_of_products() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let max_points = 15;
    let points: Vec<G1Affine> = (0..max_points)
        .map(|_| G1::random(&mut rng).into_affine())
        .collect();
    let mut precomp = vec![G1Affine::zero(); 256 * max_points];
    for i in 0..max_points {
        points[i].precomp_256(&mut precomp[i * 256..(i + 1) * 256]);
    }

    for num_points in 0..max_points {
        {
            // test vector multiplication by 0
            let scalars_fr_repr: Vec<FrRepr> =
                (0..num_points).map(|_| Fr::zero().into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let desired_result = G1::zero();

            for window in 1..10 {
                let res_no_precomp =
                    G1Affine::sum_of_products_pippinger(&points[0..num_points], &scalars, window);
                assert_eq!(
                    desired_result, res_no_precomp,
                    "Failed at raising multiple points to random vector"
                );
            }

            let res_precomp = G1Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result, res_precomp,
                "Failed at raising multiple points to all-0 vector with precomputation"
            );
        }
        {
            // test vector multiplication by 1
            let scalars_fr_repr: Vec<FrRepr> =
                (0..num_points).map(|_| Fr::one().into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let mut desired_result = G1::zero();
            for i in 0..num_points {
                desired_result.add_assign_mixed(&points[i]);
            }

            for window in 1..10 {
                let res_no_precomp =
                    G1Affine::sum_of_products_pippinger(&points[0..num_points], &scalars, window);
                assert_eq!(
                    desired_result, res_no_precomp,
                    "Failed at raising multiple points to random vector"
                );
            }

            let res_precomp = G1Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result, res_precomp,
                "Failed at raising multiple points to all-0 vector with precomputation"
            );
        }
        {
            // test vector multiplication by alternating 0/1
            let mut scalars_fr_repr: Vec<FrRepr> = Vec::with_capacity(num_points);
            for i in 0..num_points {
                if i % 2 == 0 {
                    scalars_fr_repr.push(Fr::zero().into_repr());
                } else {
                    scalars_fr_repr.push(Fr::one().into_repr());
                }
            }
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let mut desired_result = G1::zero();
            for i in 0..num_points {
                if i % 2 == 1 {
                    desired_result.add_assign_mixed(&points[i]);
                }
            }

            for window in 1..10 {
                let res_no_precomp =
                    G1Affine::sum_of_products_pippinger(&points[0..num_points], &scalars, window);
                assert_eq!(
                    desired_result, res_no_precomp,
                    "Failed at raising multiple points to random vector"
                );
            }

            let res_precomp = G1Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result, res_precomp,
                "Failed at raising multiple points to alternating 0/1 vector with precomputation"
            );
        }

        {
            // test vector multiplication by alternating 0/1/short/random
            let mut scalars_fr: Vec<Fr> = Vec::with_capacity(num_points);
            let mut short_scalar = Fr::one();
            short_scalar.add_assign(&Fr::one()); // == 2
            short_scalar.add_assign(&Fr::one()); // == 3
            for _ in 0..6 {
                // square the scalar 6 times to compute 3^{2^6} = 3^64, which takes up 102 bits
                let s = short_scalar;
                short_scalar.mul_assign(&s);
            }

            for i in 0..num_points {
                if i % 4 == 0 {
                    scalars_fr.push(Fr::zero());
                } else if i % 4 == 1 {
                    scalars_fr.push(Fr::one());
                } else if i % 4 == 2 {
                    scalars_fr.push(short_scalar);
                } else if i % 4 == 3 {
                    scalars_fr.push(Fr::random(&mut rng));
                }
            }

            let mut desired_result = G1::zero();
            for i in 0..num_points {
                if i % 4 != 0 {
                    let mut intermediate_result = points[i].into_projective();
                    if i % 4 != 1 {
                        intermediate_result.mul_assign(scalars_fr[i]);
                    }
                    desired_result.add_assign(&intermediate_result);
                }
            }

            let scalars_fr_repr: Vec<FrRepr> = scalars_fr.iter().map(|s| s.into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            for window in 1..10 {
                let res_no_precomp =
                    G1Affine::sum_of_products_pippinger(&points[0..num_points], &scalars, window);
                assert_eq!(
                    desired_result, res_no_precomp,
                    "Failed at raising multiple points to random vector"
                );
            }

            let res_precomp = G1Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result, res_precomp,
                "Failed at raising multiple points to 0/1/short/random with precomputation"
            );
        }
        {
            // test vector multiplication by random
            let mut scalars_fr: Vec<Fr> = Vec::with_capacity(num_points);

            for _ in 0..num_points {
                scalars_fr.push(Fr::random(&mut rng));
            }

            let mut desired_result = G1::zero();
            for i in 0..num_points {
                let mut intermediate_result = points[i].into_projective();
                intermediate_result.mul_assign(scalars_fr[i]);
                desired_result.add_assign(&intermediate_result);
            }

            let scalars_fr_repr: Vec<FrRepr> = scalars_fr.iter().map(|s| s.into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();
            for window in 1..10 {
                let res_no_precomp =
                    G1Affine::sum_of_products_pippinger(&points[0..num_points], &scalars, window);
                assert_eq!(
                    desired_result, res_no_precomp,
                    "Failed at raising multiple points to random vector"
                );
            }

            let res_precomp = G1Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result, res_precomp,
                "Failed at raising multiple points to random vector with precomputation"
            );
        }
    }
    //assert!(false);
}

// #[test]
// fn test_g1_mul_sec() {
//     const SAMPLES: usize = 100;
//
//     let mut rng = rand_xorshift::XorShiftRng::from_seed([
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
//         0xe5,
//     ]);
//
//     // mul_assign_sec ensures constant time for a same base point
//     // and various scalars
//     let v: Vec<(G1, Fr)> = (0..SAMPLES)
//         .map(|_| ((G1::random(&mut rng)), Fr::random(&mut rng)))
//         .collect();
//
//     for i in 0..SAMPLES {
//         let mut tmp = v[i].0.clone();
//         tmp.mul_assign(v[i].1.clone());
//         let mut t1 = v[i].0.clone();
//         t1.mul_assign_sec(v[i].1.clone());
//
//         assert_eq!(
//             t1.into_affine(),
//             tmp.into_affine(),
//             "mul_sec is not correct"
//         );
//     }
// }
// #[test]
// fn test_g1_mul_shamir() {
//     const SAMPLES: usize = 100;
//
//     let mut rng = rand_xorshift::XorShiftRng::from_seed([
//         0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
//         0xe5,
//     ]);
//     // mul_assign_sec ensures constant time for a same base point
//     // and various scalars
//     let v: Vec<(G1, G1, Fr, Fr)> = (0..SAMPLES)
//         .map(|_| {
//             (
//                 (G1::random(&mut rng)),
//                 (G1::random(&mut rng)),
//                 Fr::random(&mut rng),
//                 Fr::random(&mut rng),
//             )
//         })
//         .collect();
//
//     for i in 0..SAMPLES {
//         let tmp = CurveProjective::mul_shamir(v[i].0, v[i].1, v[i].2, v[i].3);
//         let mut t1 = v[i].0;
//         let mut t2 = v[i].1;
//         t1.mul_assign(v[i].2);
//         t2.mul_assign(v[i].3);
//         t1.add_assign(&t2);
//         assert_eq!(
//             t1.into_affine(),
//             tmp.into_affine(),
//             "mul_shamir is not correct"
//         );
//     }
// }

#[test]
fn test_g2_mul() {
    const ZERO_ONE_TESTS: usize = 10;
    const SAMPLES: usize = 100;
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let mut pre_3 = [G2Affine::zero(); 3];
    let mut pre_256 = [G2Affine::zero(); 256];
    for _ in 0..ZERO_ONE_TESTS {
        // test multiplication by 0 and by 1
        let test_point = G2::random(&mut rng);
        let affine_test_point = test_point.into_affine();
        let affine_zero = G2::zero().into_affine();
        affine_test_point.precomp_3(&mut pre_3);
        affine_test_point.precomp_256(&mut pre_256);
        let mut test_point_copy = test_point;
        test_point_copy.mul_assign(Fr::zero());
        assert_eq!(
            test_point_copy.into_affine(),
            affine_zero,
            "G2 mul by 0 is not correct"
        );
        let mut affine_test_point_copy = affine_test_point;
        affine_test_point_copy.mul_precomp_3(Fr::zero(), &pre_3);
        assert_eq!(
            test_point_copy.into_affine(),
            affine_zero,
            "G2 mul_precomp_3 by 0 is not correct"
        );
        affine_test_point_copy = affine_test_point;
        affine_test_point_copy.mul_precomp_256(Fr::zero(), &pre_256);
        assert_eq!(
            test_point_copy.into_affine(),
            affine_zero,
            "G2 mul_precomp_256 by 0 is not correct"
        );
        test_point_copy = test_point;
        test_point_copy.mul_assign(Fr::one());
        assert_eq!(
            test_point_copy.into_affine(),
            affine_test_point,
            "G2 mul by 1 is not correct"
        );
        affine_test_point_copy = affine_test_point;
        affine_test_point_copy.mul_precomp_3(Fr::one(), &pre_3);
        assert_eq!(
            test_point_copy.into_affine(),
            affine_test_point,
            "G2 mul_precomp_3 by 1 is not correct"
        );
        affine_test_point_copy = affine_test_point;
        affine_test_point_copy.mul_precomp_256(Fr::one(), &pre_256);
        assert_eq!(
            test_point_copy.into_affine(),
            affine_test_point,
            "G2 mul_precomp_256 by 1 is not correct"
        );
    }
    // test random multiplications
    for _ in 0..SAMPLES {
        let test_point = G2::random(&mut rng);
        let affine_test_point = test_point.into_affine();
        affine_test_point.precomp_3(&mut pre_3);
        affine_test_point.precomp_256(&mut pre_256);
        let s = Fr::random(&mut rng);
        // perform a basic square and multiply to compare against
        let mut correct_res = G2::zero();
        for i in BitIterator::new(s.into_repr()) {
            correct_res.double();
            if i {
                correct_res.add_assign(&test_point);
            }
        }
        let affine_res = correct_res.into_affine();
        let mut test_point_copy = test_point;
        test_point_copy.mul_assign(s);
        assert_eq!(
            test_point_copy.into_affine(),
            affine_res,
            "G2 mul_precomp_256 is not correct"
        );
        let mut affine_test_point_copy = affine_test_point;
        affine_test_point_copy.mul_precomp_3(s, &pre_3);
        assert_eq!(
            test_point_copy.into_affine(),
            affine_res,
            "G2 mul_precomp_256 is not correct"
        );
        affine_test_point_copy = affine_test_point;
        affine_test_point_copy.mul_precomp_256(s, &pre_256);
        assert_eq!(
            test_point_copy.into_affine(),
            affine_res,
            "G2 mul_precomp_256 is not correct"
        );
    }
}

#[test]
fn test_g2_sum_of_products() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let max_points = 15;
    let points: Vec<G2Affine> = (0..max_points)
        .map(|_| G2::random(&mut rng).into_affine())
        .collect();
    let mut precomp = vec![G2Affine::zero(); 256 * max_points];
    for i in 0..max_points {
        points[i].precomp_256(&mut precomp[i * 256..(i + 1) * 256]);
    }
    for num_points in 0..max_points {
        {
            // test vector multiplication by 0
            let scalars_fr_repr: Vec<FrRepr> =
                (0..num_points).map(|_| Fr::zero().into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let desired_result = G2::zero().into_affine();
            let res_no_precomp = G2Affine::sum_of_products(&points[0..num_points], &scalars);
            assert_eq!(
                desired_result,
                res_no_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector"
            );
            let res_precomp = G2Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result,
                res_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector with precomputation"
            );
        }
        {
            // test vector multiplication by 1
            let scalars_fr_repr: Vec<FrRepr> =
                (0..num_points).map(|_| Fr::one().into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let mut desired_result = G2::zero();
            for i in 0..num_points {
                desired_result.add_assign(&points[i].into_projective());
            }
            let res_no_precomp = G2Affine::sum_of_products(&points[0..num_points], &scalars);
            assert_eq!(
                desired_result.into_affine(),
                res_no_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector"
            );
            let res_precomp = G2Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result.into_affine(),
                res_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector with precomputation"
            );
        }
        {
            // test vector multiplication by alternating 0/1
            let mut scalars_fr_repr: Vec<FrRepr> = Vec::with_capacity(num_points);
            for i in 0..num_points {
                if i % 2 == 0 {
                    scalars_fr_repr.push(Fr::zero().into_repr());
                } else {
                    scalars_fr_repr.push(Fr::one().into_repr());
                }
            }
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let mut desired_result = G2::zero();
            for i in 0..num_points {
                if i % 2 == 1 {
                    desired_result.add_assign(&points[i].into_projective());
                }
            }
            let res_no_precomp = G2Affine::sum_of_products(&points[0..num_points], &scalars);
            assert_eq!(
                desired_result.into_affine(),
                res_no_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector"
            );
            let res_precomp = G2Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result.into_affine(),
                res_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector with precomputation"
            );
        }
        {
            // test vector multiplication by alternating 0/1/short/random
            let mut scalars_fr: Vec<Fr> = Vec::with_capacity(num_points);
            let mut short_scalar = Fr::one();
            short_scalar.add_assign(&Fr::one()); // == 2
            short_scalar.add_assign(&Fr::one()); // == 3
            for _ in 0..6 {
                // square the scalar 6 times to compute 3^{2^6} = 3^64, which takes up 102 bits
                let s = short_scalar;
                short_scalar.mul_assign(&s);
            }
            for i in 0..num_points {
                if i % 4 == 0 {
                    scalars_fr.push(Fr::zero());
                } else if i % 4 == 1 {
                    scalars_fr.push(Fr::one());
                } else if i % 4 == 2 {
                    scalars_fr.push(short_scalar);
                } else if i % 4 == 3 {
                    scalars_fr.push(Fr::random(&mut rng));
                }
            }
            let mut desired_result = G2::zero();
            for i in 0..num_points {
                if i % 4 != 0 {
                    let mut intermediate_result = points[i].into_projective();
                    if i % 4 != 1 {
                        intermediate_result.mul_assign(scalars_fr[i]);
                    }
                    desired_result.add_assign(&intermediate_result);
                }
            }
            let scalars_fr_repr: Vec<FrRepr> = scalars_fr.iter().map(|s| s.into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let res_no_precomp = G2Affine::sum_of_products(&points[0..num_points], &scalars);
            assert_eq!(
                desired_result.into_affine(),
                res_no_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector"
            );
            let res_precomp = G2Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result.into_affine(),
                res_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector with precomputation"
            );
        }
        {
            // test vector multiplication by random
            let mut scalars_fr: Vec<Fr> = Vec::with_capacity(num_points);
            for _ in 0..num_points {
                scalars_fr.push(Fr::random(&mut rng));
            }
            let mut desired_result = G2::zero();
            for i in 0..num_points {
                let mut intermediate_result = points[i].into_projective();
                intermediate_result.mul_assign(scalars_fr[i]);
                desired_result.add_assign(&intermediate_result);
            }
            let scalars_fr_repr: Vec<FrRepr> = scalars_fr.iter().map(|s| s.into_repr()).collect();
            let scalars: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

            let res_no_precomp = G2Affine::sum_of_products(&points[0..num_points], &scalars);
            assert_eq!(
                desired_result.into_affine(),
                res_no_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector"
            );
            let res_precomp = G2Affine::sum_of_products_precomp_256(
                &points[0..num_points],
                &scalars,
                &precomp[0..num_points * 256],
            );
            assert_eq!(
                desired_result.into_affine(),
                res_precomp.into_affine(),
                "Failed at raising multiple points to all-0 vector with precomputation"
            );
        }
    }
}
