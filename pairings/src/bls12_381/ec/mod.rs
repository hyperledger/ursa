macro_rules! curve_impl {
    (
        $name:expr,
        $projective:ident,
        $affine:ident,
        $prepared:ident,
        $basefield:ident,
        $scalarfield:ident,
        $uncompressed:ident,
        $compressed:ident,
        $pairing:ident
    ) => {
        #[derive(Copy, Clone, PartialEq, Eq, Debug, Zeroize)]
        pub struct $affine {
            pub(crate) x: $basefield,
            pub(crate) y: $basefield,
            pub(crate) infinity: bool,
        }

        /// # Safety
        pub const unsafe fn transmute_affine(x: $basefield, y: $basefield, i: bool) -> $affine {
            $affine { x, y, infinity: i }
        }

        // set the default values for the group elements to 0s
        impl ::std::default::Default for $affine {
            fn default() -> Self {
                $affine::zero()
            }
        }

        // set the default values for the group elements to 0s
        impl ::std::default::Default for $projective {
            fn default() -> Self {
                $projective::zero()
            }
        }

        impl ::std::fmt::Display for $affine {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                if self.infinity {
                    write!(f, "{}(Infinity)", $name)
                } else {
                    write!(f, "{}(x={}, y={})", $name, self.x, self.y)
                }
            }
        }

        #[derive(Copy, Clone, Debug, Eq, Zeroize)]
        pub struct $projective {
            pub(crate) x: $basefield,
            pub(crate) y: $basefield,
            pub(crate) z: $basefield,
        }

        /// placeholder
        /// # Safety
        pub const unsafe fn transmute_projective(
            x: $basefield,
            y: $basefield,
            z: $basefield,
        ) -> $projective {
            $projective { x, y, z }
        }

        impl ::std::fmt::Display for $projective {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "{}", self.into_affine())
            }
        }

        impl PartialEq for $projective {
            fn eq(&self, other: &$projective) -> bool {
                if self.is_zero() {
                    return other.is_zero();
                }

                if other.is_zero() {
                    return false;
                }

                // The points (X, Y, Z) and (X', Y', Z')
                // are equal when (X * Z^2) = (X' * Z'^2)
                // and (Y * Z^3) = (Y' * Z'^3).

                let mut z1 = self.z;
                z1.square();
                let mut z2 = other.z;
                z2.square();

                let mut tmp1 = self.x;
                tmp1.mul_assign(&z2);

                let mut tmp2 = other.x;
                tmp2.mul_assign(&z1);

                if tmp1 != tmp2 {
                    return false;
                }

                z1.mul_assign(&self.z);
                z2.mul_assign(&other.z);
                z2.mul_assign(&self.y);
                z1.mul_assign(&other.y);

                if z1 != z2 {
                    return false;
                }

                true
            }
        }

        impl $affine {
            fn mul_bits<S: AsRef<[u64]>>(&self, bits: BitIterator<S>) -> $projective {
                let mut res = $projective::zero();
                for i in bits {
                    res.double();
                    if i {
                        res.add_assign_mixed(self)
                    }
                }
                res
            }

            /// Attempts to construct an affine point given an x-coordinate. The
            /// point is not guaranteed to be in the prime order subgroup.
            ///
            /// If and only if `greatest` is set will the lexicographically
            /// largest y-coordinate be selected.
            fn get_point_from_x(x: $basefield, greatest: bool) -> Option<$affine> {
                // Compute x^3 + b
                let mut x3b = x;
                x3b.square();
                x3b.mul_assign(&x);
                x3b.add_assign(&$affine::get_coeff_b());

                x3b.sqrt().map(|y| {
                    let mut negy = y;
                    negy.negate();

                    $affine {
                        x,
                        y: if (y < negy) ^ greatest { y } else { negy },
                        infinity: false,
                    }
                })
            }

            fn is_on_curve(&self) -> bool {
                if self.is_zero() {
                    true
                } else {
                    // Check that the point is on the curve
                    let mut y2 = self.y;
                    y2.square();

                    let mut x3b = self.x;
                    x3b.square();
                    x3b.mul_assign(&self.x);
                    x3b.add_assign(&Self::get_coeff_b());

                    y2 == x3b
                }
            }

            fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
                self.mul($scalarfield::char()).is_zero()
            }
        }

        impl CurveAffine for $affine {
            type Engine = Bls12;
            type Scalar = $scalarfield;
            type Base = $basefield;
            type Prepared = $prepared;
            type Projective = $projective;
            type Uncompressed = $uncompressed;
            type Compressed = $compressed;
            type Pair = $pairing;
            type PairingResult = Fq12;

            fn zero() -> Self {
                $affine {
                    x: $basefield::zero(),
                    y: $basefield::one(),
                    infinity: true,
                }
            }

            fn one() -> Self {
                Self::get_generator()
            }

            fn is_zero(&self) -> bool {
                self.infinity
            }

            fn mul<S: Into<<Self::Scalar as PrimeField>::Repr>>(&self, by: S) -> $projective {
                let bits = BitIterator::new(by.into());
                self.mul_bits(bits)
            }

            fn negate(&mut self) {
                if !self.is_zero() {
                    self.y.negate();
                }
            }

            fn prepare(&self) -> Self::Prepared {
                $prepared::from_affine(*self)
            }

            fn pairing_with(&self, other: &Self::Pair) -> Self::PairingResult {
                self.perform_pairing(other)
            }

            fn into_projective(&self) -> $projective {
                (*self).into()
            }

            fn as_tuple(&self) -> (&$basefield, &$basefield) {
                (&self.x, &self.y)
            }

            unsafe fn as_tuple_mut(&mut self) -> (&mut $basefield, &mut $basefield) {
                (&mut self.x, &mut self.y)
            }

            // pre[0] becomes (2^64) * self, pre[1]  becomes (2^128) * self, and pre[2] (becomes 2^196) * self
            fn precomp_3(&self, pre: &mut [Self]) {
                // TODO: check if pre has the right length?
                // TODO: possible optimization: convert 3 points into affine jointly by doing a single inversion, rather than separately
                // In fact, this function gets called multiple times, and the conversions to affine could be cheaper if done together
                let mut p = self.into_projective();
                for i in 0..3 {
                    for _ in 0..64 {
                        p.double();
                    }
                    pre[i] = p.into_affine();
                }
            }

            // Expects pre[0] = (2^64) * self, pre[1] = (2^128) * self, pre[2] = (2^192) * self
            fn mul_precomp_3<S: Into<<Self::Scalar as PrimeField>::Repr>>(
                &self,
                other: S,
                pre: &[Self],
            ) -> $projective {
                // TODO: we may decide we should clear memory, such as the old self
                // and the precomp array.
                // For now, none of the other functions do that, either.

                // Interleaved window technique: deal with each of the four words of the scalar in parallel
                // TODO: possible optimization: maybe convert precomp to affine using a single inversion and about 16 multiplications?

                let mut precomp = Vec::with_capacity(16);
                precomp.push(Self::Projective::zero()); // 0000 - 0*self
                precomp.push(self.into_projective()); // 0001 - 1*self
                precomp.push(pre[0].into_projective()); // 0010 - (2^64)*self
                precomp.push(precomp[2]);
                precomp[3].add_assign_mixed(self); // 0011 - (2^64+1)*self
                precomp.push(pre[1].into_projective()); // 0100 - (2^128)*self
                precomp.push(precomp[4]);
                precomp[5].add_assign_mixed(self); // 0101 - (2^128+1)*self
                precomp.push(precomp[2]);
                precomp[6].add_assign_mixed(&pre[1]); // 0110 - (2^128+2^64)*self
                precomp.push(precomp[6]);
                precomp[7].add_assign_mixed(self); // 0111 - (2^128+2^64+1)*self
                precomp.push(pre[2].into_projective()); // 1000  - (2^192)*self
                for i in 9..16 {
                    precomp.push(precomp[i - 8]);
                    precomp[i].add_assign_mixed(&pre[2]); // 1001 trough 1111 -- 2^192*self + ...
                }

                let repr = other.into();
                let bits: &[u64; 4] = &repr.0;
                let mut nibble = (bits[3] >> 60) & 8;
                nibble |= (bits[2] >> 61) & 4;
                nibble |= (bits[1] >> 62) & 2;
                nibble |= (bits[0] >> 63) & 1;
                let mut res = precomp[nibble as usize];

                for i in (0..63).rev() {
                    res.double();
                    nibble = ((bits[3] >> i) << 3) & 8; // can't shift by i-3 because it can be negative
                    nibble |= ((bits[2] >> i) << 2) & 4;
                    nibble |= ((bits[1] >> i) << 1) & 2;
                    nibble |= (bits[0] >> i) & 1;
                    res.add_assign(&precomp[nibble as usize]);
                }
                res
            }

            // pre[i] becomes (\sum_{b such that bth bit of i is 1} 2^{32i}) * self for i in 0..25
            fn precomp_256(&self, pre: &mut [Self]) {
                // TODO: check if pre has the right length?
                // TODO: possible optimization: convert 256 points into affine jointly by doing a single inversion, rather than separately
                // In fact, this function gets called multiple times, and the conversions to affine could be cheaper if done together

                pre[0] = Self::zero();
                let mut piece_length = 1;
                let mut power_of_2_times_self = self.into_projective(); // power_of_2_times_self = 2^{32*piece_length} * self
                while piece_length <= 128 {
                    // operate in pieces of length 1, 2, 4, 8, 16, 32, 64, 128
                    pre[piece_length] = power_of_2_times_self.into_affine();
                    for i in 1..piece_length {
                        pre[i + piece_length] = pre[i];
                        let mut temp = pre[i].into_projective();
                        temp.add_assign_mixed(&pre[piece_length]);
                        pre[i + piece_length] = temp.into_affine();
                    }
                    if piece_length < 128 {
                        for _ in 0..32 {
                            power_of_2_times_self.double();
                        }
                    }
                    piece_length *= 2;
                }
            }

            // Expects pre[i] = (\sum_{b such that bth bit of i is 1} 2^{32i}) * self for i in 0..256
            // pre can be obtained by calling precomp_256
            fn mul_precomp_256<S: Into<<Self::Scalar as PrimeField>::Repr>>(
                &self,
                other: S,
                pre: &[Self],
            ) -> $projective {
                // TODO: we may decide we should clear memory, such as the old self
                // and the precomp array.
                // For now, none of the other functions do that, either.

                // Interleaved window technique: deal with each of the 8 32-bit chunks words of the scalar in parallel
                let repr = other.into();
                let bits: &[u64; 4] = &repr.0; // Not using as_ref here, to ensure a compile-time error if repr not [u64; 4]

                let mut byte = (bits[3] >> 56) & 128;
                byte |= (bits[3] >> 25) & 64;
                byte |= (bits[2] >> 58) & 32;
                byte |= (bits[2] >> 27) & 16;
                byte |= (bits[1] >> 60) & 8;
                byte |= (bits[1] >> 29) & 4;
                byte |= (bits[0] >> 62) & 2;
                byte |= (bits[0] >> 31) & 1;
                let mut res = pre[byte as usize].into_projective();

                for i in (0..31).rev() {
                    res.double();
                    byte = (bits[3] >> (i + 25)) & 128;
                    byte |= ((bits[3] >> i) << 6) & 64; // can't shift by i-6 because it can be negative
                    byte |= (bits[2] >> (i + 27)) & 32;
                    byte |= ((bits[2] >> i) << 4) & 16;
                    byte |= (bits[1] >> (i + 29)) & 8;
                    byte |= ((bits[1] >> i) << 2) & 4;
                    byte |= (bits[0] >> (i + 31)) & 2;
                    byte |= (bits[0] >> i) & 1;
                    res.add_assign_mixed(&pre[byte as usize]);
                }
                res
            }

            // TODO: may want to look at http://cacr.uwaterloo.ca/techreports/2001/corr2001-41.ps;
            // TODO: may want to look at algorithms in Relic https://github.com/relic-toolkit/relic

            fn sum_of_products(points: &[Self], scalars: &[&[u64; 4]]) -> $projective {
                // TODO: figure out what to do if the lengths of the two input slices don't match
                // For now, take the minimum
                let num_components = if points.len() < scalars.len() {
                    points.len()
                } else {
                    scalars.len()
                };
                Self::sum_of_products_pippinger(
                    points,
                    scalars,
                    Self::find_pippinger_window(num_components),
                )
            }

            fn find_pippinger_window(num_components: usize) -> usize {
                // (20, 3), (43, 3) means that if 20 <= num_components < 43, you should use w=3
                // These were obtained from find_pippinger_window_via_estimate
                let boundaries = [
                    (1, 1),
                    (2, 2),
                    (20, 3),
                    (43, 4),
                    (105, 5),
                    (239, 6),
                    (578, 7),
                    (1258, 8),
                    (3464, 9),
                    (6492, 10),
                    (17146, 11),
                    (33676, 12),
                    (60319, 13),
                    (218189, 14),
                    (303280, 15),
                    (543651, 16),
                ];
                for i in 1..boundaries.len() {
                    if boundaries[i].0 > num_components {
                        return boundaries[i - 1].1;
                    }
                }
                boundaries[boundaries.len() - 1].1
            }

            // This function estimates the number of mixed (projective+affine) and projective additions
            // to well within 1%, and overall running time for G1 to within 3%, at least on one particular machine
            // for num_components < 10000.
            fn find_pippinger_window_via_estimate(num_components: usize) -> usize {
                let n_components = num_components as f64;
                let affine_time = 768.0; // This is from emprirical time (in ns) for a G1 mixed addition
                let projective_time = 1043.0; // This is from empirical time (in ns) for a G1 projective addition
                let mut w = 1;
                let mut two_to_w = 2.0;
                let mut affine_adds = 127.0 * n_components;
                let mut projective_adds = 256.0;
                let mut old_total_cost =
                    affine_adds * affine_time + projective_adds * projective_time;
                while w < 63 {
                    w += 1;
                    two_to_w *= 2.0;
                    let loop_iterations = (255 / w + 1) as f64; // 256/w with rounding up
                    affine_adds =
                        (loop_iterations - 2.0) * n_components * (two_to_w - 1.0) / two_to_w; // The (two_to_w-1))/two_to_w is to account for 0 buckets
                                                                                              // First addition to each bucket is quick, because the bucket is 0. So
                                                                                              // we need to subtract the number of nonempty buckets times the number of loop iterations
                    let prob_empty_bucket = (1.0 - 1.0 / two_to_w).powf(n_components);
                    let expected_nonempty_nonzero_buckets =
                        (two_to_w - 1.0) * (1.0 - prob_empty_bucket);
                    affine_adds -= expected_nonempty_nonzero_buckets * (loop_iterations - 2.0);
                    let mut _a0 = expected_nonempty_nonzero_buckets * (loop_iterations - 2.0);
                    // first and last iteration are different.

                    // First iteration high-order bit is always 0,
                    // because the prime r is close to 2^255
                    let first_iteration_max_bucket = two_to_w / 2.0;
                    affine_adds += n_components * (first_iteration_max_bucket - 1.0)
                        / first_iteration_max_bucket; // The (two_to_w-1))/two_to_w is to account for 0 buckets
                    let prob_empty_bucket_first_iteration =
                        (1.0 - 1.0 / first_iteration_max_bucket).powf(n_components);
                    let expected_nonempty_nonzero_buckets_first_iteration =
                        (first_iteration_max_bucket - 1.0)
                            * (1.0 - prob_empty_bucket_first_iteration);
                    affine_adds -= expected_nonempty_nonzero_buckets_first_iteration;
                    _a0 += expected_nonempty_nonzero_buckets_first_iteration;

                    // last iteration is the leftover bits
                    let last_iteration_bit_width = 256 - (255 / w) * w;
                    let last_iteration_max_bucket = (1u64 << last_iteration_bit_width) as f64;
                    affine_adds += n_components * (last_iteration_max_bucket - 1.0)
                        / last_iteration_max_bucket;
                    let prob_empty_bucket_last_iteration =
                        (1.0 - 1.0 / last_iteration_max_bucket).powf(n_components);
                    let expected_nonempty_nonzero_buckets_last_iteration =
                        (last_iteration_max_bucket - 1.0)
                            * (1.0 - prob_empty_bucket_last_iteration);
                    affine_adds -= expected_nonempty_nonzero_buckets_last_iteration;
                    _a0 += expected_nonempty_nonzero_buckets_last_iteration;

                    projective_adds = (loop_iterations - 2.0)
                        * (expected_nonempty_nonzero_buckets + two_to_w - 2.0)
                        + first_iteration_max_bucket
                        - 2.0
                        + expected_nonempty_nonzero_buckets_first_iteration
                        + last_iteration_max_bucket
                        - 2.0
                        + expected_nonempty_nonzero_buckets_last_iteration;
                    let _p0 = (loop_iterations - 2.0)
                        * (two_to_w - 1.0 - expected_nonempty_nonzero_buckets)
                        + first_iteration_max_bucket
                        - expected_nonempty_nonzero_buckets_first_iteration
                        + last_iteration_max_bucket
                        - expected_nonempty_nonzero_buckets_last_iteration
                        - 2.0;
                    let new_total_cost =
                        affine_adds * affine_time + projective_adds * projective_time;
                    /*print!("w = {}, total_cost = {} ", w, new_total_cost);
                    println!(
                        "a={}, p={}, a0={}, p0={}, ne={}, pe={}",
                        affine_adds,
                        projective_adds,
                        a0,
                        p0,
                        expected_nonempty_nonzero_buckets,
                        prob_empty_bucket
                    );*/
                    if new_total_cost > old_total_cost {
                        w -= 1;
                        break;
                    }
                    old_total_cost = new_total_cost;
                }
                //println!("Result: {}", w);
                w
            }

            fn sum_of_products_pippinger(
                points: &[Self],
                scalars: &[&[u64; 4]],
                window: usize,
            ) -> $projective {
                // TODO: we may decide we should clear memory
                // For now, none of the other functions do that, either.
                // TODO: is it worth it to convert buckets to affine? (with one inversion)
                let mut res = Self::Projective::zero();
                let num_components = if points.len() < scalars.len() {
                    points.len()
                } else {
                    scalars.len()
                };
                let num_buckets = 1 << window;
                let edge = window - 1;
                let mask = (num_buckets - 1) as u64;
                let mut buckets = vec![Self::Projective::zero(); num_buckets];
                let mut bit_sequence_index = 255; // points to the top bit we need to process
                let mut num_doubles = 0;
                loop {
                    for _ in 0..num_doubles {
                        res.double();
                    }
                    let mut max_bucket = 0;
                    let word_index = bit_sequence_index >> 6; // divide bit_sequence_index by 64 to find word_index
                    let bit_index = bit_sequence_index & 63; // mod bit_sequence_index by 64 to find bit_index
                    if bit_index < edge {
                        // we are on the edge of a word; have to look at the previous word, if it exists
                        if word_index == 0 {
                            // there is no word before
                            let smaller_mask = ((1 << (bit_index + 1)) - 1) as u64;
                            for i in 0..num_components {
                                let bucket_index: usize =
                                    (scalars[i][word_index] & smaller_mask) as usize;
                                if bucket_index > 0 {
                                    buckets[bucket_index].add_assign_mixed(&points[i]);
                                    if bucket_index > max_bucket {
                                        max_bucket = bucket_index;
                                    }
                                }
                            }
                        } else {
                            // there is a word before
                            let high_order_mask = ((1 << (bit_index + 1)) - 1) as u64;
                            let high_order_shift = edge - bit_index;
                            let low_order_mask = ((1 << high_order_shift) - 1) as u64;
                            let low_order_shift = 64 - high_order_shift;
                            let prev_word_index = word_index - 1;
                            for i in 0..num_components {
                                let mut bucket_index = ((scalars[i][word_index] & high_order_mask)
                                    << high_order_shift)
                                    as usize;
                                bucket_index |= ((scalars[i][prev_word_index] >> low_order_shift)
                                    & low_order_mask)
                                    as usize;
                                if bucket_index > 0 {
                                    buckets[bucket_index].add_assign_mixed(&points[i]);
                                    if bucket_index > max_bucket {
                                        max_bucket = bucket_index;
                                    }
                                }
                            }
                        }
                    } else {
                        let shift = bit_index - edge;
                        for i in 0..num_components {
                            let bucket_index: usize =
                                ((scalars[i][word_index] >> shift) & mask) as usize;
                            assert!(bit_sequence_index != 255 || scalars[i][3] >> 63 == 0);
                            if bucket_index > 0 {
                                buckets[bucket_index].add_assign_mixed(&points[i]);
                                if bucket_index > max_bucket {
                                    max_bucket = bucket_index;
                                }
                            }
                        }
                    }
                    res.add_assign(&buckets[max_bucket]);
                    for i in (1..max_bucket).rev() {
                        let temp = buckets[i + 1]; // TODO: this is necessary only to please the borrow checker
                        buckets[i].add_assign(&temp);
                        res.add_assign(&buckets[i]);
                        buckets[i + 1] = Self::Projective::zero();
                    }
                    buckets[1] = Self::Projective::zero();
                    if bit_sequence_index < window {
                        break;
                    }
                    bit_sequence_index -= window;
                    num_doubles = {
                        if bit_sequence_index < edge {
                            bit_sequence_index + 1
                        } else {
                            window
                        }
                    };
                }
                res
            }

            // Expects pre[j*256+i] = (\sum_{b such that bth bit of i is 1} 2^{32i}) * self[j] for i in 0..256 and for each j
            // pre can be obtained by calling precomp_256
            fn sum_of_products_precomp_256(
                points: &[Self],
                scalars: &[&[u64; 4]],
                pre: &[Self],
            ) -> $projective {
                // TODO: we may decide we should clear memory, such as the old self
                // and the precomp array.
                // For now, none of the other functions do that, either.
                // TODO: figure out what to do if the lengths of the two input slices don't match
                // For now, take the minimum
                let mut res = Self::Projective::zero();
                let num_components = if points.len() < scalars.len() {
                    points.len()
                } else {
                    scalars.len()
                };

                // Interleaved window technique: deal with each of the 8 32-bit chunks words of each scalar in parallel

                // TODO: understand how this large table will affect performance due to caching

                for i in (0..32).rev() {
                    res.double();
                    for j in 0..num_components {
                        let mut byte = (scalars[j][3] >> (i + 25)) & 128;
                        byte |= ((scalars[j][3] >> i) << 6) & 64; // can't shift by i-6 because it can be negative
                        byte |= (scalars[j][2] >> (i + 27)) & 32;
                        byte |= ((scalars[j][2] >> i) << 4) & 16;
                        byte |= (scalars[j][1] >> (i + 29)) & 8;
                        byte |= ((scalars[j][1] >> i) << 2) & 4;
                        byte |= (scalars[j][0] >> (i + 31)) & 2;
                        byte |= (scalars[j][0] >> i) & 1;
                        res.add_assign_mixed(&pre[(j << 8) + byte as usize]);
                    }
                }
                res
            }
        }

        // impl Rand for $projective {}

        impl CurveProjective for $projective {
            type Engine = Bls12;
            type Scalar = $scalarfield;
            type Base = $basefield;
            type Affine = $affine;

            fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
                loop {
                    let x = $basefield::random(rng);
                    let greatest = rng.next_u32() % 2 != 0;
                    if let Some(p) = $affine::get_point_from_x(x, greatest) {
                        let p = p.scale_by_cofactor();

                        if !p.is_zero() {
                            return p;
                        }
                    }
                }
            }

            // The point at infinity is always represented by
            // Z = 0.
            fn zero() -> Self {
                $projective {
                    x: $basefield::zero(),
                    y: $basefield::one(),
                    z: $basefield::zero(),
                }
            }

            fn one() -> Self {
                $affine::one().into()
            }

            // The point at infinity is always represented by
            // Z = 0.
            fn is_zero(&self) -> bool {
                self.z.is_zero()
            }

            fn is_normalized(&self) -> bool {
                self.is_zero() || self.z == $basefield::one()
            }

            fn batch_normalization(v: &mut [Self]) {
                // Montgomery’s Trick and Fast Implementation of Masked AES
                // Genelle, Prouff and Quisquater
                // Section 3.2

                // First pass: compute [a, ab, abc, ...]
                let mut prod = Vec::with_capacity(v.len());
                let mut tmp = $basefield::one();
                for g in v
                    .iter_mut()
                    // Ignore normalized elements
                    .filter(|g| !g.is_normalized())
                {
                    tmp.mul_assign(&g.z);
                    prod.push(tmp);
                }

                // Invert `tmp`.
                tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

                // Second pass: iterate backwards to compute inverses
                for (g, s) in v
                    .iter_mut()
                    // Backwards
                    .rev()
                    // Ignore normalized elements
                    .filter(|g| !g.is_normalized())
                    // Backwards, skip last element, fill in one for last term.
                    .zip(
                        prod.into_iter()
                            .rev()
                            .skip(1)
                            .chain(Some($basefield::one())),
                    )
                {
                    // tmp := tmp * g.z; g.z := tmp * s = 1/z
                    let mut newtmp = tmp;
                    newtmp.mul_assign(&g.z);
                    g.z = tmp;
                    g.z.mul_assign(&s);
                    tmp = newtmp;
                }

                // Perform affine transformations
                for g in v.iter_mut().filter(|g| !g.is_normalized()) {
                    let mut z = g.z; // 1/z
                    z.square(); // 1/z^2
                    g.x.mul_assign(&z); // x/z^2
                    z.mul_assign(&g.z); // 1/z^3
                    g.y.mul_assign(&z); // y/z^3
                    g.z = $basefield::one(); // z = 1
                }
            }

            fn double(&mut self) {
                if self.is_zero() {
                    return;
                }

                // Other than the point at infinity, no points on E or E'
                // can double to equal the point at infinity, as y=0 is
                // never true for points on the curve. (-4 and -4u-4
                // are not cubic residue in their respective fields.)

                // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

                // A = X1^2
                let mut a = self.x;
                a.square();

                // B = Y1^2
                let mut b = self.y;
                b.square();

                // C = B^2
                let mut c = b;
                c.square();

                // D = 2*((X1+B)2-A-C)
                let mut d = self.x;
                d.add_assign(&b);
                d.square();
                d.sub_assign(&a);
                d.sub_assign(&c);
                d.double();

                // E = 3*A
                let mut e = a;
                e.double();
                e.add_assign(&a);

                // F = E^2
                let mut f = e;
                f.square();

                // Z3 = 2*Y1*Z1
                self.z.mul_assign(&self.y);
                self.z.double();

                // X3 = F-2*D
                self.x = f;
                self.x.sub_assign(&d);
                self.x.sub_assign(&d);

                // Y3 = E*(D-X3)-8*C
                self.y = d;
                self.y.sub_assign(&self.x);
                self.y.mul_assign(&e);
                c.double();
                c.double();
                c.double();
                self.y.sub_assign(&c);
            }

            fn add_assign(&mut self, other: &Self) {
                if self.is_zero() {
                    *self = *other;
                    return;
                }

                if other.is_zero() {
                    return;
                }

                // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

                // Z1Z1 = Z1^2
                let mut z1z1 = self.z;
                z1z1.square();

                // Z2Z2 = Z2^2
                let mut z2z2 = other.z;
                z2z2.square();

                // U1 = X1*Z2Z2
                let mut u1 = self.x;
                u1.mul_assign(&z2z2);

                // U2 = X2*Z1Z1
                let mut u2 = other.x;
                u2.mul_assign(&z1z1);

                // S1 = Y1*Z2*Z2Z2
                let mut s1 = self.y;
                s1.mul_assign(&other.z);
                s1.mul_assign(&z2z2);

                // S2 = Y2*Z1*Z1Z1
                let mut s2 = other.y;
                s2.mul_assign(&self.z);
                s2.mul_assign(&z1z1);

                if u1 == u2 && s1 == s2 {
                    // The two points are equal, so we double.
                    self.double();
                } else {
                    // If we're adding -a and a together, self.z becomes zero as H becomes zero.

                    // H = U2-U1
                    let mut h = u2;
                    h.sub_assign(&u1);

                    // I = (2*H)^2
                    let mut i = h;
                    i.double();
                    i.square();

                    // J = H*I
                    let mut j = h;
                    j.mul_assign(&i);

                    // r = 2*(S2-S1)
                    let mut r = s2;
                    r.sub_assign(&s1);
                    r.double();

                    // V = U1*I
                    let mut v = u1;
                    v.mul_assign(&i);

                    // X3 = r^2 - J - 2*V
                    self.x = r;
                    self.x.square();
                    self.x.sub_assign(&j);
                    self.x.sub_assign(&v);
                    self.x.sub_assign(&v);

                    // Y3 = r*(V - X3) - 2*S1*J
                    self.y = v;
                    self.y.sub_assign(&self.x);
                    self.y.mul_assign(&r);
                    s1.mul_assign(&j); // S1 = S1 * J * 2
                    s1.double();
                    self.y.sub_assign(&s1);

                    // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H
                    self.z.add_assign(&other.z);
                    self.z.square();
                    self.z.sub_assign(&z1z1);
                    self.z.sub_assign(&z2z2);
                    self.z.mul_assign(&h);
                }
            }

            fn add_assign_mixed(&mut self, other: &Self::Affine) {
                if other.is_zero() {
                    return;
                }

                if self.is_zero() {
                    self.x = other.x;
                    self.y = other.y;
                    self.z = $basefield::one();
                    return;
                }

                // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl

                // Z1Z1 = Z1^2
                let mut z1z1 = self.z;
                z1z1.square();

                // U2 = X2*Z1Z1
                let mut u2 = other.x;
                u2.mul_assign(&z1z1);

                // S2 = Y2*Z1*Z1Z1
                let mut s2 = other.y;
                s2.mul_assign(&self.z);
                s2.mul_assign(&z1z1);

                if self.x == u2 && self.y == s2 {
                    // The two points are equal, so we double.
                    self.double();
                } else {
                    // If we're adding -a and a together, self.z becomes zero as H becomes zero.

                    // H = U2-X1
                    let mut h = u2;
                    h.sub_assign(&self.x);

                    // HH = H^2
                    let mut hh = h;
                    hh.square();

                    // I = 4*HH
                    let mut i = hh;
                    i.double();
                    i.double();

                    // J = H*I
                    let mut j = h;
                    j.mul_assign(&i);

                    // r = 2*(S2-Y1)
                    let mut r = s2;
                    r.sub_assign(&self.y);
                    r.double();

                    // V = X1*I
                    let mut v = self.x;
                    v.mul_assign(&i);

                    // X3 = r^2 - J - 2*V
                    self.x = r;
                    self.x.square();
                    self.x.sub_assign(&j);
                    self.x.sub_assign(&v);
                    self.x.sub_assign(&v);

                    // Y3 = r*(V-X3)-2*Y1*J
                    j.mul_assign(&self.y); // J = 2*Y1*J
                    j.double();
                    self.y = v;
                    self.y.sub_assign(&self.x);
                    self.y.mul_assign(&r);
                    self.y.sub_assign(&j);

                    // Z3 = (Z1+H)^2-Z1Z1-HH
                    self.z.add_assign(&h);
                    self.z.square();
                    self.z.sub_assign(&z1z1);
                    self.z.sub_assign(&hh);
                }
            }

            fn negate(&mut self) {
                if !self.is_zero() {
                    self.y.negate()
                }
            }

            fn mul_assign<S: Into<<Self::Scalar as PrimeField>::Repr>>(&mut self, other: S) {
                let mut res = Self::zero();

                let mut found_one = false;

                for i in BitIterator::new(other.into()) {
                    if found_one {
                        res.double();
                    } else {
                        found_one = i;
                    }

                    if i {
                        res.add_assign(self);
                    }
                }

                *self = res;
            }

            fn into_affine(&self) -> $affine {
                (*self).into()
            }

            fn recommended_wnaf_for_scalar(scalar: <Self::Scalar as PrimeField>::Repr) -> usize {
                Self::empirical_recommended_wnaf_for_scalar(scalar)
            }

            fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
                Self::empirical_recommended_wnaf_for_num_scalars(num_scalars)
            }

            fn as_tuple(&self) -> (&$basefield, &$basefield, &$basefield) {
                (&self.x, &self.y, &self.z)
            }

            unsafe fn as_tuple_mut(
                &mut self,
            ) -> (&mut $basefield, &mut $basefield, &mut $basefield) {
                (&mut self.x, &mut self.y, &mut self.z)
            }
        }

        // The affine point X, Y is represented in the jacobian
        // coordinates with Z = 1.
        impl From<$affine> for $projective {
            fn from(p: $affine) -> $projective {
                if p.is_zero() {
                    $projective::zero()
                } else {
                    $projective {
                        x: p.x,
                        y: p.y,
                        z: $basefield::one(),
                    }
                }
            }
        }

        // The projective point X, Y, Z is represented in the affine
        // coordinates as X/Z^2, Y/Z^3.
        impl From<$projective> for $affine {
            fn from(p: $projective) -> $affine {
                if p.is_zero() {
                    $affine::zero()
                } else if p.z == $basefield::one() {
                    // If Z is one, the point is already normalized.
                    $affine {
                        x: p.x,
                        y: p.y,
                        infinity: false,
                    }
                } else {
                    // Z is nonzero, so it must have an inverse in a field.
                    let zinv = p.z.inverse().unwrap();
                    let mut zinv_powered = zinv;
                    zinv_powered.square();

                    // X/Z^2
                    let mut x = p.x;
                    x.mul_assign(&zinv_powered);

                    // Y/Z^3
                    let mut y = p.y;
                    zinv_powered.mul_assign(&zinv);
                    y.mul_assign(&zinv_powered);

                    $affine {
                        x,
                        y,
                        infinity: false,
                    }
                }
            }
        }
    };
}

pub mod g1;
pub mod g2;

pub use self::g1::*;
pub use self::g2::*;

#[test]
fn test_group_defaults() {
    use crate::{CurveAffine, CurveProjective};

    assert_eq!(G1::default(), G1::zero());
    assert_eq!(G2::default(), G2::zero());
    assert_eq!(G1Affine::default(), G1Affine::zero());
    assert_eq!(G2Affine::default(), G2Affine::zero());
}
