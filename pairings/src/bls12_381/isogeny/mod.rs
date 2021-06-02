/*!
Isogenies E' -> E and E2' -> E2 for OSSWU map.
*/

mod g1;
mod g2;
#[cfg(test)]
mod tests;

use crate::CurveProjective;
use ff::Field;

/// Alias for the coordinate type corresponding to a CurveProjective type
type CoordT<PtT> = <PtT as CurveProjective>::Base;

/// Evaluate isogeny map from curve with non-zero j-invariant.
pub trait IsogenyMap {
    /// Eavluate isogeny map
    fn isogeny_map(&mut self);
}

/// Generic isogeny evaluation function
fn eval_iso<PtT: CurveProjective>(pt: &mut PtT, coeffs: [&[CoordT<PtT>]; 4]) {
    // XXX hack: In array below, 16 is long enough for both iso11 and iso3.
    // Rust (still) can't handle generic array sizes (issue #43408)
    let mut tmp = [CoordT::<PtT>::zero(); 16];
    let mut mapvals = [CoordT::<PtT>::zero(); 4];
    // scope for pt borrow
    {
        // unpack input point
        let (x, y, z) = pt.as_tuple();

        // precompute powers of z
        let zpows = {
            // XXX hack: In array below, 15 is long enough for both iso11 and iso3.
            let mut zpows = [CoordT::<PtT>::zero(); 15];
            zpows[0] = *z;
            zpows[0].square(); // z^2
            zpows[1] = zpows[0];
            zpows[1].square(); // z^4
            {
                let (z_squared, rest) = zpows.split_at_mut(1);
                for idx in 1..coeffs[2].len() - 2 {
                    if idx % 2 == 0 {
                        rest[idx] = rest[idx / 2 - 1];
                        rest[idx].square();
                    } else {
                        rest[idx] = rest[idx - 1];
                        rest[idx].mul_assign(&z_squared[0]);
                    }
                }
            }
            zpows
        };

        for idx in 0..4 {
            let clen = coeffs[idx].len() - 1;
            // multiply coeffs by powers of Z
            for jdx in 0..clen {
                tmp[jdx] = coeffs[idx][clen - 1 - jdx];
                tmp[jdx].mul_assign(&zpows[jdx]);
            }
            // compute map value by Horner's rule
            mapvals[idx] = coeffs[idx][clen];
            for tmpval in &tmp[..clen] {
                mapvals[idx].mul_assign(x);
                mapvals[idx].add_assign(tmpval);
            }
        }

        // x denominator is order 1 less than x numerator, so we need an extra factor of Z^2
        mapvals[1].mul_assign(&zpows[0]);

        // multiply result of Y map by the y-coord, y / z^3
        mapvals[2].mul_assign(y);
        mapvals[3].mul_assign(z);
        mapvals[3].mul_assign(&zpows[0]);
    } // pt is no longer borrowed here

    // hack to simultaneously access elements of tmp
    let (xx, yy, zz) = {
        let (xx, rest) = tmp.split_at_mut(1);
        let (yy, rest) = rest.split_at_mut(1);
        (&mut xx[0], &mut yy[0], &mut rest[0])
    };

    // compute Jacobian coordinates of resulting point
    *zz = mapvals[1];
    zz.mul_assign(&mapvals[3]); // Zout = xden * yden

    *xx = mapvals[0];
    xx.mul_assign(&mapvals[3]); // xnum * yden
    xx.mul_assign(zz); // xnum * xden * yden^2

    *yy = *zz;
    yy.square(); // xden^2 * yden^2
    yy.mul_assign(&mapvals[2]); // ynum * xden^2 * yden^2
    yy.mul_assign(&mapvals[1]); // ynum * xden^3 * yden^2

    let (x, y, z) = unsafe { pt.as_tuple_mut() };
    *x = *xx;
    *y = *yy;
    *z = *zz;
}
