/*!
 This module defines a hash_to_curve trait.
*/

use crate::{
    bls12_381::{ClearH, IsogenyMap, OSSWUMap},
    hash_to_field::{hash_to_field, ExpandMsg, FromRO},
    CurveProjective,
};

type CoordT<PtT> = <PtT as CurveProjective>::Base;

/// Random oracle and injective maps to curve
pub trait HashToCurve<X>
where
    X: ExpandMsg,
{
    /// Random oracle
    fn hash_to_curve<Mt: AsRef<[u8]>, Dt: AsRef<[u8]>>(msg: Mt, dst: Dt) -> Self;

    /// Injective encoding
    fn encode_to_curve<Mt: AsRef<[u8]>, Dt: AsRef<[u8]>>(msg: Mt, dst: Dt) -> Self;
}

impl<PtT, X> HashToCurve<X> for PtT
where
    PtT: ClearH + IsogenyMap + OSSWUMap,
    CoordT<PtT>: FromRO,
    X: ExpandMsg,
{
    fn hash_to_curve<Mt: AsRef<[u8]>, Dt: AsRef<[u8]>>(msg: Mt, dst: Dt) -> PtT {
        let mut p = {
            let u = hash_to_field::<CoordT<PtT>, X>(msg.as_ref(), dst.as_ref(), 2);
            let mut q0 = PtT::osswu_map(&u[0]);
            q0.isogeny_map();
            let mut q1 = PtT::osswu_map(&u[1]);
            q1.isogeny_map();
            q0.add_assign(&q1);
            q0
        };
        p.clear_h();
        p
    }

    fn encode_to_curve<Mt: AsRef<[u8]>, Dt: AsRef<[u8]>>(msg: Mt, dst: Dt) -> PtT {
        let mut p = {
            let u = hash_to_field::<CoordT<PtT>, X>(msg.as_ref(), dst.as_ref(), 1);
            PtT::osswu_map(&u[0])
        };
        p.isogeny_map();
        p.clear_h();
        p
    }
}
