/*!
Tests for isogenies.
*/

use super::IsogenyMap;
use crate::{
    bls12_381::{
        transmute::{g1_projective, g2_projective},
        Fq, Fq2, FqRepr,
    },
    CurveProjective,
};
use ff::{Field, PrimeField};

#[test]
fn test_iso11() {
    let zero = Fq::zero();
    let mut pt = unsafe { g1_projective(zero, zero, zero) };
    pt.isogeny_map();
    let (x, y, z) = pt.as_tuple();
    assert_eq!(x, &zero);
    assert_eq!(y, &zero);
    assert_eq!(z, &zero);

    let one = Fq::one();
    let mut pt = unsafe { g1_projective(one, one, one) };
    pt.isogeny_map();
    let (x, y, z) = pt.as_tuple();
    assert_eq!(
        x,
        &Fq::from_repr(FqRepr([
            0xb129fab9bef88eddu64,
            0x1c5429e2f4b8bc35u64,
            0xcaab8cc9ec4893f2u64,
            0x9e9c31f30a607c8bu64,
            0x9661fcf22bedfddbu64,
            0x10fc4a3ba5f48e07u64,
        ]))
        .unwrap()
    );
    assert_eq!(
        y,
        &Fq::from_repr(FqRepr([
            0xaf52c5fbd490f370u64,
            0x1533c0f27b46c02fu64,
            0xc8890dd0987b134fu64,
            0x43e2d5f172257d50u64,
            0x538ebef63fb145beu64,
            0x11eab1145b95cb9fu64,
        ]))
        .unwrap()
    );
    assert_eq!(
        z,
        &Fq::from_repr(FqRepr([
            0x7441c43513e11f49u64,
            0x620b0af2483ad30fu64,
            0x678c5bf3ad4090b4u64,
            0xc75152c6f387d070u64,
            0x5f3cc0ed1bd3f0eeu64,
            0x12514e630a486abbu64,
        ]))
        .unwrap()
    );

    let xi = Fq::from_repr(FqRepr([
        0xf6adc4118ae592abu64,
        0xa384a7ab165def35u64,
        0x2365b1fb1c8a73bfu64,
        0xc40dc338ca285231u64,
        0x47ff3364428c59b3u64,
        0x1789051238d025e3u64,
    ]))
    .unwrap();
    let yi = Fq::from_repr(FqRepr([
        0x1a635634e9cced27u64,
        0x03f604e47bc51aa9u64,
        0x06f6ff472fa7276eu64,
        0x0459ed10f1f8abb1u64,
        0x8e76c82bd4a29d21u64,
        0x088cb5712bf81924u64,
    ]))
    .unwrap();
    let zi = Fq::from_repr(FqRepr([
        0x0416411fe2e97d06u64,
        0xaced7fec7a63fe65u64,
        0x683295bcaed54202u64,
        0xbdc3405df9ff0a3bu64,
        0xf9698f57510273fbu64,
        0x064bb4b501466b2au64,
    ]))
    .unwrap();
    let mut pt = unsafe { g1_projective(xi, yi, zi) };
    pt.isogeny_map();
    let (x, y, z) = pt.as_tuple();
    assert_eq!(
        x,
        &Fq::from_repr(FqRepr([
            0xa51741657e71601du64,
            0x1771cef34519b6f2u64,
            0x2d1aff4e4ae28379u64,
            0x9ddcd540391389adu64,
            0x0db61b8544450f53u64,
            0x0f34c6cea2fc0199u64,
        ]))
        .unwrap()
    );
    assert_eq!(
        y,
        &Fq::from_repr(FqRepr([
            0xd1d70b485ea22464u64,
            0xd3a592a3ffc2c77cu64,
            0x72ef2afff097ad4fu64,
            0xf1c66e0e000b5673u64,
            0x1d32499c9f462716u64,
            0x19284e38020f6072u64,
        ]))
        .unwrap()
    );
    assert_eq!(
        z,
        &Fq::from_repr(FqRepr([
            0x583946b46d152c9fu64,
            0xb7f34ad188fdc105u64,
            0x47f7edb38429108au64,
            0xb6602e02d0d7ac4du64,
            0xc27121d0eb3d5efcu64,
            0x16f4243bf7230576u64,
        ]))
        .unwrap()
    );
}

#[test]
fn test_iso3() {
    let zero = Fq2::zero();
    let mut pt = unsafe { g2_projective(zero, zero, zero) };
    pt.isogeny_map();
    let (x, y, z) = pt.as_tuple();
    assert_eq!(x, &zero);
    assert_eq!(y, &zero);
    assert_eq!(z, &zero);

    let one = Fq2::one();
    let mut pt = unsafe { g2_projective(one, one, one) };
    pt.isogeny_map();
    let (x, y, z) = pt.as_tuple();
    let c0 = FqRepr([
        0x57c6555579807bcau64,
        0xc285c71b6d7a38e3u64,
        0xde7b4e7d31a614c6u64,
        0x31b21e4af64b0e94u64,
        0x8fc02d1bfb73bf52u64,
        0x1439b899baf1b35bu64,
    ]);
    let c1 = FqRepr([
        0xf58daaab358a307bu64,
        0x665f8e3829a071c6u64,
        0x55c5ca596c9b3369u64,
        0xfeecf110f9110a6au64,
        0xd464b281b39bd1ccu64,
        0x0e725f493c63801cu64,
    ]);
    let x_expect = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    let c0 = FqRepr([
        0xa72f3db7cb8405a4u64,
        0x221fda12b88ad097u64,
        0x71ec98c879891123u64,
        0x54f9a5b05305ae23u64,
        0xf176e62b3bde9b44u64,
        0x04d0ca6dbecbd55eu64,
    ]);
    let c1 = FqRepr([
        0xe1b3626ab65e39a9u64,
        0x4e79097a56dc4bd9u64,
        0xb0e977c69aa27452u64,
        0x761b0f37a1e26286u64,
        0xfbf7043de3811ad0u64,
        0x124c9ad43b6cf79bu64,
    ]);
    let y_expect = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    let c0 = FqRepr([
        0xb9fefffffffebb2au64,
        0x1eabfffeb153ffffu64,
        0x6730d2a0f6b0f624u64,
        0x64774b84f38512bfu64,
        0x4b1ba7b6434bacd7u64,
        0x1a0111ea397fe69au64,
    ]);
    let c1 = FqRepr([
        0x00000000000065b2u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
        0x0000000000000000u64,
    ]);
    let z_expect = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    assert_eq!(x, &x_expect);
    assert_eq!(y, &y_expect);
    assert_eq!(z, &z_expect);

    let c0 = FqRepr([
        0x0018c03388164247u64,
        0xc4c8890b30d528ebu64,
        0xd52d2a45caca6edau64,
        0x89b3941228dae354u64,
        0x3f3f7d07e4c40a93u64,
        0x0530990b2b3e9a8au64,
    ]);
    let c1 = FqRepr([
        0x6b90db064d0030e9u64,
        0xd6a6501c1871b906u64,
        0x11c92e91687441adu64,
        0xf974e31a71e5fe1fu64,
        0x87933ab312f66f88u64,
        0x117d0dba9f178439u64,
    ]);
    let xi = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    let c0 = FqRepr([
        0x6dee4915e87b601au64,
        0xad55ed81ecc390ffu64,
        0xa9c3c810a96f8ca7u64,
        0x0c7d97874f6f026du64,
        0x967de59661e37bb5u64,
        0x11b94175e3be4de8u64,
    ]);
    let c1 = FqRepr([
        0x53563b5cfa722ba8u64,
        0x41b7f7263e23c28eu64,
        0x17cf622d5607fbcau64,
        0xe8722180e02d0818u64,
        0xf8c75b4c8b66c965u64,
        0x035eea1ab1a2a087u64,
    ]);
    let yi = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    let c0 = FqRepr([
        0x71f8d78673dbfa39u64,
        0x62d7bae1a74336dcu64,
        0x53bf87ae6e302bd3u64,
        0x4d197aa97c5317f5u64,
        0xc41aa271acd3a3a1u64,
        0x189add484077dd45u64,
    ]);
    let c1 = FqRepr([
        0x9a214bfcea21674fu64,
        0x3a5d62187b013310u64,
        0xc15f3a4db5bc86a7u64,
        0x96b99fa5eb4f47c8u64,
        0xb36b52b4a8696193u64,
        0x0e613ba7c4916c20u64,
    ]);
    let zi = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    let mut pt = unsafe { g2_projective(xi, yi, zi) };
    pt.isogeny_map();
    let (x, y, z) = pt.as_tuple();
    let c0 = FqRepr([
        0xf119e132b7ebd22cu64,
        0x37932278669819e7u64,
        0xdb71788e6d1c6512u64,
        0x678934e396004f81u64,
        0x55213880b7ed140du64,
        0x181403b14aa19327u64,
    ]);
    let c1 = FqRepr([
        0xdaac25bd8310aef3u64,
        0xbdaab7e27633f5d2u64,
        0x2e8422b082fc8c69u64,
        0xf6b6f9af2f2fc258u64,
        0x8b649eeb97f5676eu64,
        0x13f21dc8a4dfcc1au64,
    ]);
    let x_expect = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    let c0 = FqRepr([
        0xbe1f08d76520ec2au64,
        0xd9ef23f135188a36u64,
        0x3b97d6bb83c22918u64,
        0x6a2ce7736962cd7cu64,
        0x95d5421d9c9465deu64,
        0x09cab53c88c263bdu64,
    ]);
    let c1 = FqRepr([
        0x3e6a004356660064u64,
        0x0b182f682ab74743u64,
        0xc53c7316655326eau64,
        0x669c0d885b42452au64,
        0x97df98a239aa957du64,
        0x06299d091ec0ed11u64,
    ]);
    let y_expect = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    let c0 = FqRepr([
        0xe518e02aaa358acdu64,
        0x4c00a671fa8fc185u64,
        0xf88193c7dd618937u64,
        0x2d6e07a3e0ca5733u64,
        0x121d7ae073e479fdu64,
        0x00644ae14e9341fbu64,
    ]);
    let c1 = FqRepr([
        0x9bed7fa96e783e15u64,
        0xde7d5d396f73c236u64,
        0x491857011bcac282u64,
        0x82d08553b1dacca2u64,
        0x41def4997b2fc93fu64,
        0x14474088f5b1d2e3u64,
    ]);
    let z_expect = Fq2 {
        c0: Fq::from_repr(c0).unwrap(),
        c1: Fq::from_repr(c1).unwrap(),
    };
    assert_eq!(x, &x_expect);
    assert_eq!(y, &y_expect);
    assert_eq!(z, &z_expect);
}
