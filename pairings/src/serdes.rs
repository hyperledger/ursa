use crate::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use ff::{PrimeField, PrimeFieldRepr};
use std::io::{Error, ErrorKind, Read, Result, Write};
type Compressed = bool;

/// Serialization support for group elements.
pub trait SerDes: Sized {
    /// Serialize a struct to a writer with a flag of compressness.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()>;

    /// Deserialize a struct; give an indicator if the element was compressed or not.
    /// Returns an error is the encoding does not match the indicator.
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self>;
}

impl SerDes for Fr {
    /// The compressed parameter has no effect since Fr element will always be compressed.
    fn serialize<W: Write>(&self, writer: &mut W, _compressed: Compressed) -> Result<()> {
        self.into_repr().write_be(writer)
    }

    /// The compressed parameter has no effect since Fr element will always be compressed.
    fn deserialize<R: Read>(reader: &mut R, _compressed: Compressed) -> Result<Self> {
        let mut r = FrRepr::default();
        r.read_be(reader)?;
        match Fr::from_repr(r) {
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => Ok(p),
        }
    }
}

impl SerDes for Fq12 {
    /// The compressed parameter has no effect since Fr element will always be compressed.
    fn serialize<W: Write>(&self, writer: &mut W, _compressed: Compressed) -> Result<()> {
        let mut buf: Vec<u8> = vec![];

        match self.c0.c0.c0.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c0.c0.c1.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c0.c1.c0.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c0.c1.c1.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c0.c2.c0.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c0.c2.c1.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c1.c0.c0.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };

        match self.c1.c0.c1.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c1.c1.c0.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c1.c1.c1.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c1.c2.c0.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        match self.c1.c2.c1.into_repr().write_be(&mut buf) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(p) => p,
        };
        writer.write_all(&buf)?;
        Ok(())
    }

    /// The compressed parameter has no effect since Fr element will always be compressed.
    fn deserialize<R: Read>(mut reader: &mut R, _compressed: Compressed) -> Result<Self> {
        let mut q = FqRepr::default();
        q.read_be(&mut reader)?;
        let c000 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c001 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c010 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c011 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c020 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c021 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c100 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c101 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c110 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c111 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c120 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        q.read_be(&mut reader)?;
        let c121 = match Fq::from_repr(q) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            Ok(q) => q,
        };
        Ok(Fq12 {
            c0: Fq6 {
                c0: Fq2 { c0: c000, c1: c001 },

                c1: Fq2 { c0: c010, c1: c011 },

                c2: Fq2 { c0: c020, c1: c021 },
            },
            c1: Fq6 {
                c0: Fq2 { c0: c100, c1: c101 },

                c1: Fq2 { c0: c110, c1: c111 },

                c2: Fq2 { c0: c120, c1: c121 },
            },
        })
    }
}

impl SerDes for G1 {
    /// Convert a G1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        let t = self.into_affine();

        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = G1Compressed::from_affine(t);
                tmp.as_ref().to_vec()
            } else {
                let tmp = G1Uncompressed::from_affine(t);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a G1 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G1Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        // first bit is 1 => compressed mode
        // first bit is 0 => uncompressed mode
        if ((buf[0] & 0x80) == 0x80) != compressed {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid compressness"));
        }

        if compressed {
            // convert the blob into a group element
            let mut g_buf = G1Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else {
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G1Uncompressed::size() - G1Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G1Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        }
    }
}

impl SerDes for G2 {
    /// Convert a G2 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        let t = self.into_affine();
        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = G2Compressed::from_affine(t);
                tmp.as_ref().to_vec()
            } else {
                let tmp = G2Uncompressed::from_affine(t);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a G2 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G2Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        // first bit is 1 => compressed mode
        // first bit is 0 => uncompressed mode
        if ((buf[0] & 0x80) == 0x80) != compressed {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid compressness"));
        }

        if compressed {
            // convert the buf into a group element
            let mut g_buf = G2Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else {
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G2Uncompressed::size() - G2Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G2Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        }
    }
}

impl SerDes for G1Affine {
    /// Convert a G1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = G1Compressed::from_affine(*self);
                tmp.as_ref().to_vec()
            } else {
                let tmp = G1Uncompressed::from_affine(*self);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a G1 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G1Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        // first bit is 1 => compressed mode
        // first bit is 0 => uncompressed mode
        if ((buf[0] & 0x80) == 0x80) != compressed {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid compressness"));
        }

        if compressed {
            // convert the blob into a group element
            let mut g_buf = G1Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p,
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else {
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G1Uncompressed::size() - G1Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G1Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p,
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        }
    }
}

impl SerDes for G2Affine {
    /// Convert a G2 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = G2Compressed::from_affine(*self);
                tmp.as_ref().to_vec()
            } else {
                let tmp = G2Uncompressed::from_affine(*self);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a G2 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R, compressed: Compressed) -> Result<Self> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G2Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        // first bit is 1 => compressed mode
        // first bit is 0 => uncompressed mode
        if ((buf[0] & 0x80) == 0x80) != compressed {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid compressness"));
        }

        if compressed {
            // convert the buf into a group element
            let mut g_buf = G2Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p,
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        } else {
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G2Uncompressed::size() - G2Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G2Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p,
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok(g)
        }
    }
}

#[cfg(test)]
mod serdes_test {
    use super::*;
    use rand_core::SeedableRng;
    #[test]
    fn test_g1_serialization_rand() {
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // G1::zero, compressed
        let g1_zero = G1::zero();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_zero.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48, "length of blob is incorrect");
        let g1_zero_recover = G1::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g1_zero, g1_zero_recover);

        // G1::one, compressed
        let g1_one = G1::one();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_one.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48, "length of blob is incorrect");
        let g1_one_recover = G1::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g1_one, g1_one_recover);

        // G1::rand, compressed
        let g1_rand = G1::random(&mut rng);
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_rand.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48, "length of blob is incorrect");
        let g1_rand_recover = G1::deserialize(&mut buf[..].as_ref(), true).unwrap();

        assert_eq!(g1_rand, g1_rand_recover);

        // G1::zero, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_zero.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g1_zero_recover = G1::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g1_zero, g1_zero_recover);

        // G1::one, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_one.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g1_one_recover = G1::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g1_one, g1_one_recover);

        // G1::rand, uncompressed
        let g1_rand = G1::random(&mut rng);
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_rand.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g1_rand_recover = G1::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g1_rand, g1_rand_recover);
    }

    #[test]
    fn test_g2_serialization_rand() {
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        // G2::zero, compressed
        let g2_zero = G2::zero();
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_zero.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g2_zero_recover = G2::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g2_zero, g2_zero_recover);

        // G2::one, compressed
        let g2_one = G2::one();
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_one.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g2_one_recover = G2::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g2_one, g2_one_recover);

        // G2::rand, compressed
        let g2_rand = G2::random(&mut rng);
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_rand.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g2_rand_recover = G2::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g2_rand, g2_rand_recover);

        // G2::zero, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_zero.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 192, "length of blob is incorrect");
        let g2_zero_recover = G2::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g2_zero, g2_zero_recover);

        // G2::one, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_one.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 192, "length of blob is incorrect");
        let g2_one_recover = G2::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g2_one, g2_one_recover);

        // G2::rand uncompressed
        let g2_rand = G2::random(&mut rng);
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_rand.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 192, "length of blob is incorrect");
        let g2_rand_recover = G2::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g2_rand, g2_rand_recover);
    }

    #[test]
    fn test_g1affine_serialization_rand() {
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // G1::zero, compressed
        let g1_zero = G1::zero().into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_zero.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48, "length of blob is incorrect");
        let g1_zero_recover = G1Affine::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g1_zero, g1_zero_recover);

        // G1::one, compressed
        let g1_one = G1::one().into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_one.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48, "length of blob is incorrect");
        let g1_one_recover = G1Affine::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g1_one, g1_one_recover);

        // G1::rand, compressed
        let g1_rand = G1::random(&mut rng).into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_rand.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48, "length of blob is incorrect");
        let g1_rand_recover = G1Affine::deserialize(&mut buf[..].as_ref(), true).unwrap();

        assert_eq!(g1_rand, g1_rand_recover);

        // G1::zero, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_zero.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g1_zero_recover = G1Affine::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g1_zero, g1_zero_recover);

        // G1::one, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_one.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g1_one_recover = G1Affine::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g1_one, g1_one_recover);

        // G1::rand, uncompressed
        let g1_rand = G1::random(&mut rng).into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(g1_rand.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g1_rand_recover = G1Affine::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g1_rand, g1_rand_recover);
    }

    #[test]
    fn test_g2affine_serialization_rand() {
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        // G2::zero, compressed
        let g2_zero = G2::zero().into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_zero.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g2_zero_recover = G2Affine::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g2_zero, g2_zero_recover);

        // G2::one, compressed
        let g2_one = G2::one().into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_one.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g2_one_recover = G2Affine::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g2_one, g2_one_recover);

        // G2::rand, compressed
        let g2_rand = G2::random(&mut rng).into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_rand.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 96, "length of blob is incorrect");
        let g2_rand_recover = G2Affine::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(g2_rand, g2_rand_recover);

        // G2::zero, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_zero.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 192, "length of blob is incorrect");
        let g2_zero_recover = G2Affine::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g2_zero, g2_zero_recover);

        // G2::one, uncompressed
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_one.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 192, "length of blob is incorrect");
        let g2_one_recover = G2Affine::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g2_one, g2_one_recover);

        // G2::rand uncompressed
        let g2_rand = G2::random(&mut rng).into_affine();
        let mut buf: Vec<u8> = vec![];
        // serialize a G2 element into buffer
        assert!(g2_rand.serialize(&mut buf, false).is_ok());
        assert_eq!(buf.len(), 192, "length of blob is incorrect");
        let g2_rand_recover = G2Affine::deserialize(&mut buf[..].as_ref(), false).unwrap();
        assert_eq!(g2_rand, g2_rand_recover);
    }

    #[test]
    fn test_fr_serialization_rand() {
        use ff::Field;
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        // fr::zero
        let fr_zero = Fr::zero();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(fr_zero.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 32, "length of blob is incorrect");
        let fr_zero_recover = Fr::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(fr_zero, fr_zero_recover);

        // fr::one
        let fr_one = Fr::one();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(fr_one.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 32, "length of blob is incorrect");
        let fr_one_recover = Fr::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(fr_one, fr_one_recover);

        // fr::rand
        let fr_rand = Fr::random(&mut rng);
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(fr_rand.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 32, "length of blob is incorrect");
        let fr_rand_recover = Fr::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(fr_rand, fr_rand_recover);
    }

    #[test]
    fn test_fq12_serialization_rand() {
        use ff::Field;
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        // fq12::zero
        let fq12_zero = Fq12::zero();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(fq12_zero.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48 * 12, "length of blob is incorrect");
        let fq12_zero_recover = Fq12::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(fq12_zero, fq12_zero_recover);

        // fq12::one
        let fq12_one = Fq12::one();
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(fq12_one.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48 * 12, "length of blob is incorrect");
        let fq12_one_recover = Fq12::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(fq12_one, fq12_one_recover);

        // fr::rand
        let fq12_rand = Fq12::random(&mut rng);
        let mut buf: Vec<u8> = vec![];
        // serialize a G1 element into buffer
        assert!(fq12_rand.serialize(&mut buf, true).is_ok());
        assert_eq!(buf.len(), 48 * 12, "length of blob is incorrect");
        let fq12_rand_recover = Fq12::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(fq12_rand, fq12_rand_recover);
    }
}
