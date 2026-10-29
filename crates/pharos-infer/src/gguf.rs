//! A checked, zero-copy GGUF (version 3) reader: metadata and the tensor
//! directory, with tensor data borrowed from the file.
//!
//! The file is untrusted input. Every count, length, and offset is checked
//! against limits and the file size before use, nested arrays are refused,
//! and only the tensor types this engine computes with (F32, Q8_0) yield
//! data.

use alloc::vec::Vec;

use crate::Error;
use crate::quant::{Q8_0_BYTES, QK8_0};

/// File magic: "GGUF".
pub const MAGIC: [u8; 4] = *b"GGUF";
pub const VERSION: u32 = 3;
/// Limits far above the M3.1 candidates (Qwen2.5-0.5B: 26 keys, 291
/// tensors, 151,936 tokens).
pub const MAX_KEYS: u64 = 1 << 12;
pub const MAX_TENSORS: u64 = 1 << 14;
pub const MAX_STRING: u64 = 1 << 20;
pub const MAX_ARRAY: u64 = 1 << 22;
const DEFAULT_ALIGNMENT: u64 = 32;

/// ggml tensor types this engine reads.
pub const TYPE_F32: u32 = 0;
pub const TYPE_Q8_0: u32 = 8;

/// A metadata value; arrays and strings borrow the file.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value<'a> {
    Int(i128),
    Float(f64),
    Bool(bool),
    Str(&'a [u8]),
    /// Element type, count, and the elements' bytes.
    Array(u32, u64, &'a [u8]),
}

/// One tensor's directory entry.
#[derive(Debug, Clone, Copy)]
pub struct TensorInfo<'a> {
    pub name: &'a [u8],
    /// `dims[0]` is the row length (ggml's `ne[0]`); unused dimensions are 1.
    pub dims: [u64; 4],
    pub ty: u32,
    offset: u64,
}

/// A parsed file.
pub struct Gguf<'a> {
    pub metadata: Vec<(&'a [u8], Value<'a>)>,
    pub tensors: Vec<TensorInfo<'a>>,
    data: &'a [u8],
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], Error> {
        let n = usize::try_from(n).map_err(|_| Error::Truncated)?;
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.bytes.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u64()?;
        if len > MAX_STRING {
            return Err(Error::BadFormat);
        }
        self.take(len)
    }

    /// A scalar of type `ty`, or `None` for strings and arrays.
    fn scalar(&mut self, ty: u32) -> Result<Option<Value<'a>>, Error> {
        let v = match ty {
            0 => Value::Int(i128::from(self.take(1)?[0])),
            1 => Value::Int(i128::from(self.take(1)?[0] as i8)),
            2 => {
                let b = self.take(2)?;
                Value::Int(i128::from(u16::from_le_bytes([b[0], b[1]])))
            }
            3 => {
                let b = self.take(2)?;
                Value::Int(i128::from(i16::from_le_bytes([b[0], b[1]])))
            }
            4 => Value::Int(i128::from(self.u32()?)),
            5 => Value::Int(i128::from(self.u32()? as i32)),
            6 => Value::Float(f64::from(f32::from_bits(self.u32()?))),
            7 => match self.take(1)?[0] {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                _ => return Err(Error::BadFormat),
            },
            10 => Value::Int(i128::from(self.u64()?)),
            11 => Value::Int(i128::from(self.u64()? as i64)),
            12 => Value::Float(f64::from_bits(self.u64()?)),
            8 | 9 => return Ok(None),
            _ => return Err(Error::BadFormat),
        };
        Ok(Some(v))
    }

    fn value(&mut self, ty: u32) -> Result<Value<'a>, Error> {
        if let Some(v) = self.scalar(ty)? {
            return Ok(v);
        }
        if ty == 8 {
            return Ok(Value::Str(self.string()?));
        }
        let elem = self.u32()?;
        if elem == 9 {
            return Err(Error::BadFormat); // nested arrays
        }
        let count = self.u64()?;
        if count > MAX_ARRAY {
            return Err(Error::BadFormat);
        }
        let start = self.pos;
        for _ in 0..count {
            if elem == 8 {
                self.string()?;
            } else {
                self.scalar(elem)?;
            }
        }
        Ok(Value::Array(elem, count, &self.bytes[start..self.pos]))
    }
}

/// Bytes a tensor of `ty` with `n` elements occupies, if this engine reads
/// that type.
fn tensor_bytes(ty: u32, n: u64) -> Option<u64> {
    match ty {
        TYPE_F32 => n.checked_mul(4),
        TYPE_Q8_0 if n % QK8_0 as u64 == 0 => (n / QK8_0 as u64).checked_mul(Q8_0_BYTES as u64),
        _ => None,
    }
}

impl<'a> Gguf<'a> {
    /// Parses the header, metadata, and tensor directory, and checks that
    /// every tensor of a supported type lies inside the file.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader { bytes, pos: 0 };
        if r.take(4)? != MAGIC {
            return Err(Error::BadFormat);
        }
        if r.u32()? != VERSION {
            return Err(Error::BadFormat);
        }
        let n_tensors = r.u64()?;
        let n_keys = r.u64()?;
        if n_tensors > MAX_TENSORS || n_keys > MAX_KEYS {
            return Err(Error::BadFormat);
        }
        let mut metadata = Vec::new();
        for _ in 0..n_keys {
            let key = r.string()?;
            let ty = r.u32()?;
            metadata.push((key, r.value(ty)?));
        }
        let mut tensors = Vec::new();
        for _ in 0..n_tensors {
            let name = r.string()?;
            let n_dims = r.u32()?;
            if !(1..=4).contains(&n_dims) {
                return Err(Error::BadFormat);
            }
            let mut dims = [1u64; 4];
            for d in dims.iter_mut().take(n_dims as usize) {
                *d = r.u64()?;
                if *d == 0 {
                    return Err(Error::BadFormat);
                }
            }
            let ty = r.u32()?;
            let offset = r.u64()?;
            tensors.push(TensorInfo {
                name,
                dims,
                ty,
                offset,
            });
        }
        let mut gguf = Self {
            metadata,
            tensors,
            data: &[],
        };
        let alignment = match gguf.get(b"general.alignment") {
            None => DEFAULT_ALIGNMENT,
            Some(Value::Int(a)) if a > 0 && a <= 1 << 16 && (a & (a - 1)) == 0 => a as u64,
            Some(_) => return Err(Error::BadFormat),
        };
        let start = (r.pos as u64).div_ceil(alignment) * alignment;
        let start = usize::try_from(start).map_err(|_| Error::Truncated)?;
        gguf.data = bytes.get(start..).ok_or(Error::Truncated)?;
        for t in &gguf.tensors {
            if t.offset % alignment != 0 {
                return Err(Error::BadFormat);
            }
            let n = t
                .dims
                .iter()
                .try_fold(1u64, |a, d| a.checked_mul(*d))
                .ok_or(Error::BadFormat)?;
            if let Some(size) = tensor_bytes(t.ty, n) {
                let end = t.offset.checked_add(size).ok_or(Error::BadFormat)?;
                if end > gguf.data.len() as u64 {
                    return Err(Error::Truncated);
                }
            }
        }
        Ok(gguf)
    }

    /// The value of metadata key `key`.
    pub fn get(&self, key: &[u8]) -> Option<Value<'a>> {
        self.metadata
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }

    /// An unsigned integer value.
    pub fn uint(&self, key: &[u8]) -> Result<u64, Error> {
        match self.get(key) {
            Some(Value::Int(v)) => u64::try_from(v).map_err(|_| Error::BadConfig),
            _ => Err(Error::BadConfig),
        }
    }

    /// A floating-point value.
    pub fn float(&self, key: &[u8]) -> Result<f64, Error> {
        match self.get(key) {
            Some(Value::Float(v)) => Ok(v),
            _ => Err(Error::BadConfig),
        }
    }

    /// The elements of a string array.
    pub fn strings(&self, key: &[u8]) -> Result<Vec<&'a [u8]>, Error> {
        let Some(Value::Array(8, count, bytes)) = self.get(key) else {
            return Err(Error::BadConfig);
        };
        let mut r = Reader { bytes, pos: 0 };
        (0..count).map(|_| r.string()).collect()
    }

    /// The elements of an integer array.
    pub fn ints(&self, key: &[u8]) -> Result<Vec<i128>, Error> {
        let Some(Value::Array(ty, count, bytes)) = self.get(key) else {
            return Err(Error::BadConfig);
        };
        let mut r = Reader { bytes, pos: 0 };
        (0..count)
            .map(|_| match r.scalar(ty)? {
                Some(Value::Int(v)) => Ok(v),
                _ => Err(Error::BadConfig),
            })
            .collect()
    }

    /// Tensor `name` with its data, if it exists, has `dims` (unlisted
    /// trailing dimensions 1), and has a type this engine reads.
    pub fn tensor(&self, name: &[u8], dims: &[u64]) -> Result<Tensor<'a>, Error> {
        let t = self
            .tensors
            .iter()
            .find(|t| t.name == name)
            .ok_or(Error::MissingTensor)?;
        let mut want = [1u64; 4];
        want[..dims.len()].copy_from_slice(dims);
        if t.dims != want {
            return Err(Error::BadConfig);
        }
        let n = t.dims.iter().product::<u64>();
        let size = tensor_bytes(t.ty, n).ok_or(Error::UnsupportedType)?;
        let start = t.offset as usize;
        Ok(Tensor {
            ty: t.ty,
            cols: t.dims[0] as usize,
            rows: (n / t.dims[0]) as usize,
            data: &self.data[start..start + size as usize],
        })
    }

    /// Whether tensor `name` exists.
    pub fn has(&self, name: &[u8]) -> bool {
        self.tensors.iter().any(|t| t.name == name)
    }
}

/// A 2-D (or 1-D, one row) tensor's data, borrowed from the file.
#[derive(Debug, Clone, Copy)]
pub struct Tensor<'a> {
    pub ty: u32,
    /// Row length (ggml `ne[0]`).
    pub cols: usize,
    pub rows: usize,
    pub data: &'a [u8],
}

impl Tensor<'_> {
    /// Bytes per row.
    pub fn row_bytes(&self) -> usize {
        match self.ty {
            TYPE_Q8_0 => self.cols / QK8_0 * Q8_0_BYTES,
            _ => self.cols * 4,
        }
    }

    /// Row `i`'s bytes.
    pub fn row(&self, i: usize) -> &[u8] {
        let n = self.row_bytes();
        &self.data[i * n..(i + 1) * n]
    }

    /// An F32 tensor's values.
    pub fn f32s(&self) -> Result<Vec<f32>, Error> {
        if self.ty != TYPE_F32 {
            return Err(Error::UnsupportedType);
        }
        Ok(self
            .data
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect())
    }
}
