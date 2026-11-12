use pyo3::prelude::*;
use zeroize::Zeroize;

/// A memory-hardened buffer for sensitive credentials (PINs/PUKs).
/// Locks allocated buffer pages in RAM via `mlock` to prevent swap leakage,
/// and securely zeroes out memory upon drop.
#[pyclass]
#[derive(Zeroize)]
pub struct PinBuffer {
    #[zeroize(skip)]
    len: usize,
    buffer: Vec<u8>,
}

impl Drop for PinBuffer {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            unsafe {
                libc::munlock(self.buffer.as_ptr() as *const libc::c_void, self.buffer.capacity());
            }
        }
        self.buffer.zeroize();
        self.len = 0;
    }
}

#[pymethods]
impl PinBuffer {
    #[new]
    pub fn new(pin: &str) -> Self {
        let bytes = pin.as_bytes().to_vec();
        let len = bytes.len();
        if !bytes.is_empty() {
            unsafe {
                libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.capacity());
            }
        }
        Self { len, buffer: bytes }
    }

    pub fn length(&self) -> usize {
        self.len
    }

    pub fn __len__(&self) -> usize {
        self.len
    }

    pub fn is_valid_pin_format(&self) -> bool {
        self.len >= 6 && self.len <= 8 && self.buffer.iter().all(|b| b.is_ascii_digit())
    }

    pub fn scrub(&mut self) {
        if !self.buffer.is_empty() {
            unsafe {
                libc::munlock(self.buffer.as_ptr() as *const libc::c_void, self.buffer.capacity());
            }
        }
        self.buffer.zeroize();
        self.len = 0;
    }

    fn __repr__(&self) -> String {
        "<PinBuffer [REDACTED: MEMORY PROTECTED]>".to_string()
    }
}
