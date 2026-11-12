use libloading::{Library, Symbol};
use pyo3::prelude::*;
use regex::Regex;
use std::ffi::{c_char, c_void, CString};

pub const SCARD_SCOPE_SYSTEM: usize = 2;
pub const SCARD_SCOPE_USER: usize = 0;
pub const SCARD_SHARE_SHARED: usize = 2;
pub const SCARD_PROTOCOL_T0: usize = 1;
pub const SCARD_PROTOCOL_T1: usize = 2;
pub const SCARD_LEAVE_CARD: usize = 0;
pub const SCARD_S_SUCCESS: i64 = 0;
pub const SCARD_STATE_UNAWARE: usize = 0x0000;
pub const SCARD_STATE_PRESENT: usize = 0x0020;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SCARD_IO_REQUEST {
    pub dw_protocol: usize,
    pub cb_pci_length: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SCARD_READERSTATE {
    pub sz_reader: *const c_char,
    pub pv_user_data: *mut c_void,
    pub dw_current_state: usize,
    pub dw_event_state: usize,
    pub cb_atr: usize,
    pub rgb_atr: [u8; 33],
}

type SCardEstablishContextFn = unsafe extern "C" fn(
    scope: usize,
    r1: *const c_void,
    r2: *const c_void,
    ph_context: *mut i64,
) -> i64;

type SCardReleaseContextFn = unsafe extern "C" fn(h_context: i64) -> i64;

type SCardListReadersFn = unsafe extern "C" fn(
    h_context: i64,
    msz_groups: *const c_char,
    msz_readers: *mut c_char,
    pcch_readers: *mut usize,
) -> i64;

type SCardGetStatusChangeFn = unsafe extern "C" fn(
    h_context: i64,
    dw_timeout: usize,
    rg_reader_states: *mut SCARD_READERSTATE,
    c_readers: usize,
) -> i64;

type SCardConnectFn = unsafe extern "C" fn(
    h_context: i64,
    sz_reader: *const c_char,
    dw_share_mode: usize,
    dw_preferred_protocols: usize,
    ph_card: *mut i64,
    pdw_active_protocol: *mut usize,
) -> i64;

type SCardDisconnectFn = unsafe extern "C" fn(h_card: i64, dw_disposition: usize) -> i64;

type SCardBeginTransactionFn = unsafe extern "C" fn(h_card: i64) -> i64;

type SCardEndTransactionFn = unsafe extern "C" fn(h_card: i64, dw_disposition: usize) -> i64;

type SCardTransmitFn = unsafe extern "C" fn(
    h_card: i64,
    pio_send_pci: *const SCARD_IO_REQUEST,
    pb_send_buffer: *const u8,
    cb_send_length: usize,
    pio_recv_pci: *mut SCARD_IO_REQUEST,
    pb_recv_buffer: *mut u8,
    pcb_recv_length: *mut usize,
) -> i64;

struct PcscSymbols {
    _lib: Library,
    establish_context: SCardEstablishContextFn,
    release_context: SCardReleaseContextFn,
    list_readers: SCardListReadersFn,
    get_status_change: SCardGetStatusChangeFn,
    connect: Option<SCardConnectFn>,
    disconnect: Option<SCardDisconnectFn>,
    begin_transaction: Option<SCardBeginTransactionFn>,
    end_transaction: Option<SCardEndTransactionFn>,
    transmit: Option<SCardTransmitFn>,
}

impl PcscSymbols {
    fn try_load() -> Option<Self> {
        let candidates = [
            "libpcsclite.so.1",
            "libpcsclite.so",
            "/lib64/libpcsclite.so.1",
            "/usr/lib64/libpcsclite.so.1",
            "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1",
            "/usr/lib/libpcsclite.so.1",
        ];

        for path in &candidates {
            if let Ok(lib) = unsafe { Library::new(path) } {
                unsafe {
                    let establish: Result<Symbol<SCardEstablishContextFn>, _> =
                        lib.get(b"SCardEstablishContext");
                    let release: Result<Symbol<SCardReleaseContextFn>, _> =
                        lib.get(b"SCardReleaseContext");
                    let list: Result<Symbol<SCardListReadersFn>, _> =
                        lib.get(b"SCardListReaders");
                    let status: Result<Symbol<SCardGetStatusChangeFn>, _> =
                        lib.get(b"SCardGetStatusChange");

                    if let (Ok(e), Ok(r), Ok(l), Ok(s)) = (establish, release, list, status) {
                        let connect = lib.get(b"SCardConnect").ok().map(|sym: Symbol<SCardConnectFn>| *sym);
                        let disconnect = lib.get(b"SCardDisconnect").ok().map(|sym: Symbol<SCardDisconnectFn>| *sym);
                        let begin_transaction = lib
                            .get(b"SCardBeginTransaction")
                            .ok()
                            .map(|sym: Symbol<SCardBeginTransactionFn>| *sym);
                        let end_transaction = lib
                            .get(b"SCardEndTransaction")
                            .ok()
                            .map(|sym: Symbol<SCardEndTransactionFn>| *sym);
                        let transmit = lib.get(b"SCardTransmit").ok().map(|sym: Symbol<SCardTransmitFn>| *sym);

                        return Some(PcscSymbols {
                            establish_context: *e,
                            release_context: *r,
                            list_readers: *l,
                            get_status_change: *s,
                            connect,
                            disconnect,
                            begin_transaction,
                            end_transaction,
                            transmit,
                            _lib: lib,
                        });
                    }
                }
            }
        }
        None
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyNativePcscStatus {
    #[pyo3(get)]
    pub available: bool,
    #[pyo3(get)]
    pub service_running: bool,
    #[pyo3(get)]
    pub readers: Vec<String>,
    #[pyo3(get)]
    pub card_present: bool,
    #[pyo3(get)]
    pub primary_reader: Option<String>,
    #[pyo3(get)]
    pub atr: Option<String>,
    #[pyo3(get)]
    pub is_cac: bool,
}

#[pymethods]
impl PyNativePcscStatus {
    fn __repr__(&self) -> String {
        format!(
            "<NativePcscStatus available={} service={} readers={} card_present={}>",
            self.available,
            self.service_running,
            self.readers.len(),
            self.card_present
        )
    }
}

#[pyclass]
#[derive(Clone, Debug, Default)]
pub struct PyPivCardMetadata {
    #[pyo3(get)]
    pub card_name: Option<String>,
    #[pyo3(get)]
    pub token_label: Option<String>,
    #[pyo3(get)]
    pub token_serial: Option<String>,
}

#[pymethods]
impl PyPivCardMetadata {
    #[new]
    fn new(card_name: Option<String>, token_label: Option<String>, token_serial: Option<String>) -> Self {
        Self { card_name, token_label, token_serial }
    }

    fn __repr__(&self) -> String {
        format!(
            "<PivCardMetadata card_name={:?} token_label={:?} token_serial={:?}>",
            self.card_name, self.token_label, self.token_serial
        )
    }
}

/// Query hardware status directly via PC/SC Lite C API without subprocesses.
pub fn query_native_pcsc_status() -> PyNativePcscStatus {
    let symbols = match PcscSymbols::try_load() {
        Some(s) => s,
        None => {
            return PyNativePcscStatus {
                available: false,
                service_running: false,
                readers: Vec::new(),
                card_present: false,
                primary_reader: None,
                atr: None,
                is_cac: false,
            };
        }
    };

    let mut context: i64 = 0;
    // Attempt system scope first, then user scope
    let rc = unsafe {
        (symbols.establish_context)(
            SCARD_SCOPE_SYSTEM,
            std::ptr::null(),
            std::ptr::null(),
            &mut context,
        )
    };

    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut context,
            )
        };
        if rc_user != SCARD_S_SUCCESS {
            return PyNativePcscStatus {
                available: true,
                service_running: false,
                readers: Vec::new(),
                card_present: false,
                primary_reader: None,
                atr: None,
                is_cac: false,
            };
        }
        context
    };

    // Context established -> pcscd is running
    let mut cch: usize = 0;
    let list_rc = unsafe {
        (symbols.list_readers)(
            context,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut cch,
        )
    };

    let mut readers = Vec::new();
    if list_rc == SCARD_S_SUCCESS && cch > 0 {
        let mut buf = vec![0u8; cch];
        let list_rc2 = unsafe {
            (symbols.list_readers)(
                context,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut c_char,
                &mut cch,
            )
        };

        if list_rc2 == SCARD_S_SUCCESS {
            // Buffer contains null-separated strings ending with \0\0
            let mut start = 0;
            for i in 0..buf.len() {
                if buf[i] == 0 {
                    if i > start {
                        if let Ok(s) = std::str::from_utf8(&buf[start..i]) {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                readers.push(trimmed.to_string());
                            }
                        }
                    }
                    start = i + 1;
                }
            }
        }
    }

    let mut card_present = false;
    let mut primary_reader = None;
    let mut found_atr = None;
    let mut is_cac = false;

    for r_name in &readers {
        if let Ok(c_name) = CString::new(r_name.as_str()) {
            let mut state = SCARD_READERSTATE {
                sz_reader: c_name.as_ptr(),
                pv_user_data: std::ptr::null_mut(),
                dw_current_state: SCARD_STATE_UNAWARE,
                dw_event_state: 0,
                cb_atr: 0,
                rgb_atr: [0u8; 33],
            };

            let st_rc = unsafe {
                (symbols.get_status_change)(context, 0, &mut state, 1)
            };

            if st_rc == SCARD_S_SUCCESS && (state.dw_event_state & SCARD_STATE_PRESENT) != 0 {
                card_present = true;
                primary_reader = Some(r_name.clone());
                if state.cb_atr > 0 && state.cb_atr <= 33 {
                    let atr_bytes = &state.rgb_atr[..state.cb_atr as usize];
                    let atr_hex = atr_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                    is_cac = is_cac_or_piv_atr(&atr_hex);
                    found_atr = Some(atr_hex);
                }
                break;
            }
        }
    }

    if primary_reader.is_none() && !readers.is_empty() {
        primary_reader = Some(readers[0].clone());
    }

    unsafe {
        (symbols.release_context)(context);
    }

    PyNativePcscStatus {
        available: true,
        service_running: true,
        readers,
        card_present,
        primary_reader,
        atr: found_atr,
        is_cac,
    }
}

/// Checks if an ATR matches known DoD CAC or PIV smart card profiles.
pub fn is_cac_or_piv_atr(raw_atr: &str) -> bool {
    let clean = raw_atr.replace([':', ' ', '-'], "").to_lowercase();
    // Known historical and modern CAC / PIV ATR prefixes
    clean.starts_with("3b7d96")
        || clean.starts_with("3bdb96")
        || clean.starts_with("3b7b94")
        || clean.starts_with("3b7d94")
        || clean.starts_with("3bf818")
        || clean.starts_with("3bfa18")
}

/// Parses the output of `pkcs15-tool -c` into (id, label) tuples.
pub fn parse_pkcs15_tool_list(output: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current_id = None;
    let mut current_label = None;

    let re_id = Regex::new(r"^\s*ID\s*:\s*([a-fA-F0-9]+)").unwrap();
    let re_label = Regex::new(r"^\s*Label\s*:\s*(.+)").unwrap();

    for line in output.lines() {
        if let Some(caps) = re_id.captures(line) {
            current_id = Some(caps[1].trim().to_string());
        } else if let Some(caps) = re_label.captures(line) {
            current_label = Some(caps[1].trim().to_string());
        }

        if let (Some(id), Some(label)) = (current_id.as_ref(), current_label.as_ref()) {
            pairs.push((id.clone(), label.clone()));
            current_id = None;
            current_label = None;
        }
    }

    pairs
}

/// Extracts the raw X.509 DER certificate bytes from a NIST SP 800-73-4 PIV container.
///
/// Supports:
/// 1. PIV compressed certificates (Tag 0x71, GZIP decompression)
/// 2. PIV uncompressed certificates (Tag 0x70 / 0x53 BER-TLV wrapper)
/// 3. Raw ASN.1 sequence headers (0x30 0x82, 0x30 0x81, 0x30 0x83)
pub fn extract_cert_from_piv_container(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }

    // 1. Check for GZIP compression anywhere in payload (PIV Tag 0x71 compressed format)
    for i in 0..payload.len().saturating_sub(2) {
        if payload[i] == 0x1F && payload[i + 1] == 0x8B {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(&payload[i..]);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok()
                && !decompressed.is_empty()
                && decompressed[0] == 0x30
                && x509_parser::parse_x509_certificate(&decompressed).is_ok()
            {
                return Some(decompressed);
            }
        }
    }

    // 2. Scan for ASN.1 DER SEQUENCE (0x30 0x82 / 0x30 0x81 / 0x30 0x83)
    let len = payload.len();
    for i in 0..len.saturating_sub(4) {
        if payload[i] == 0x30 {
            let cert_len = if payload[i + 1] == 0x82 && i + 4 <= len {
                let hi = payload[i + 2] as usize;
                let lo = payload[i + 3] as usize;
                4 + (hi << 8 | lo)
            } else if payload[i + 1] == 0x81 && i + 3 <= len {
                3 + (payload[i + 2] as usize)
            } else if payload[i + 1] == 0x83 && i + 5 <= len {
                let b1 = payload[i + 2] as usize;
                let b2 = payload[i + 3] as usize;
                let b3 = payload[i + 4] as usize;
                5 + (b1 << 16 | b2 << 8 | b3)
            } else {
                continue;
            };

            if cert_len >= 64 && i + cert_len <= len {
                let candidate = &payload[i..i + cert_len];
                if x509_parser::parse_x509_certificate(candidate).is_ok() {
                    return Some(candidate.to_vec());
                }
            }
        }
    }

    None
}

fn transmit_apdu(
    transmit_fn: SCardTransmitFn,
    h_card: i64,
    active_proto: usize,
    apdu: &[u8],
) -> Result<Vec<u8>, i64> {
    let pci = SCARD_IO_REQUEST {
        dw_protocol: active_proto,
        cb_pci_length: std::mem::size_of::<SCARD_IO_REQUEST>(),
    };
    let mut recv_buf = vec![0u8; 4096];
    let mut recv_len: usize = recv_buf.len();

    let rc = unsafe {
        transmit_fn(
            h_card,
            &pci,
            apdu.as_ptr(),
            apdu.len(),
            std::ptr::null_mut(),
            recv_buf.as_mut_ptr(),
            &mut recv_len,
        )
    };

    if rc != SCARD_S_SUCCESS {
        return Err(rc);
    }
    recv_buf.truncate(recv_len);
    Ok(recv_buf)
}

fn read_piv_container_data(
    transmit_fn: SCardTransmitFn,
    h_card: i64,
    active_proto: usize,
    tag: [u8; 3],
) -> Option<Vec<u8>> {
    // GET DATA APDU: 00 CB 3F FF 05 5C 03 [tag0] [tag1] [tag2] 00
    let get_data_apdu = [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, tag[0], tag[1], tag[2], 0x00];
    let mut resp = match transmit_apdu(transmit_fn, h_card, active_proto, &get_data_apdu) {
        Ok(r) => r,
        Err(_) => return None,
    };

    if resp.len() < 2 {
        return None;
    }

    let mut sw1 = resp[resp.len() - 2];
    let mut sw2 = resp[resp.len() - 1];

    // If 0x6C XX: wrong Le, retry with exact Le = sw2
    if sw1 == 0x6C {
        let retry_apdu = [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, tag[0], tag[1], tag[2], sw2];
        resp = match transmit_apdu(transmit_fn, h_card, active_proto, &retry_apdu) {
            Ok(r) => r,
            Err(_) => return None,
        };
        if resp.len() < 2 {
            return None;
        }
        sw1 = resp[resp.len() - 2];
        sw2 = resp[resp.len() - 1];
    }

    if sw1 != 0x90 && sw1 != 0x61 {
        return None;
    }

    let mut container_bytes = Vec::new();
    container_bytes.extend_from_slice(&resp[..resp.len() - 2]);

    // Handle 0x61 XX pagination with GET RESPONSE
    let mut iterations = 0;
    while sw1 == 0x61 && iterations < 100 {
        iterations += 1;
        let get_response_apdu = [0x00, 0xC0, 0x00, 0x00, sw2];
        let chunk = match transmit_apdu(transmit_fn, h_card, active_proto, &get_response_apdu) {
            Ok(c) => c,
            Err(_) => break,
        };
        if chunk.len() < 2 {
            break;
        }
        sw1 = chunk[chunk.len() - 2];
        sw2 = chunk[chunk.len() - 1];
        container_bytes.extend_from_slice(&chunk[..chunk.len() - 2]);
        if sw1 == 0x90 && sw2 == 0x00 {
            break;
        }
    }

    if container_bytes.is_empty() {
        None
    } else {
        Some(container_bytes)
    }
}

/// Parse Cardholder Unique Identifier (CHUID Tag 0x5FC102) payload.
/// Extracts (serial_or_guid, expiration_date).
pub fn parse_chuid_metadata(payload: &[u8]) -> (Option<String>, Option<String>) {
    if payload.is_empty() {
        return (None, None);
    }

    let mut guid_opt = None;
    let mut fascn_opt = None;
    let mut exp_opt = None;

    let mut idx = 0;
    // Skip outer 0x53 wrapper if present
    if payload.len() > 2 && payload[0] == 0x53 {
        if payload[1] < 0x80 {
            idx = 2;
        } else if payload[1] == 0x81 && payload.len() > 3 {
            idx = 3;
        } else if payload[1] == 0x82 && payload.len() > 4 {
            idx = 4;
        }
    }

    while idx < payload.len() {
        let tag = payload[idx];
        idx += 1;
        if tag == 0x00 || tag == 0xFF {
            continue;
        }
        if idx >= payload.len() {
            break;
        }
        let len = if payload[idx] < 0x80 {
            let l = payload[idx] as usize;
            idx += 1;
            l
        } else if payload[idx] == 0x81 && idx + 1 < payload.len() {
            let l = payload[idx + 1] as usize;
            idx += 2;
            l
        } else if payload[idx] == 0x82 && idx + 2 < payload.len() {
            let l = ((payload[idx + 1] as usize) << 8) | (payload[idx + 2] as usize);
            idx += 3;
            l
        } else {
            break;
        };

        if idx + len > payload.len() {
            break;
        }

        let val = &payload[idx..idx + len];
        idx += len;

        if tag == 0xEE && len == 16 {
            // RFC 4122 formatted 128-bit UUID/GUID
            guid_opt = Some(format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]
            ));
        } else if tag == 0x30 && len >= 10 {
            let hex_str: String = val.iter().map(|b| format!("{:02X}", b)).collect();
            fascn_opt = Some(hex_str);
        } else if tag == 0x35 && len == 8 {
            if let Ok(s) = std::str::from_utf8(val) {
                exp_opt = Some(s.to_string());
            }
        }
    }

    let serial = guid_opt.or(fascn_opt);
    (serial, exp_opt)
}

/// Parse Card Capability Container (CCC Tag 0x5FC107) payload.
/// Extracts the Card Identifier (Tag 0xF0) if present.
pub fn parse_ccc_metadata(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }
    let mut idx = 0;
    if payload.len() > 2 && payload[0] == 0x53 {
        if payload[1] < 0x80 {
            idx = 2;
        } else if payload[1] == 0x81 && payload.len() > 3 {
            idx = 3;
        } else if payload[1] == 0x82 && payload.len() > 4 {
            idx = 4;
        }
    }
    while idx < payload.len() {
        let tag = payload[idx];
        idx += 1;
        if tag == 0x00 || tag == 0xFF {
            continue;
        }
        if idx >= payload.len() {
            break;
        }
        let len = if payload[idx] < 0x80 {
            let l = payload[idx] as usize;
            idx += 1;
            l
        } else if payload[idx] == 0x81 && idx + 1 < payload.len() {
            let l = payload[idx + 1] as usize;
            idx += 2;
            l
        } else if payload[idx] == 0x82 && idx + 2 < payload.len() {
            let l = ((payload[idx + 1] as usize) << 8) | (payload[idx + 2] as usize);
            idx += 3;
            l
        } else {
            break;
        };

        if idx + len > payload.len() {
            break;
        }

        let val = &payload[idx..idx + len];
        idx += len;

        if tag == 0xF0 && !val.is_empty() {
            return Some(val.iter().map(|b| format!("{:02X}", b)).collect());
        }
    }
    None
}

/// Reads smart card metadata (CHUID / CCC) directly via NIST SP 800-73-4 APDU containers.
pub fn read_piv_card_metadata_native(reader_opt: Option<&str>) -> PyPivCardMetadata {
    let symbols = match PcscSymbols::try_load() {
        Some(s) => s,
        None => return PyPivCardMetadata::default(),
    };

    let (connect_fn, disconnect_fn, transmit_fn) = match (symbols.connect, symbols.disconnect, symbols.transmit) {
        (Some(c), Some(d), Some(t)) => (c, d, t),
        _ => return PyPivCardMetadata::default(),
    };

    let mut context: i64 = 0;
    let rc = unsafe {
        (symbols.establish_context)(
            SCARD_SCOPE_SYSTEM,
            std::ptr::null(),
            std::ptr::null(),
            &mut context,
        )
    };

    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut context,
            )
        };
        if rc_user != SCARD_S_SUCCESS {
            return PyPivCardMetadata::default();
        }
        context
    };

    let target_reader = match resolve_target_reader(&symbols, context, reader_opt) {
        Some(r) => r,
        None => {
            unsafe { (symbols.release_context)(context); }
            return PyPivCardMetadata::default();
        }
    };

    let c_reader = match CString::new(target_reader.as_str()) {
        Ok(c) => c,
        Err(_) => {
            unsafe { (symbols.release_context)(context); }
            return PyPivCardMetadata::default();
        }
    };

    let mut h_card: i64 = 0;
    let mut active_proto: usize = 0;
    let conn_rc = unsafe {
        connect_fn(
            context,
            c_reader.as_ptr(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &mut h_card,
            &mut active_proto,
        )
    };

    if conn_rc != SCARD_S_SUCCESS {
        unsafe { (symbols.release_context)(context); }
        return PyPivCardMetadata::default();
    }

    let in_tx = if let Some(begin_fn) = symbols.begin_transaction {
        unsafe { begin_fn(h_card) == SCARD_S_SUCCESS }
    } else {
        false
    };

    if !select_piv_applet(transmit_fn, h_card, active_proto) {
        unsafe {
            if in_tx {
                if let Some(end_fn) = symbols.end_transaction {
                    let _ = end_fn(h_card, SCARD_LEAVE_CARD);
                }
            }
            disconnect_fn(h_card, SCARD_LEAVE_CARD);
            (symbols.release_context)(context);
        }
        return PyPivCardMetadata::default();
    }

    let (serial, _exp) = if let Some(chuid_data) = read_piv_container_data(transmit_fn, h_card, active_proto, [0x5F, 0xC1, 0x02]) {
        parse_chuid_metadata(&chuid_data)
    } else {
        (None, None)
    };

    let ccc_id = if let Some(ccc_data) = read_piv_container_data(transmit_fn, h_card, active_proto, [0x5F, 0xC1, 0x07]) {
        parse_ccc_metadata(&ccc_data)
    } else {
        None
    };

    unsafe {
        if in_tx {
            if let Some(end_fn) = symbols.end_transaction {
                let _ = end_fn(h_card, SCARD_LEAVE_CARD);
            }
        }
        disconnect_fn(h_card, SCARD_LEAVE_CARD);
        (symbols.release_context)(context);
    }

    let is_piv = serial.is_some() || ccc_id.is_some();
    if is_piv {
        PyPivCardMetadata {
            card_name: Some("DoD Common Access Card (CAC / PIV)".to_string()),
            token_label: Some("DoD Common Access Card".to_string()),
            token_serial: serial,
        }
    } else {
        PyPivCardMetadata::default()
    }
}

/// Discovers and reads digital certificates from a physical smart card via direct in-process
/// NIST SP 800-73-4 PIV APDUs, eliminating external pkcs15-tool or opensc subprocess dependencies.
pub fn read_piv_certificates_native(reader_opt: Option<&str>) -> Vec<crate::cert::PyCardCertificate> {
    let mut results = Vec::new();
    let symbols = match PcscSymbols::try_load() {
        Some(s) => s,
        None => return results,
    };

    let (connect_fn, disconnect_fn, transmit_fn) = match (symbols.connect, symbols.disconnect, symbols.transmit) {
        (Some(c), Some(d), Some(t)) => (c, d, t),
        _ => return results,
    };

    let mut context: i64 = 0;
    let rc = unsafe {
        (symbols.establish_context)(
            SCARD_SCOPE_SYSTEM,
            std::ptr::null(),
            std::ptr::null(),
            &mut context,
        )
    };

    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut context,
            )
        };
        if rc_user != SCARD_S_SUCCESS {
            return results;
        }
        context
    };

    // Determine target reader
    let target_reader = match resolve_target_reader(&symbols, context, reader_opt) {
        Some(r) => r,
        None => {
            unsafe { (symbols.release_context)(context); }
            return results;
        }
    };

    let c_reader = match CString::new(target_reader.as_str()) {
        Ok(c) => c,
        Err(_) => {
            unsafe { (symbols.release_context)(context); }
            return results;
        }
    };

    let mut h_card: i64 = 0;
    let mut active_proto: usize = 0;
    let conn_rc = unsafe {
        connect_fn(
            context,
            c_reader.as_ptr(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &mut h_card,
            &mut active_proto,
        )
    };

    if conn_rc != SCARD_S_SUCCESS {
        unsafe { (symbols.release_context)(context); }
        return results;
    }

    let in_tx = if let Some(begin_fn) = symbols.begin_transaction {
        unsafe { begin_fn(h_card) == SCARD_S_SUCCESS }
    } else {
        false
    };

    if !select_piv_applet(transmit_fn, h_card, active_proto) {
        unsafe {
            if in_tx {
                if let Some(end_fn) = symbols.end_transaction {
                    let _ = end_fn(h_card, SCARD_LEAVE_CARD);
                }
            }
            disconnect_fn(h_card, SCARD_LEAVE_CARD);
            (symbols.release_context)(context);
        }
        return results;
    }

    // PIV AID selected: Query standard NIST SP 800-73-4 certificate containers
    let targets = [
        ([0x5F, 0xC1, 0x05], "0005", "CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        ([0x5F, 0xC1, 0x0A], "0002", "CAC Email Signature", "S/MIME Digital Email Signing"),
        ([0x5F, 0xC1, 0x0B], "0003", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
        ([0x5F, 0xC1, 0x01], "0004", "CAC Device Authentication", "Device / Card Authentication"),
        // Legacy CAC transition containers fallback
        ([0x5F, 0xC1, 0x02], "0002", "CAC Email Signature", "S/MIME Digital Email Signing"),
        ([0x5F, 0xC1, 0x03], "0003", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
    ];

    for (tag, id, label, usage) in targets {
        if results.iter().any(|c: &crate::cert::PyCardCertificate| c.id == id) {
            continue;
        }
        if let Some(container_data) = read_piv_container_data(transmit_fn, h_card, active_proto, tag) {
            if let Some(der_bytes) = extract_cert_from_piv_container(&container_data) {
                if let Ok(py_cert) = crate::cert::parse_der_or_pem_bytes(
                    id.to_string(),
                    label.to_string(),
                    usage.to_string(),
                    &der_bytes,
                ) {
                    if !results.iter().any(|c: &crate::cert::PyCardCertificate| c.serial == py_cert.serial && !c.serial.is_empty()) {
                        results.push(py_cert);
                    }
                }
            }
        }
    }

    unsafe {
        if in_tx {
            if let Some(end_fn) = symbols.end_transaction {
                let _ = end_fn(h_card, SCARD_LEAVE_CARD);
            }
        }
        disconnect_fn(h_card, SCARD_LEAVE_CARD);
        (symbols.release_context)(context);
    }

    results
}

fn select_piv_applet(transmit_fn: SCardTransmitFn, h_card: i64, active_proto: usize) -> bool {
    let piv_aid_9 = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];
    let piv_aid_11 = [0x00, 0xA4, 0x04, 0x00, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];

    if let Ok(resp) = transmit_apdu(transmit_fn, h_card, active_proto, &piv_aid_9) {
        if resp.len() >= 2 && (resp[resp.len() - 2] == 0x90 || resp[resp.len() - 2] == 0x61) {
            return true;
        }
    }

    if let Ok(resp) = transmit_apdu(transmit_fn, h_card, active_proto, &piv_aid_11) {
        if resp.len() >= 2 && (resp[resp.len() - 2] == 0x90 || resp[resp.len() - 2] == 0x61) {
            return true;
        }
    }

    false
}

fn get_reader_list(symbols: &PcscSymbols, context: i64) -> Vec<String> {
    let mut cch: usize = 0;
    let list_rc = unsafe {
        (symbols.list_readers)(context, std::ptr::null(), std::ptr::null_mut(), &mut cch)
    };
    if list_rc != SCARD_S_SUCCESS || cch == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; cch];
    let list_rc2 = unsafe {
        (symbols.list_readers)(context, std::ptr::null(), buf.as_mut_ptr() as *mut c_char, &mut cch)
    };
    if list_rc2 != SCARD_S_SUCCESS {
        return Vec::new();
    }

    let mut readers = Vec::new();
    let mut start = 0;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            if i > start {
                if let Ok(s) = std::str::from_utf8(&buf[start..i]) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        readers.push(trimmed.to_string());
                    }
                }
            }
            start = i + 1;
        }
    }
    readers
}

fn resolve_target_reader(symbols: &PcscSymbols, context: i64, reader_opt: Option<&str>) -> Option<String> {
    if let Some(r) = reader_opt {
        return Some(r.to_string());
    }
    let readers = get_reader_list(symbols, context);
    if readers.is_empty() {
        return None;
    }
    let mut selected = readers[0].clone();
    for r_name in &readers {
        if let Ok(c_name) = CString::new(r_name.as_str()) {
            let mut state = SCARD_READERSTATE {
                sz_reader: c_name.as_ptr(),
                pv_user_data: std::ptr::null_mut(),
                dw_current_state: SCARD_STATE_UNAWARE,
                dw_event_state: 0,
                cb_atr: 0,
                rgb_atr: [0u8; 33],
            };
            let st_rc = unsafe {
                (symbols.get_status_change)(context, 0, &mut state, 1)
            };
            if st_rc == SCARD_S_SUCCESS && (state.dw_event_state & SCARD_STATE_PRESENT) != 0 {
                selected = r_name.clone();
                break;
            }
        }
    }
    Some(selected)
}

/// Queries the PIV cardholder PIN retry counter non-destructively inside a PC/SC transaction.
///
/// Sends an empty VERIFY APDU (00 20 00 80) to Key Reference 0x80 (PIV Cardholder PIN).
///
/// Returns: (is_success, retries_remaining, status_message)
/// When the PIN is already verified in an active session (0x90 0x00), retries_remaining is 255.
pub fn query_piv_pin_status(reader_opt: Option<&str>) -> (bool, u8, String) {
    let symbols = match PcscSymbols::try_load() {
        Some(s) => s,
        None => return (false, 0, "PC/SC Lite library unavailable".to_string()),
    };

    let (connect_fn, disconnect_fn, transmit_fn) = match (symbols.connect, symbols.disconnect, symbols.transmit) {
        (Some(c), Some(d), Some(t)) => (c, d, t),
        _ => return (false, 0, "PC/SC smart card functions unavailable".to_string()),
    };

    let mut context: i64 = 0;
    let rc = unsafe {
        (symbols.establish_context)(SCARD_SCOPE_SYSTEM, std::ptr::null(), std::ptr::null(), &mut context)
    };
    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(SCARD_SCOPE_USER, std::ptr::null(), std::ptr::null(), &mut context)
        };
        if rc_user != SCARD_S_SUCCESS {
            return (false, 0, "Failed to establish PC/SC context".to_string());
        }
        context
    };

    let target_reader = match resolve_target_reader(&symbols, context, reader_opt) {
        Some(r) => r,
        None => {
            unsafe { (symbols.release_context)(context); }
            return (false, 0, "No smart card reader with inserted card found".to_string());
        }
    };

    let c_reader = match CString::new(target_reader.as_str()) {
        Ok(c) => c,
        Err(_) => {
            unsafe { (symbols.release_context)(context); }
            return (false, 0, "Invalid reader name".to_string());
        }
    };

    let mut h_card: i64 = 0;
    let mut active_proto: usize = 0;
    let conn_rc = unsafe {
        connect_fn(
            context,
            c_reader.as_ptr(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &mut h_card,
            &mut active_proto,
        )
    };

    if conn_rc != SCARD_S_SUCCESS {
        unsafe { (symbols.release_context)(context); }
        return (false, 0, "Failed to connect to smart card".to_string());
    }

    let in_tx = if let Some(begin_fn) = symbols.begin_transaction {
        unsafe { begin_fn(h_card) == SCARD_S_SUCCESS }
    } else {
        false
    };

    if !select_piv_applet(transmit_fn, h_card, active_proto) {
        unsafe {
            if in_tx {
                if let Some(end_fn) = symbols.end_transaction {
                    let _ = end_fn(h_card, SCARD_LEAVE_CARD);
                }
            }
            disconnect_fn(h_card, SCARD_LEAVE_CARD);
            (symbols.release_context)(context);
        }
        return (false, 0, "PIV applet selection failed (non-PIV smart card)".to_string());
    }

    // Send empty VERIFY APDU to query retry counter without consuming an attempt
    let verify_empty = [0x00, 0x20, 0x00, 0x80];
    let resp = match transmit_apdu(transmit_fn, h_card, active_proto, &verify_empty) {
        Ok(r) => r,
        Err(e) => {
            unsafe {
                if in_tx {
                    if let Some(end_fn) = symbols.end_transaction {
                        let _ = end_fn(h_card, SCARD_LEAVE_CARD);
                    }
                }
                disconnect_fn(h_card, SCARD_LEAVE_CARD);
                (symbols.release_context)(context);
            }
            return (false, 0, format!("APDU transmit failure: error {e}"));
        }
    };

    unsafe {
        if in_tx {
            if let Some(end_fn) = symbols.end_transaction {
                let _ = end_fn(h_card, SCARD_LEAVE_CARD);
            }
        }
        disconnect_fn(h_card, SCARD_LEAVE_CARD);
        (symbols.release_context)(context);
    }

    if resp.len() < 2 {
        return (false, 0, "Invalid response from smart card".to_string());
    }

    let sw1 = resp[resp.len() - 2];
    let sw2 = resp[resp.len() - 1];

    if sw1 == 0x90 && sw2 == 0x00 {
        (true, 255, "PIN verified (Active session)".to_string())
    } else if sw1 == 0x63 && (sw2 & 0xF0) == 0xC0 {
        let retries = sw2 & 0x0F;
        if retries == 0 {
            (false, 0, "PIN locked (0 attempts remaining)".to_string())
        } else {
            (true, retries, format!("{retries} attempt(s) remaining"))
        }
    } else if sw1 == 0x69 && sw2 == 0x83 {
        (false, 0, "Authentication method blocked (PIN locked)".to_string())
    } else {
        (false, 0, format!("Card returned status {sw1:02X} {sw2:02X}"))
    }
}

/// Evaluates the status words (SW1, SW2) from an empty VERIFY APDU (00 20 00 80)
/// before transmitting CHANGE REFERENCE DATA. Fails closed on any locked, 1-retry,
/// or unrecognized status word.
pub fn evaluate_precheck_verify_sw(sw1: u8, sw2: u8) -> Result<u8, (u8, String)> {
    if (sw1 == 0x69 && sw2 == 0x83) || (sw1 == 0x63 && (sw2 & 0xF0) == 0xC0 && (sw2 & 0x0F) == 0) {
        return Err((0, "PIN is locked (0 attempts remaining); PUK unblock required".to_string()));
    }
    if sw1 == 0x63 && (sw2 & 0xF0) == 0xC0 {
        let retries = sw2 & 0x0F;
        if retries == 1 {
            return Err((
                1,
                "Only 1 PIN retry attempt remains; refusing automated PIN change to prevent card lockout".to_string(),
            ));
        }
        return Ok(retries);
    }
    if sw1 == 0x90 && sw2 == 0x00 {
        return Ok(255);
    }
    Err((
        0,
        format!("Security abort: Unexpected status {sw1:02X} {sw2:02X} from pre-check VERIFY APDU"),
    ))
}

/// Changes the PIV Cardholder PIN on the smart card via CHANGE REFERENCE DATA (00 24 00 80).
///
/// Parameters:
/// - old_pin: Current 6-8 digit PIN
/// - new_pin: New 6-8 digit PIN
///
/// Returns: (is_success, retries_remaining, status_message)
pub fn change_piv_pin_native(
    reader_opt: Option<&str>,
    old_pin: &str,
    new_pin: &str,
) -> (bool, u8, String) {
    if old_pin.len() < 6 || old_pin.len() > 8 || !old_pin.chars().all(|c| c.is_ascii_digit()) {
        return (false, 0, "Current PIN must be 6 to 8 numeric digits".to_string());
    }
    if new_pin.len() < 6 || new_pin.len() > 8 || !new_pin.chars().all(|c| c.is_ascii_digit()) {
        return (false, 0, "New PIN must be 6 to 8 numeric digits".to_string());
    }
    if old_pin == new_pin {
        return (false, 0, "New PIN must be different from current PIN".to_string());
    }

    use zeroize::Zeroize;
    let mut old_buf = [0xFFu8; 8];
    let mut new_buf = [0xFFu8; 8];

    for (i, b) in old_pin.as_bytes().iter().enumerate() {
        old_buf[i] = *b;
    }
    for (i, b) in new_pin.as_bytes().iter().enumerate() {
        new_buf[i] = *b;
    }

    let symbols = match PcscSymbols::try_load() {
        Some(s) => s,
        None => {
            old_buf.zeroize();
            new_buf.zeroize();
            return (false, 0, "PC/SC Lite library unavailable".to_string());
        }
    };

    let (connect_fn, disconnect_fn, transmit_fn) = match (symbols.connect, symbols.disconnect, symbols.transmit) {
        (Some(c), Some(d), Some(t)) => (c, d, t),
        _ => {
            old_buf.zeroize();
            new_buf.zeroize();
            return (false, 0, "PC/SC smart card functions unavailable".to_string());
        }
    };

    let mut context: i64 = 0;
    let rc = unsafe {
        (symbols.establish_context)(SCARD_SCOPE_SYSTEM, std::ptr::null(), std::ptr::null(), &mut context)
    };
    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(SCARD_SCOPE_USER, std::ptr::null(), std::ptr::null(), &mut context)
        };
        if rc_user != SCARD_S_SUCCESS {
            old_buf.zeroize();
            new_buf.zeroize();
            return (false, 0, "Failed to establish PC/SC context".to_string());
        }
        context
    };

    let target_reader = match resolve_target_reader(&symbols, context, reader_opt) {
        Some(r) => r,
        None => {
            unsafe { (symbols.release_context)(context); }
            old_buf.zeroize();
            new_buf.zeroize();
            return (false, 0, "No smart card reader with inserted card found".to_string());
        }
    };

    let c_reader = match CString::new(target_reader.as_str()) {
        Ok(c) => c,
        Err(_) => {
            unsafe { (symbols.release_context)(context); }
            old_buf.zeroize();
            new_buf.zeroize();
            return (false, 0, "Invalid reader name".to_string());
        }
    };

    let mut h_card: i64 = 0;
    let mut active_proto: usize = 0;
    let conn_rc = unsafe {
        connect_fn(
            context,
            c_reader.as_ptr(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &mut h_card,
            &mut active_proto,
        )
    };

    if conn_rc != SCARD_S_SUCCESS {
        unsafe { (symbols.release_context)(context); }
        old_buf.zeroize();
        new_buf.zeroize();
        return (false, 0, "Failed to connect to smart card".to_string());
    }

    let in_tx = if let Some(begin_fn) = symbols.begin_transaction {
        unsafe { begin_fn(h_card) == SCARD_S_SUCCESS }
    } else {
        false
    };
    if !in_tx {
        old_buf.zeroize();
        new_buf.zeroize();
        unsafe {
            disconnect_fn(h_card, SCARD_LEAVE_CARD);
            (symbols.release_context)(context);
        }
        return (
            false,
            0,
            "Security abort: Could not acquire exclusive PC/SC transaction for PIN change".to_string(),
        );
    }

    if !select_piv_applet(transmit_fn, h_card, active_proto) {
        old_buf.zeroize();
        new_buf.zeroize();
        unsafe {
            if let Some(end_fn) = symbols.end_transaction {
                let _ = end_fn(h_card, SCARD_LEAVE_CARD);
            }
            disconnect_fn(h_card, SCARD_LEAVE_CARD);
            (symbols.release_context)(context);
        }
        return (
            false,
            0,
            "PIV applet selection failed; refusing to send CHANGE REFERENCE DATA to unselected applet".to_string(),
        );
    }

    // Fail-closed: verify retry counter inside the transaction before attempting CHANGE REFERENCE DATA
    let verify_empty = [0x00, 0x20, 0x00, 0x80];
    match transmit_apdu(transmit_fn, h_card, active_proto, &verify_empty) {
        Ok(v_resp) if v_resp.len() >= 2 => {
            let v_sw1 = v_resp[v_resp.len() - 2];
            let v_sw2 = v_resp[v_resp.len() - 1];
            if let Err((retries, err_msg)) = evaluate_precheck_verify_sw(v_sw1, v_sw2) {
                old_buf.zeroize();
                new_buf.zeroize();
                unsafe {
                    if let Some(end_fn) = symbols.end_transaction {
                        let _ = end_fn(h_card, SCARD_LEAVE_CARD);
                    }
                    disconnect_fn(h_card, SCARD_LEAVE_CARD);
                    (symbols.release_context)(context);
                }
                return (false, retries, err_msg);
            }
        }
        _ => {
            old_buf.zeroize();
            new_buf.zeroize();
            unsafe {
                if let Some(end_fn) = symbols.end_transaction {
                    let _ = end_fn(h_card, SCARD_LEAVE_CARD);
                }
                disconnect_fn(h_card, SCARD_LEAVE_CARD);
                (symbols.release_context)(context);
            }
            return (
                false,
                0,
                "Security abort: Pre-check VERIFY APDU failed; refusing to transmit CHANGE REFERENCE DATA".to_string(),
            );
        }
    }

    // Build CHANGE REFERENCE DATA APDU:
    // CLA=00, INS=24, P1=00, P2=80, Lc=10, old_buf(8), new_buf(8)
    let mut change_apdu = [0u8; 21];
    change_apdu[0] = 0x00;
    change_apdu[1] = 0x24;
    change_apdu[2] = 0x00;
    change_apdu[3] = 0x80;
    change_apdu[4] = 0x10;
    change_apdu[5..13].copy_from_slice(&old_buf);
    change_apdu[13..21].copy_from_slice(&new_buf);

    old_buf.zeroize();
    new_buf.zeroize();

    let resp = match transmit_apdu(transmit_fn, h_card, active_proto, &change_apdu) {
        Ok(r) => {
            change_apdu.zeroize();
            r
        }
        Err(e) => {
            change_apdu.zeroize();
            unsafe {
                if in_tx {
                    if let Some(end_fn) = symbols.end_transaction {
                        let _ = end_fn(h_card, SCARD_LEAVE_CARD);
                    }
                }
                disconnect_fn(h_card, SCARD_LEAVE_CARD);
                (symbols.release_context)(context);
            }
            return (false, 0, format!("APDU transmit failure: error {e}"));
        }
    };

    unsafe {
        if in_tx {
            if let Some(end_fn) = symbols.end_transaction {
                let _ = end_fn(h_card, SCARD_LEAVE_CARD);
            }
        }
        disconnect_fn(h_card, SCARD_LEAVE_CARD);
        (symbols.release_context)(context);
    }

    if resp.len() < 2 {
        return (false, 0, "Invalid response from smart card".to_string());
    }

    let sw1 = resp[resp.len() - 2];
    let sw2 = resp[resp.len() - 1];

    if sw1 == 0x90 && sw2 == 0x00 {
        (true, 3, "PIN changed successfully".to_string())
    } else if sw1 == 0x63 && (sw2 & 0xF0) == 0xC0 {
        let retries = sw2 & 0x0F;
        (false, retries, format!("Incorrect current PIN ({retries} attempt(s) remaining)"))
    } else if sw1 == 0x69 && sw2 == 0x83 {
        (false, 0, "PIN blocked (0 attempts remaining)".to_string())
    } else if sw1 == 0x6A && sw2 == 0x80 {
        (false, 0, "New PIN rejected by smart card policy".to_string())
    } else {
        (false, 0, format!("Card returned status {sw1:02X} {sw2:02X}"))
    }
}

/// Blocks waiting for a smart card insertion or removal event.
///
/// Returns Option<(reader_name, is_card_present)>:
/// - Some((reader, true)): Card was just inserted.
/// - Some((reader, false)): Card was just removed.
/// - None: Timeout expired with no state change, or error.
pub fn wait_for_smartcard_event(timeout_ms: u32) -> Option<(String, bool)> {
    let symbols = PcscSymbols::try_load()?;

    let mut context: i64 = 0;
    let rc = unsafe {
        (symbols.establish_context)(SCARD_SCOPE_SYSTEM, std::ptr::null(), std::ptr::null(), &mut context)
    };
    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(SCARD_SCOPE_USER, std::ptr::null(), std::ptr::null(), &mut context)
        };
        if rc_user != SCARD_S_SUCCESS {
            return None;
        }
        context
    };

    let readers = get_reader_list(&symbols, context);
    if readers.is_empty() {
        unsafe { (symbols.release_context)(context); }
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms.min(1000) as u64));
        return None;
    }

    let mut reader_cstrings: Vec<CString> = Vec::new();
    let mut states: Vec<SCARD_READERSTATE> = Vec::new();

    for r_name in &readers {
        if let Ok(c_name) = CString::new(r_name.as_str()) {
            reader_cstrings.push(c_name);
        }
    }

    for c_name in &reader_cstrings {
        states.push(SCARD_READERSTATE {
            sz_reader: c_name.as_ptr(),
            pv_user_data: std::ptr::null_mut(),
            dw_current_state: SCARD_STATE_UNAWARE,
            dw_event_state: 0,
            cb_atr: 0,
            rgb_atr: [0u8; 33],
        });
    }

    let init_rc = unsafe {
        (symbols.get_status_change)(context, 0, states.as_mut_ptr(), states.len())
    };

    if init_rc != SCARD_S_SUCCESS {
        unsafe { (symbols.release_context)(context); }
        return None;
    }

    for state in states.iter_mut() {
        state.dw_current_state = state.dw_event_state;
    }

    let wait_rc = unsafe {
        (symbols.get_status_change)(context, timeout_ms as usize, states.as_mut_ptr(), states.len())
    };

    if wait_rc != SCARD_S_SUCCESS {
        unsafe { (symbols.release_context)(context); }
        return None;
    }

    let mut event = None;
    for (i, state) in states.iter().enumerate() {
        let changed = (state.dw_event_state & 0x0002) != 0; // SCARD_STATE_CHANGED
        if changed {
            let present = (state.dw_event_state & SCARD_STATE_PRESENT) != 0;
            let reader_name = readers.get(i).cloned().unwrap_or_default();
            event = Some((reader_name, present));
            break;
        }
    }

    unsafe { (symbols.release_context)(context); }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_atr_detection() {
        assert!(is_cac_or_piv_atr("3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"));
        assert!(!is_cac_or_piv_atr("3b:00:00:00"));
    }

    #[test]
    fn test_native_pcsc_query_does_not_crash() {
        let status = query_native_pcsc_status();
        println!("PC/SC status: {:?}", status);
    }

    #[test]
    fn test_pin_change_validation() {
        // Non-numeric rejected
        let (ok, _, msg) = change_piv_pin_native(None, "abcdef", "123456");
        assert!(!ok);
        assert!(msg.contains("numeric"));

        // Too short (< 6)
        let (ok, _, msg) = change_piv_pin_native(None, "12345", "123456");
        assert!(!ok);
        assert!(msg.contains("6 to 8"));

        // Too long (> 8)
        let (ok, _, msg) = change_piv_pin_native(None, "123456789", "123456");
        assert!(!ok);
        assert!(msg.contains("6 to 8"));

        // Same PIN rejected
        let (ok, _, msg) = change_piv_pin_native(None, "123456", "123456");
        assert!(!ok);
        assert!(msg.contains("different"));
    }

    #[test]
    fn test_evaluate_precheck_verify_sw_fail_closed() {
        assert_eq!(evaluate_precheck_verify_sw(0x63, 0xC3), Ok(3));
        assert_eq!(evaluate_precheck_verify_sw(0x63, 0xC2), Ok(2));
        assert_eq!(evaluate_precheck_verify_sw(0x90, 0x00), Ok(255));
        assert!(evaluate_precheck_verify_sw(0x63, 0xC1).is_err());
        assert!(evaluate_precheck_verify_sw(0x63, 0xC0).is_err());
        assert!(evaluate_precheck_verify_sw(0x69, 0x83).is_err());
        assert!(evaluate_precheck_verify_sw(0x6A, 0x82).is_err());
    }

    #[test]
    fn test_query_piv_pin_status_no_crash() {
        let (ok, retries, msg) = query_piv_pin_status(None);
        println!("PIN status query result: ok={} retries={} msg='{}'", ok, retries, msg);
    }

    #[test]
    fn test_extract_cert_from_piv_container_der_and_wrapper() {
        // Load real test DoD cert
        let pem_bytes = include_bytes!("../../../certificates/roots/DoD_Root_CA_3.crt");
        let pem_str = std::str::from_utf8(pem_bytes).unwrap();
        let b64 = pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>();
        let der = base64_simd_or_standard_decode(&b64);

        // 1. Direct raw DER extraction
        let extracted_raw = extract_cert_from_piv_container(&der);
        assert!(extracted_raw.is_some());
        assert_eq!(extracted_raw.unwrap(), der);

        // 2. Wrapped in NIST PIV Tag 0x70 + Length + EDC Tag 0xFE
        let mut wrapped = vec![0x70, 0x82, (der.len() >> 8) as u8, (der.len() & 0xFF) as u8];
        wrapped.extend_from_slice(&der);
        wrapped.extend_from_slice(&[0xFE, 0x00]); // EDC

        let extracted_wrapped = extract_cert_from_piv_container(&wrapped);
        assert!(extracted_wrapped.is_some());
        assert_eq!(extracted_wrapped.unwrap(), der);

        // 3. Wrapped in GZIP compressed PIV container (Tag 0x71)
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&der).unwrap();
        let gz_bytes = encoder.finish().unwrap();

        let mut gz_container = vec![0x71, 0x82, (gz_bytes.len() >> 8) as u8, (gz_bytes.len() & 0xFF) as u8];
        gz_container.extend_from_slice(&gz_bytes);
        gz_container.extend_from_slice(&[0xFE, 0x00]);

        let extracted_gz = extract_cert_from_piv_container(&gz_container);
        assert!(extracted_gz.is_some());
        assert_eq!(extracted_gz.unwrap(), der);
    }

    fn base64_simd_or_standard_decode(b64: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for c in b64.chars() {
            let val = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '+' => 62,
                '/' => 63,
                '=' | '\r' | '\n' | ' ' => continue,
                _ => continue,
            };
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        out
    }

    #[test]
    fn test_parse_chuid_and_ccc() {
        // Synthetic CHUID with 16-byte UUID in tag 0xEE and expiration in tag 0x35
        let mut chuid = vec![0x53, 0x1E]; // Tag 0x53 len 30
        chuid.push(0xEE); // Tag UUID
        chuid.push(0x10); // len 16
        chuid.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);
        chuid.push(0x35); // Tag expiration
        chuid.push(0x08); // len 8
        chuid.extend_from_slice(b"20300101");
        chuid.push(0xFE); // EDC
        chuid.push(0x00);

        let (serial, exp) = parse_chuid_metadata(&chuid);
        assert_eq!(serial.as_deref(), Some("01020304-0506-0708-090a-0b0c0d0e0f10"));
        assert_eq!(exp.as_deref(), Some("20300101"));

        // Synthetic CCC with card identifier in tag 0xF0
        let mut ccc = vec![0x53, 0x06];
        ccc.push(0xF0);
        ccc.push(0x04);
        ccc.extend_from_slice(&[0xA0, 0x00, 0x00, 0x03]);
        let card_id = parse_ccc_metadata(&ccc);
        assert_eq!(card_id.as_deref(), Some("A0000003"));

        // Empty / truncated handling
        assert_eq!(parse_chuid_metadata(&[]), (None, None));
        assert_eq!(parse_ccc_metadata(&[]), None);
    }
}
