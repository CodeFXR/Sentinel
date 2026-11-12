pub mod cert;
pub mod hardware;
pub mod integrity;
pub mod ocsp;
pub mod pki;
pub mod security;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

use cert::{parse_der_or_pem_bytes, PyCardCertificate};
use hardware::{
    change_piv_pin_native, is_cac_or_piv_atr, parse_pkcs15_tool_list,
    query_native_pcsc_status, query_piv_pin_status, read_piv_card_metadata_native,
    read_piv_certificates_native, wait_for_smartcard_event, PyNativePcscStatus,
    PyPivCardMetadata,
};
use integrity::{
    compute_file_sha256_rust, is_opensc_config_optimized_rust,
    validate_pkcs11_module_path_rust, validate_tar_member_safety_rust,
    verify_bytes_sha256_rust,
};
use ocsp::{
    extract_ocsp_urls_from_der_rust, validate_ocsp_url_rust,
    verify_ocsp_responder_cert_der_rust,
};
use pki::{
    check_bundled_ca_expirations_rust, constant_time_hex_eq, sha256_hex,
    validate_and_reserialize_ca_rust, verify_ca_file_manifest_rust,
};
use security::PinBuffer;

#[pyfunction]
fn version() -> &'static str {
    "2.0.3"
}

#[pyfunction]
fn parse_certificate(
    id: String,
    label: String,
    usage: String,
    data: &[u8],
) -> PyResult<PyCardCertificate> {
    parse_der_or_pem_bytes(id, label, usage, data)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn read_card_certificates(reader: Option<String>) -> Vec<PyCardCertificate> {
    read_piv_certificates_native(reader.as_deref())
}

#[pyfunction]
fn read_card_metadata(reader: Option<String>) -> PyPivCardMetadata {
    read_piv_card_metadata_native(reader.as_deref())
}

#[pyfunction]
fn query_pin_status(reader: Option<String>) -> (bool, u8, String) {
    query_piv_pin_status(reader.as_deref())
}

#[pyfunction]
fn change_pin(mut old_pin: String, mut new_pin: String, reader: Option<String>) -> (bool, u8, String) {
    let res = change_piv_pin_native(reader.as_deref(), &old_pin, &new_pin);
    old_pin.zeroize();
    new_pin.zeroize();
    res
}

#[pyfunction]
fn wait_for_card_event(timeout_ms: u32) -> Option<(String, bool)> {
    wait_for_smartcard_event(timeout_ms)
}

#[pyfunction]
fn parse_pkcs15_list(output: &str) -> Vec<(String, String)> {
    parse_pkcs15_tool_list(output)
}

#[pyfunction]
fn is_cac_atr(atr: &str) -> bool {
    is_cac_or_piv_atr(atr)
}

#[pyfunction]
fn query_native_pcsc() -> PyNativePcscStatus {
    query_native_pcsc_status()
}

#[pyfunction]
fn sha256_digest_hex(data: &[u8]) -> String {
    sha256_hex(data)
}

#[pyfunction]
fn constant_time_compare_hex(a: &str, b: &str) -> bool {
    constant_time_hex_eq(a, b)
}

#[pyfunction]
fn validate_and_reserialize_ca<'py>(
    py: Python<'py>,
    data: &[u8],
    fname: &str,
    verify_whitelist: bool,
) -> (Option<Bound<'py, PyBytes>>, Option<String>) {
    match validate_and_reserialize_ca_rust(data, fname, verify_whitelist) {
        Ok(pem_bytes) => (Some(PyBytes::new(py, &pem_bytes)), None),
        Err(err_msg) => (None, Some(err_msg)),
    }
}

#[pyfunction]
fn verify_ca_file_manifest(filepath: &str, fname_override: Option<&str>) -> bool {
    verify_ca_file_manifest_rust(filepath, fname_override)
}

#[pyfunction]
fn check_ca_bundle_expirations(
    certs_dir: &str,
    warn_days: u64,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    check_bundled_ca_expirations_rust(certs_dir, warn_days)
}

#[pyfunction]
fn validate_pkcs11_module_path(raw_path: &str) -> (Option<String>, Option<String>) {
    match validate_pkcs11_module_path_rust(raw_path) {
        Ok(canonical) => (Some(canonical), None),
        Err(err) => (None, Some(err)),
    }
}

#[pyfunction]
fn is_opensc_config_optimized(content: &str) -> bool {
    is_opensc_config_optimized_rust(content)
}

#[pyfunction]
fn compute_file_sha256(filepath: &str) -> Option<String> {
    compute_file_sha256_rust(filepath)
}

#[pyfunction]
fn verify_archive_sha256(
    archive_bytes: &[u8],
    expected_sha256: &str,
    max_bytes: usize,
) -> (bool, String) {
    match verify_bytes_sha256_rust(archive_bytes, expected_sha256, max_bytes) {
        Ok(actual) => (true, actual),
        Err(err) => (false, err),
    }
}

#[pyfunction]
fn validate_tar_member_safety(
    member_name: &str,
    is_hardlink: bool,
    is_symlink: bool,
    is_device_or_fifo: bool,
    linkname: &str,
    size: u64,
) -> (bool, String) {
    match validate_tar_member_safety_rust(
        member_name,
        is_hardlink,
        is_symlink,
        is_device_or_fifo,
        linkname,
        size,
    ) {
        Ok(()) => (true, String::new()),
        Err(err) => (false, err),
    }
}

#[pyfunction]
fn validate_ocsp_url(url: &str, allow_non_mil: bool) -> bool {
    validate_ocsp_url_rust(url, allow_non_mil)
}

#[pyfunction]
fn extract_ocsp_urls_from_der(der_bytes: &[u8], allow_non_mil: bool) -> Vec<String> {
    extract_ocsp_urls_from_der_rust(der_bytes, allow_non_mil)
}

#[pyfunction]
fn verify_ocsp_responder_cert_der(
    responder_der: &[u8],
    issuer_der: &[u8],
) -> (bool, bool, String) {
    verify_ocsp_responder_cert_der_rust(responder_der, issuer_der)
}

#[pymodule]
fn sentinel_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(parse_certificate, m)?)?;
    m.add_function(wrap_pyfunction!(read_card_certificates, m)?)?;
    m.add_function(wrap_pyfunction!(read_card_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(query_pin_status, m)?)?;
    m.add_function(wrap_pyfunction!(change_pin, m)?)?;
    m.add_function(wrap_pyfunction!(wait_for_card_event, m)?)?;
    m.add_function(wrap_pyfunction!(parse_pkcs15_list, m)?)?;
    m.add_function(wrap_pyfunction!(is_cac_atr, m)?)?;
    m.add_function(wrap_pyfunction!(query_native_pcsc, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_digest_hex, m)?)?;
    m.add_function(wrap_pyfunction!(constant_time_compare_hex, m)?)?;
    m.add_function(wrap_pyfunction!(validate_and_reserialize_ca, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ca_file_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(check_ca_bundle_expirations, m)?)?;
    m.add_function(wrap_pyfunction!(validate_pkcs11_module_path, m)?)?;
    m.add_function(wrap_pyfunction!(is_opensc_config_optimized, m)?)?;
    m.add_function(wrap_pyfunction!(compute_file_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(verify_archive_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(validate_tar_member_safety, m)?)?;
    m.add_function(wrap_pyfunction!(validate_ocsp_url, m)?)?;
    m.add_function(wrap_pyfunction!(extract_ocsp_urls_from_der, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ocsp_responder_cert_der, m)?)?;
    m.add_class::<PyCardCertificate>()?;
    m.add_class::<PyNativePcscStatus>()?;
    m.add_class::<PyPivCardMetadata>()?;
    m.add_class::<PinBuffer>()?;
    Ok(())
}
