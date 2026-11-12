use pyo3::prelude::*;
use regex::Regex;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyCardCertificate {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub label: String,
    #[pyo3(get)]
    pub subject: String,
    #[pyo3(get)]
    pub issuer: String,
    #[pyo3(get)]
    pub issuer_cn: String,
    #[pyo3(get)]
    pub cn: String,
    #[pyo3(get)]
    pub holder_name: String,
    #[pyo3(get)]
    pub edipi: String,
    #[pyo3(get)]
    pub upn: Option<String>,
    #[pyo3(get)]
    pub aia_url: Option<String>,
    #[pyo3(get)]
    pub valid_from_str: String,
    #[pyo3(get)]
    pub valid_to_str: String,
    #[pyo3(get)]
    pub serial: String,
    #[pyo3(get)]
    pub usage: String,
    #[pyo3(get)]
    pub is_valid: bool,
    #[pyo3(get)]
    pub status_text: String,
    #[pyo3(get)]
    pub raw_der: Vec<u8>,
}

#[pymethods]
impl PyCardCertificate {
    fn __repr__(&self) -> String {
        format!(
            "<CardCertificate id='{}' label='{}' holder='{}' edipi='{}' valid={}>",
            self.id, self.label, self.holder_name, self.edipi, self.is_valid
        )
    }
}

pub fn parse_der_or_pem_bytes(
    id: String,
    label: String,
    usage: String,
    bytes: &[u8],
) -> Result<PyCardCertificate, String> {
    // If PEM formatted, extract DER bytes
    let der_data: Vec<u8> = if bytes.starts_with(b"-----BEGIN") || bytes.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") {
        match Pem::iter_from_buffer(bytes).next() {
            Some(Ok(pem)) => pem.contents,
            _ => return Err("Failed to decode PEM block".to_string()),
        }
    } else {
        bytes.to_vec()
    };

    let (_, x509) = parse_x509_certificate(&der_data)
        .map_err(|e| format!("ASN.1 X.509 DER parse error: {:?}", e))?;

    let subject = x509.subject().to_string();
    let issuer = x509.issuer().to_string();

    // Extract CN
    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Fallback regex
            let re_cn = Regex::new(r"CN\s*=\s*([^,\n]+)").unwrap();
            re_cn
                .captures(&subject)
                .map(|c| c[1].trim().to_string())
                .unwrap_or_default()
        });

    // Extract Issuer CN
    let issuer_cn = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let re_cn = Regex::new(r"CN\s*=\s*([^,\n]+)").unwrap();
            re_cn
                .captures(&issuer)
                .map(|c| c[1].trim().to_string())
                .unwrap_or_else(|| issuer.clone())
        });

    // Extract DoD EDIPI & format Holder Name
    let (mut holder_name, mut edipi) = format_dod_cn(&cn);

    if holder_name.is_empty() {
        let re_sn = Regex::new(r"(?i)serialNumber\s*=\s*([^\s,]+)").unwrap();
        if let Some(caps) = re_sn.captures(&subject) {
            holder_name = format!("PIV Credential ({})", &caps[1]);
        } else if !cn.is_empty() {
            holder_name = cn.clone();
        } else {
            holder_name = "DoD Smart Card Credential".to_string();
        }
    }

    if edipi.is_empty() {
        let re_edipi = Regex::new(r"\b(\d{10})\b").unwrap();
        if let Some(caps) = re_edipi.captures(&subject) {
            edipi = caps[1].to_string();
        }
    }

    // Dates and validity
    let not_before = x509.validity().not_before;
    let not_after = x509.validity().not_after;

    let valid_from_str = format_asn1_time(&not_before);
    let valid_to_str = format_asn1_time(&not_after);

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let not_before_ts = not_before.timestamp();
    let not_after_ts = not_after.timestamp();

    let is_valid = now_ts >= not_before_ts && now_ts <= not_after_ts;
    let status_text = if now_ts < not_before_ts {
        format!("Not Yet Valid (Valid from {})", valid_from_str)
    } else if now_ts > not_after_ts {
        "Expired".to_string()
    } else {
        let remaining_days = (not_after_ts - now_ts) / 86400;
        if remaining_days < 60 {
            format!("Expiring soon ({} days) (Revocation Unchecked)", remaining_days)
        } else {
            format!("Date Valid through {} (Revocation Unchecked)", valid_to_str)
        }
    };

    let serial = x509.raw_serial_as_string();

    // Extract SAN UPN (OID 1.3.6.1.4.1.311.20.2.3) and AIA CA-Issuer URL
    let mut upn: Option<String> = None;
    let mut aia_url: Option<String> = None;

    for ext in x509.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for gn in &san.general_names {
                    if let GeneralName::OtherName(oid, data) = gn {
                        if oid.to_id_string() == "1.3.6.1.4.1.311.20.2.3" {
                            if let Some(val) = extract_upn_from_other_name(data) {
                                upn = Some(val);
                            }
                        }
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for desc in &aia.accessdescs {
                    if desc.access_method == oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS {
                        if let GeneralName::URI(uri) = desc.access_location {
                            aia_url = Some(uri.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if edipi.is_empty() {
        if let Some(ref u) = upn {
            let re_upn_edipi = Regex::new(r"(\d{10})").unwrap();
            if let Some(caps) = re_upn_edipi.captures(u) {
                edipi = caps[1].to_string();
            }
        }
    }

    Ok(PyCardCertificate {
        id,
        label,
        subject,
        issuer,
        issuer_cn,
        cn,
        holder_name,
        edipi,
        upn,
        aia_url,
        valid_from_str,
        valid_to_str,
        serial,
        usage,
        is_valid,
        status_text,
        raw_der: der_data,
    })
}

fn extract_upn_from_other_name(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let inner = if data[0] == 0xa0 && data.len() > 2 {
        let len_byte = data[1] as usize;
        if len_byte & 0x80 == 0 && data.len() >= 2 + len_byte {
            &data[2..2 + len_byte]
        } else if len_byte == 0x81 && data.len() > 3 {
            let l = data[2] as usize;
            &data[3..3 + l]
        } else {
            &data[2..]
        }
    } else {
        data
    };
    if inner.len() > 2 && inner[0] == 0x0c {
        let str_len = inner[1] as usize;
        let start = 2;
        let end = start + str_len;
        if inner.len() >= end {
            if let Ok(s) = std::str::from_utf8(&inner[start..end]) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    let printable: Vec<u8> = data.iter().copied().filter(|&b| (0x20..=0x7e).contains(&b)).collect();
    if printable.contains(&b'@') {
        if let Ok(s) = std::str::from_utf8(&printable) {
            let s_trim = s.trim();
            if s_trim.contains('@') {
                return Some(s_trim.to_string());
            }
        }
    }
    None
}

fn title_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;

    for c in s.chars() {
        if c.is_whitespace() || c == '.' || c == '-' {
            result.push(c);
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            result.extend(c.to_lowercase());
        }
    }
    result
}

fn format_asn1_time(time: &ASN1Time) -> String {
    time.to_rfc2822().unwrap_or_else(|_| time.to_string())
}

/// Parses DoD Common Name into clean holder name and EDIPI, stripping component tokens
/// (CTR, CIV, MIL) and attaching generational suffixes (Jr, II, III).
pub fn format_dod_cn(cn: &str) -> (String, String) {
    let mut holder_name = cn.to_string();
    let mut edipi = String::new();

    if cn.contains('.') {
        let mut parts: Vec<&str> = cn.split('.').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        if let Some(last_part) = parts.last() {
            if last_part.chars().all(|c| c.is_ascii_digit()) && last_part.len() >= 9 {
                edipi = last_part.to_string();
                parts.pop();

                let component_tokens = ["CTR", "CIV", "MIL", "FN", "NAF", "VOL", "RET", "CONTRACTOR", "AFFILIATE"];
                let gen_suffixes = ["JR", "SR", "II", "III", "IV", "V"];

                let mut filtered_parts: Vec<&str> = Vec::new();
                let mut found_gen = String::new();

                for p in parts {
                    let p_upper = p.to_ascii_uppercase();
                    if component_tokens.contains(&p_upper.as_str()) {
                        continue;
                    }
                    if gen_suffixes.contains(&p_upper.as_str()) {
                        found_gen = if p_upper == "JR" || p_upper == "SR" {
                            title_case(p)
                        } else {
                            p_upper
                        };
                        continue;
                    }
                    filtered_parts.push(p);
                }

                if !filtered_parts.is_empty() {
                    if filtered_parts.len() >= 2 {
                        let mut last = title_case(filtered_parts[0]);
                        if !found_gen.is_empty() {
                            last = format!("{} {}", last, found_gen);
                        }
                        let first_middle: Vec<String> = filtered_parts[1..].iter().map(|p| title_case(p)).collect();
                        holder_name = format!("{} {}", first_middle.join(" "), last);
                    } else {
                        let mut base = title_case(filtered_parts[0]);
                        if !found_gen.is_empty() {
                            base = format!("{} {}", base, found_gen);
                        }
                        holder_name = base;
                    }
                }
            }
        }
    }
    (holder_name, edipi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_dod_cn_standard() {
        let (holder, edipi) = format_dod_cn("DOE.JOHN.ROBERT.1234567890");
        assert_eq!(holder, "John Robert Doe");
        assert_eq!(edipi, "1234567890");
    }

    #[test]
    fn test_format_dod_cn_contractor() {
        let (holder, edipi) = format_dod_cn("DOE.JOHN.R.CTR.1234567890");
        assert_eq!(holder, "John R Doe");
        assert_eq!(edipi, "1234567890");
    }

    #[test]
    fn test_format_dod_cn_civilian_with_suffix() {
        let (holder, edipi) = format_dod_cn("SMITH.JAMES.M.JR.CIV.9876543210");
        assert_eq!(holder, "James M Smith Jr");
        assert_eq!(edipi, "9876543210");
    }

    #[test]
    fn test_format_dod_cn_two_part_name() {
        let (holder, edipi) = format_dod_cn("BROWN.MARY.1122334455");
        assert_eq!(holder, "Mary Brown");
        assert_eq!(edipi, "1122334455");
    }

    #[test]
    fn test_extract_upn_from_other_name() {
        let upn_bytes = b"1234567890@mil";
        let mut data = vec![0xa0, (upn_bytes.len() + 2) as u8, 0x0c, upn_bytes.len() as u8];
        data.extend_from_slice(upn_bytes);
        assert_eq!(extract_upn_from_other_name(&data), Some("1234567890@mil".to_string()));

        assert_eq!(extract_upn_from_other_name(b"\x00\x01user@mil\x00"), Some("user@mil".to_string()));
        assert_eq!(extract_upn_from_other_name(b"no-at-sign"), None);
    }
}
