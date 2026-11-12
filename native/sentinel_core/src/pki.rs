//! Native DoD PKI Manifest, FIPS 180-4 SHA-256 Engine, and X.509 CA Verifier.
//!
//! Provides constant-time digest verification, canonical ASN.1 DER SHA-256 allowlist
//! enforcement for all 45 official DoD PKI certificates, X.509 v3 BasicConstraints
//! and validity window verification via `x509-parser`, and canonical PEM serialization.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

/// Maximum allowed certificate file size (5 MiB) to prevent memory exhaustion.
pub const MAX_CERT_FILE_BYTES: usize = 5 * 1024 * 1024;

/// Hardware-accelerated FIPS 180-4 SHA-256 hasher backed by the audited `sha2` crate.
#[derive(Clone, Default)]
pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

/// Compute raw 32-byte SHA-256 digest of a byte slice.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute lowercase 64-character hexadecimal SHA-256 digest of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_bytes(data);
    let mut out = String::with_capacity(64);
    for b in &digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Constant-time comparison of two hexadecimal SHA-256 strings (case-insensitive).
pub fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.trim().as_bytes();
    let b_bytes = b.trim().as_bytes();
    if a_bytes.len() != b_bytes.len() || a_bytes.is_empty() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x.to_ascii_lowercase() ^ y.to_ascii_lowercase();
    }
    diff == 0
}

/// Authoritative raw file SHA-256 manifest for bundled DoD PKI files.
pub const DOD_CA_FILE_FINGERPRINTS: &[(&str, &str)] = &[
    ("DOD_DERILITY_CA-1.crt", "b792d3cd0a8d2b077ea81cab0c6cd4edc018b054b89c59268d42a5590bd691ff"),
    ("DOD_DERILITY_CA-3.crt", "365049baa57070951e53dc9011006d94f95b31baff9404fbf2a1734675559d84"),
    ("DOD_DERILITY_CA-4.crt", "69e4b7ac1dbd472c2b561775e0d992d2a2ec8a9e2dad537693740f0340016805"),
    ("DOD_DERILITY_CA-5.crt", "8416b0a5526c15f294309ed19cc790439b09b10755b7a370f670cac64dc810d7"),
    ("DOD_DERILITY_CA-6.crt", "713112199a0198a97837d8a3bca13c218bc7ec6590ced816ebdd8d7ea8b3c1a5"),
    ("DOD_EMAIL_CA-62.crt", "aa418e09adc19edb0a0302e01120a07d68f60cf05c2c4c28aef24af93b9a7d26"),
    ("DOD_EMAIL_CA-63.crt", "e0471278a605146108bcfb6cd8408ec94d497c2e912d91b13dc8c4d85e6474a7"),
    ("DOD_EMAIL_CA-64.crt", "433098257647e0fd92b2262bf58b16dacc54a98f51cf8b5be5d47dbb5d92b1a1"),
    ("DOD_EMAIL_CA-65.crt", "adb54e87d349dcc5665652d83274815da10e5cd18640a5f84a4ed90b96a83bc6"),
    ("DOD_EMAIL_CA-70.crt", "3988b7899fb52ba764169db787d7ae357b12f76e361d20c631cb41740fca6b69"),
    ("DOD_EMAIL_CA-71.crt", "97b6bcd92d05f4e4c764560365b4ed728f983ab48477286e106e4100c28a275d"),
    ("DOD_EMAIL_CA-72.crt", "b342f980fd1a88ad4605447db67eae6163ba33cb7e108ac9ace482a0139a9988"),
    ("DOD_EMAIL_CA-73.crt", "93f52cbb1c9666e5b9bc7dd7b901816560ee0d82edad97137aec35531b21761f"),
    ("DOD_EMAIL_CA-78.crt", "4f3ee6ddd7821cb9d49d09805ce3678d1ba521efc44d6f146fe79363b3170b9b"),
    ("DOD_EMAIL_CA-79.crt", "ef60845fc4d2bedcb404a7d7b375229e6a6dee6c2def84866f3dd0a14acd639b"),
    ("DOD_EMAIL_CA-80.crt", "bf463e544dbc8b2dbe588ef957df9251af2deb9171916fc1371f0ccaa7b73633"),
    ("DOD_EMAIL_CA-81.crt", "87696e907b5c9bb7bb407480559bd98e07b54d0a47d748540b01ce0bac379fcf"),
    ("DOD_ID_CA-62.crt", "25f2aa5eb6ebff9b66ffde5c62fea0d4eb791ec7fa7ff6f2e388126c74100ed0"),
    ("DOD_ID_CA-63.crt", "7649a6591cebc1c6400195caacba43e76d2588a2025eba49eb2d2cafe2c097ae"),
    ("DOD_ID_CA-64.crt", "c81bd68f5b7453aa99c471fe79f2eeba643e9b0ff2466235b6b9deecfac841c9"),
    ("DOD_ID_CA-65.crt", "15896437be65f4c922b51623b40621a362483175638c567f6738b5a8d136b3cb"),
    ("DOD_ID_CA-70.crt", "1fd13654266223a348e79f827a3f358ccf803215955990982d32009b270d9b2e"),
    ("DOD_ID_CA-71.crt", "9d93bfba93a82b8532ff3985b81fcf26dd42f878e8ab397a857ee6ba52db4306"),
    ("DOD_ID_CA-72.crt", "d53d3673229377b608f52f622a6db780baed0692ceb16593f1f87b45257cf005"),
    ("DOD_ID_CA-73.crt", "a4d2016bff3e1baec36b42a4921ec3d7ef8b3130e10bb1b02cf0c01babf8a3df"),
    ("DOD_ID_CA-78.crt", "178f10e93fb7966d437cf40f02115237f558704337a482f020d63cd9b004ae76"),
    ("DOD_ID_CA-79.crt", "3d49e89b592e2eeb4389fb82747e1e67e5389c7d25d70352c9df9480f83cebd9"),
    ("DOD_ID_CA-80.crt", "17038dc5ccd48f4ed0677dea3758d7059d0fec7aeb0aeaa748f80d0133a8d577"),
    ("DOD_ID_CA-81.crt", "09a0be8af9309bb53bbc643f7178a6b3d6e12f59907a7a2116fef53ac099c5ce"),
    ("DOD_SW_CA-66.crt", "6c592affece2d6bfcc51a5d74a8bf72f2a730554bfb886169cef4a692c1c077f"),
    ("DOD_SW_CA-67.crt", "a3f6b2e15d03b2be4b38d870fc483b7b29096978cbf469b23a55469bcf528f8e"),
    ("DOD_SW_CA-68.crt", "5043ab9bf7978b0292ed6f3e9c5057e86eab5d9107845766e878ddec2249c38a"),
    ("DOD_SW_CA-69.crt", "210c46224b7375fcf246165163c30185e41ec4df0730b10b9afa2fe79c4fa538"),
    ("DOD_SW_CA-74.crt", "bc3e078e31530686c0a058c0911aa1ccb80cbba0fd54c19c60f06f567ada2104"),
    ("DOD_SW_CA-75.crt", "8ee4b5c2731dad2a18e13eab0289ab7a52622ff55272ae796a0b5d20fcdb6cde"),
    ("DOD_SW_CA-76.crt", "550b688a41e6841c649b876e74d4a67331832ca834195bb78411036448dfa975"),
    ("DOD_SW_CA-77.crt", "2a5c88ce7e20096fdf6c739dc54d842996b6e75fc6d05913b0f3b06ede151db8"),
    ("DOD_SW_CA-82.crt", "81498acfe45eda7f67bef9c345618fec8efa8b612fd9c9bbb016306b04f2c5b5"),
    ("DOD_SW_CA-83.crt", "612625a070c229a89f4137995989689cace809ab75f1879c80adaee10c45acee"),
    ("DOD_SW_CA-84.crt", "4c7245e536c95d8035604e516e8a32b09670f33545de7cba06075da0757364f7"),
    ("DOD_SW_CA-85.crt", "d9ed4f3ebec2295f4a792a008a905e540f95834531540434a66c3a697ab3de35"),
    ("DoD_Full_Chain.crt", "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d"),
    ("DoD_Full_Chain.pem", "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d"),
    ("DoD_Root_CA_3.crt", "9ca4000a486094dbcf46f5d5162375789a5e8b564ce754a87e4b90e06db0e177"),
    ("DoD_Root_CA_4.crt", "488cac7d9d9fe818945410a5d37713ac3ebbd8d5a36f71d489278c8ba334b27c"),
    ("DoD_Root_CA_5.crt", "07820e449f9543fa02f9f207cd0babb15d82d7f2dea34874e8e85a2a3f55a0a4"),
    ("DoD_Root_CA_6.crt", "6936a739b3327f15c563d106862c5b9406c6be24cb5656288ada6826783e0ff4"),
    ("DoD_Roots.pem", "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779"),
    ("DoW_Full_Chain.crt", "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d"),
    ("DoW_Full_Chain.pem", "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d"),
    ("DoW_Roots.pem", "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779"),
];

/// Canonical ASN.1 DER SHA-256 certificate fingerprints for all 45 individual DoD CAs.
pub const DOD_CA_DER_FINGERPRINTS: &[(&str, &str)] = &[
    ("DOD_DERILITY_CA-1.crt", "67a953b9e17f77599c6e553053dcd43fd7478fdd5cbd844612ceb6064386f8df"),
    ("DOD_DERILITY_CA-3.crt", "83eea7e541716dcfb4b705a44e34f7e0af86d839c7cd796962a70e91d4932646"),
    ("DOD_DERILITY_CA-4.crt", "8112237903e9a9afdc4e5bec6970c3ef09c9a63897da4156c22a77d355ad0deb"),
    ("DOD_DERILITY_CA-5.crt", "70a011a6b00759f6ab1d08acb3f646d66f578e41f71f1c9586e1f470f4576870"),
    ("DOD_DERILITY_CA-6.crt", "4f6c4dc6800346464db209f5a05ec1f4019e7ba48f7346011d9643d2e4b3eace"),
    ("DOD_EMAIL_CA-62.crt", "36490d91175ca3b39b21b21941db70635c58a3fd0f51135af9f0edc15cbf55b6"),
    ("DOD_EMAIL_CA-63.crt", "c6a4dac9fd846474ea35c52afada31510d388ee5af694d8e7f7300eee73cbd2f"),
    ("DOD_EMAIL_CA-64.crt", "690c69044761d3a9ab208e4ef2c7b461f09ab524137e7d059176324df42480d8"),
    ("DOD_EMAIL_CA-65.crt", "d483b29aae8b40d62ad4757f2986a6d541c4241383d7928592fc61ba5d01085a"),
    ("DOD_EMAIL_CA-70.crt", "2ad7d00e45d128a46fdb5747d39eaa994f034086d05cb891e01bf61c7d97c083"),
    ("DOD_EMAIL_CA-71.crt", "9d7e0bfb84d6a5f66cfd701b786dc75db31422687212bf26c276b70df0627bdb"),
    ("DOD_EMAIL_CA-72.crt", "22ffd6b58540bed6f568890348da2654ca54b50f2216c9eade78812782206ba2"),
    ("DOD_EMAIL_CA-73.crt", "ca4733b4e471a699d025fa88cee35e07372dcaa9cfe609469c16a72ec5595cf7"),
    ("DOD_EMAIL_CA-78.crt", "2c95f5c815569b65cdf70d03f135f2cf130b82b33d5719a68d25a1ec19d405fc"),
    ("DOD_EMAIL_CA-79.crt", "3d8d7bf0c6381aa07ff5e0aa47fec6d077aeec1c2ee22183b2c2028a2ff35d68"),
    ("DOD_EMAIL_CA-80.crt", "8208232225e469e65e93497402be9a377d81a25938b85ccae3f3adc14078de93"),
    ("DOD_EMAIL_CA-81.crt", "8dc6e3657631ec33de1706c2803662786c120825d121b5dd4b1c90b126654967"),
    ("DOD_ID_CA-62.crt", "a3626dfa33eadf6f1ac300a733f52322c6cdc59f5d561e2188c493d016c49dd5"),
    ("DOD_ID_CA-63.crt", "dd2dc71d5affa281ceb4da78d58a8119ffe606d732dab5343b2b1c3de4993613"),
    ("DOD_ID_CA-64.crt", "fc6fd238f81a3b1755db3bc5471440a186ef3ab4e9ea6d76c2e157c22236b482"),
    ("DOD_ID_CA-65.crt", "80e252331942dcaaaa7de7fb450ee9610081f44bbe164fe9936a759ba4541e5b"),
    ("DOD_ID_CA-70.crt", "3ccc94baa9108ef0ca373b89074b8cfac6c0cf0f07ab190c570d5053032f337a"),
    ("DOD_ID_CA-71.crt", "f7ba690fe17cff7b191ac6d32522931c6f472df487574f0d1c576da0d2ab7049"),
    ("DOD_ID_CA-72.crt", "b1c14ea631f47bcd7698e7673fdf5b5b104c52631ce58913346ec7a07e154638"),
    ("DOD_ID_CA-73.crt", "3d6a666556365400d6e2beed9dd97082537fb74887a5c68b426eb06c327e0826"),
    ("DOD_ID_CA-78.crt", "bbaf5275b33aff5aa9e5bce945640ac0c08f4a4d02d7d2e26e78293e912231ce"),
    ("DOD_ID_CA-79.crt", "4a3a111b697959d3f620cbf9f5150e4087861d47a695860aff8136a819a71e1a"),
    ("DOD_ID_CA-80.crt", "ad6bb50b82da2f99c242d7971012175809b22af0112f1e695ef3c236c7d2f22e"),
    ("DOD_ID_CA-81.crt", "abdc810cf17cea00bbaace9418b872c25cf8bf3d7694a4e05b9f391d23b80d03"),
    ("DOD_SW_CA-66.crt", "79dd87d87503bd9c422b49e2bf7a23a5c0783cce85d588759f3a349ec26eb84a"),
    ("DOD_SW_CA-67.crt", "cca9b469b4edda4d615b58c130ecaebba5ca439adbee8be15206626e5122f4ca"),
    ("DOD_SW_CA-68.crt", "dcd29a5b27db87d5d617f395edad6d7fa0fe230117afbf6c4b7f31f372a2e66a"),
    ("DOD_SW_CA-69.crt", "3320f4876c4d0fa7118f2891a1421bb3cda7bb64be80f9bd040bcff6faa3dbee"),
    ("DOD_SW_CA-74.crt", "6338c57b568b1d47568ab7548a8d66cc31bc4a096a4cc10a4b45edeb09bd65f6"),
    ("DOD_SW_CA-75.crt", "6cbc8895834385d27678cb0012d224277b02dcfc4502bceafdfe1a0a2543f416"),
    ("DOD_SW_CA-76.crt", "0e0f71389c9937334989842a908206e671f356a10903e2cf398abb5e27b3f40c"),
    ("DOD_SW_CA-77.crt", "48e2775e6db09931c3d62a913889affc653aa9d9142ac4c10bd11f6968fc4a31"),
    ("DOD_SW_CA-82.crt", "7aafb4a72e96483d9db2b4226dcead0bb01a95c236768c7a0f681abf5f168e81"),
    ("DOD_SW_CA-83.crt", "cc88db853e8f8c2c61f40f281ebca7ed08a082e1ac10679b785db9f76e9b7015"),
    ("DOD_SW_CA-84.crt", "560eb4465753bd286bf65fd0d16256fd126daa0d1d5abbe9ff7a5688ae830357"),
    ("DOD_SW_CA-85.crt", "6fa364cfc7ecdc69e581d20f0bcea306f8d8a52142b3dadda949276db1061098"),
    ("DoD_Root_CA_3.crt", "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2"),
    ("DoD_Root_CA_4.crt", "559a5189452b13f8233f0022363c06f26e3c517c1d4b77445035959df3244f74"),
    ("DoD_Root_CA_5.crt", "1f4ede9dc2a241f6521bf518424acd49ebe84420e69daf5bac57af1f8ee294a9"),
    ("DoD_Root_CA_6.crt", "2a5e41aca93df7cc496d2369b7a0a037045d502f1abaaf76975fc07c6660cf93"),
];

/// Authoritative DER SHA-256 digests of the 4 DoD Root CAs.
pub const DOD_ROOT_DER_FINGERPRINTS: &[(&str, &str)] = &[
    ("DoD_Root_CA_3.crt", "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2"),
    ("DoD_Root_CA_4.crt", "559a5189452b13f8233f0022363c06f26e3c517c1d4b77445035959df3244f74"),
    ("DoD_Root_CA_5.crt", "1f4ede9dc2a241f6521bf518424acd49ebe84420e69daf5bac57af1f8ee294a9"),
    ("DoD_Root_CA_6.crt", "2a5e41aca93df7cc496d2369b7a0a037045d502f1abaaf76975fc07c6660cf93"),
];

fn lookup_file_fingerprint(fname: &str) -> Option<&'static str> {
    DOD_CA_FILE_FINGERPRINTS
        .iter()
        .find(|&&(k, _)| k == fname)
        .map(|&(_, v)| v)
}

fn lookup_der_fingerprint(fname: &str) -> Option<&'static str> {
    DOD_CA_DER_FINGERPRINTS
        .iter()
        .find(|&&(k, _)| k == fname)
        .map(|&(_, v)| v)
}

fn is_allowed_der_hash(hash_hex: &str) -> bool {
    DOD_CA_DER_FINGERPRINTS
        .iter()
        .any(|&(_, v)| constant_time_hex_eq(v, hash_hex))
}

fn is_root_der_hash(hash_hex: &str) -> bool {
    DOD_ROOT_DER_FINGERPRINTS
        .iter()
        .any(|&(_, v)| constant_time_hex_eq(v, hash_hex))
}

/// Strictly decode Base64 body (ignoring ASCII whitespace) into raw bytes.
#[allow(clippy::manual_is_multiple_of, clippy::chunks_exact_to_as_chunks)]
pub fn decode_base64_clean(input: &[u8]) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if cleaned.is_empty() || cleaned.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    for (chunk_idx, chunk) in cleaned.chunks_exact(4).enumerate() {
        let is_last = (chunk_idx + 1) * 4 == cleaned.len();
        let mut vals = [0u8; 4];
        let mut pad_count = 0usize;

        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                if !is_last || i < 2 {
                    return None;
                }
                pad_count += 1;
                vals[i] = 0;
            } else {
                if pad_count > 0 {
                    return None;
                }
                vals[i] = match b {
                    b'A'..=b'Z' => b - b'A',
                    b'a'..=b'z' => b - b'a' + 26,
                    b'0'..=b'9' => b - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    _ => return None,
                };
            }
        }

        let triple = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);

        out.push(((triple >> 16) & 0xFF) as u8);
        if pad_count < 2 {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if pad_count == 0 {
            out.push((triple & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Encode raw ASN.1 DER bytes into canonical 64-column PEM certificate format.
pub fn encode_der_to_canonical_pem(der: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = Vec::with_capacity(der.len().div_ceil(3) * 4);

    for chunk in der.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        b64.push(TABLE[((triple >> 18) & 0x3F) as usize]);
        b64.push(TABLE[((triple >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 {
            b64.push(TABLE[((triple >> 6) & 0x3F) as usize]);
        } else {
            b64.push(b'=');
        }
        if chunk.len() > 2 {
            b64.push(TABLE[(triple & 0x3F) as usize]);
        } else {
            b64.push(b'=');
        }
    }

    let mut pem = Vec::with_capacity(b64.len() + 64);
    pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
    for line in b64.chunks(64) {
        pem.extend_from_slice(line);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END CERTIFICATE-----");
    pem
}

/// Extract all PEM `-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----` bodies.
pub fn extract_pem_certificate_bodies(data: &[u8]) -> Vec<&[u8]> {
    const BEGIN_TAG: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END_TAG: &[u8] = b"-----END CERTIFICATE-----";

    let mut bodies = Vec::new();
    let mut cursor = 0usize;

    while cursor < data.len() {
        let Some(rel_start) = find_subslice(&data[cursor..], BEGIN_TAG) else {
            break;
        };
        let body_start = cursor + rel_start + BEGIN_TAG.len();
        let Some(rel_end) = find_subslice(&data[body_start..], END_TAG) else {
            break;
        };
        let body_end = body_start + rel_end;
        bodies.push(&data[body_start..body_end]);
        cursor = body_end + END_TAG.len();
    }
    bodies
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Verify ASN.1 X.509 certificate structure, CA basicConstraints, expiration, and self-signed root status.
pub fn verify_x509_ca_properties_rust(der_bytes: &[u8], require_self_signed: bool) -> Option<Vec<u8>> {
    if der_bytes.len() < 64 || der_bytes[0] != 0x30 {
        return None;
    }
    let (rem, cert) = parse_x509_certificate(der_bytes).ok()?;
    if !rem.is_empty() {
        return None;
    }

    if cert.subject().iter_rdn().count() == 0 || cert.issuer().iter_rdn().count() == 0 {
        return None;
    }

    if require_self_signed && cert.subject() != cert.issuer() {
        return None;
    }

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let not_after_ts = cert.validity().not_after.timestamp();
    let not_before_ts = cert.validity().not_before.timestamp();
    if now_ts <= 0 || not_after_ts <= now_ts || not_before_ts > now_ts {
        return None;
    }

    let bc = cert.basic_constraints().ok()??;
    if !bc.value.ca {
        return None;
    }

    Some(encode_der_to_canonical_pem(der_bytes))
}

/// Validate X.509 certificate data, DER fingerprints, and CA properties, returning canonical PEM bytes.
pub fn validate_and_reserialize_ca_rust(
    data: &[u8],
    fname: &str,
    verify_whitelist: bool,
) -> Result<Vec<u8>, String> {
    let pem_bodies = extract_pem_certificate_bodies(data);
    if pem_bodies.is_empty() {
        return Err(format!(
            "Security: Rejected {}: contains no valid PEM certificate blocks",
            fname
        ));
    }

    let is_root_target = DOD_ROOT_DER_FINGERPRINTS.iter().any(|&(k, _)| k == fname)
        || fname == "DoD_Roots.pem"
        || fname == "DoW_Roots.pem";
    let is_full_chain = matches!(
        fname,
        "DoD_Full_Chain.pem" | "DoD_Full_Chain.crt" | "DoW_Full_Chain.pem" | "DoW_Full_Chain.crt"
    );

    let mut reserialized_certs: Vec<Vec<u8>> = Vec::new();
    let mut seen_der_hashes: Vec<String> = Vec::new();

    for (idx, body) in pem_bodies.iter().enumerate() {
        let Some(der_bytes) = decode_base64_clean(body) else {
            return Err(format!(
                "Security: Rejected {}: block {} has invalid base64 encoding",
                fname,
                idx + 1
            ));
        };
        if der_bytes.len() < 64 || der_bytes[0] != 0x30 {
            return Err(format!(
                "Security: Rejected {}: block {} has invalid ASN.1 DER sequence",
                fname,
                idx + 1
            ));
        }

        let der_sha256 = sha256_hex(&der_bytes);
        seen_der_hashes.push(der_sha256.clone());

        if verify_whitelist {
            if let Some(expected_der) = lookup_der_fingerprint(fname) {
                if !constant_time_hex_eq(&der_sha256, expected_der) {
                    return Err(format!(
                        "Security: DER fingerprint mismatch for '{}'! Expected {}, got {}",
                        fname, expected_der, der_sha256
                    ));
                }
            } else if fname == "DoD_Roots.pem" || fname == "DoW_Roots.pem" {
                if !is_root_der_hash(&der_sha256) {
                    return Err(format!(
                        "Security: Non-root certificate found inside root bundle '{}' ({})",
                        fname, der_sha256
                    ));
                }
            } else if is_full_chain {
                if !is_allowed_der_hash(&der_sha256) {
                    return Err(format!(
                        "Security: Unauthorized certificate block {} in '{}' ({})",
                        idx + 1,
                        fname,
                        der_sha256
                    ));
                }
            } else {
                return Err(format!(
                    "Security: Rejected unauthorized certificate filename '{}'",
                    fname
                ));
            }
        }

        match verify_x509_ca_properties_rust(&der_bytes, is_root_target) {
            Some(validated_pem) => reserialized_certs.push(validated_pem),
            None => {
                if is_full_chain {
                    continue;
                }
                return Err(format!(
                    "Security: Rejected {}: certificate block {} failed X.509 CA/validity verification",
                    fname,
                    idx + 1
                ));
            }
        }
    }

    if verify_whitelist && (fname == "DoD_Roots.pem" || fname == "DoW_Roots.pem") {
        for &(_, req_root_hash) in DOD_ROOT_DER_FINGERPRINTS {
            if !seen_der_hashes.iter().any(|h| constant_time_hex_eq(h, req_root_hash)) {
                return Err(format!(
                    "Security: Root bundle '{}' is missing one or more required DoD Root CAs",
                    fname
                ));
            }
        }
    }

    if reserialized_certs.is_empty() {
        return Err(format!("Security: No valid certificates remained in '{}'", fname));
    }

    let mut output = Vec::new();
    for (i, cert_pem) in reserialized_certs.iter().enumerate() {
        if i > 0 {
            output.push(b'\n');
        }
        output.extend_from_slice(cert_pem);
    }
    output.push(b'\n');
    Ok(output)
}

/// Return true only if `filepath` is a regular file (not a symlink) matching the DoD CA manifest.
pub fn verify_ca_file_manifest_rust(filepath: &str, fname_override: Option<&str>) -> bool {
    let path = Path::new(filepath);
    let Ok( symlink_meta ) = fs::symlink_metadata(path) else {
        return false;
    };
    if symlink_meta.file_type().is_symlink() || !symlink_meta.is_file() {
        return false;
    }
    if symlink_meta.len() > MAX_CERT_FILE_BYTES as u64 {
        return false;
    }

    let target_name = match fname_override {
        Some(name) if !name.is_empty() => name,
        _ => match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => return false,
        },
    };

    let Some(expected_raw_sha256) = lookup_file_fingerprint(target_name) else {
        return false;
    };

    let Ok(raw) = fs::read(path) else {
        return false;
    };
    if raw.len() > MAX_CERT_FILE_BYTES {
        return false;
    }

    let raw_sha256 = sha256_hex(&raw);
    if constant_time_hex_eq(&raw_sha256, expected_raw_sha256) {
        return true;
    }

    if let Some(expected_der_sha256) = lookup_der_fingerprint(target_name) {
        let bodies = extract_pem_certificate_bodies(&raw);
        if bodies.len() == 1 {
            if let Some(der) = decode_base64_clean(bodies[0]) {
                if der.len() >= 64 && der[0] == 0x30 {
                    let der_sha256 = sha256_hex(&der);
                    if constant_time_hex_eq(&der_sha256, expected_der_sha256) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Format UNIX timestamp (UTC) as `YYYY-MM-DD` using Howard Hinnant's civil-from-days algorithm.
pub fn format_unix_timestamp_ymd(timestamp_secs: i64) -> String {
    let days = timestamp_secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", year, m, d)
}

/// Inspect bundled DoD certificates in `<certs_dir>/all_cas` and classify into `(valid, expiring_soon, expired)`.
pub fn check_bundled_ca_expirations_rust(
    certs_dir: &str,
    warn_days: u64,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut valid = Vec::new();
    let mut expiring_soon = Vec::new();
    let mut expired = Vec::new();

    let all_cas_dir = Path::new(certs_dir).join("all_cas");
    let Ok(entries) = fs::read_dir(&all_cas_dir) else {
        return (valid, expiring_soon, expired);
    };

    let mut filenames: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".crt"))
        .collect();
    filenames.sort();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let threshold_ts = now_ts + (warn_days as i64) * 86_400;

    for fname in filenames {
        let fpath = all_cas_dir.join(&fname);
        let Ok(raw) = fs::read(&fpath) else {
            continue;
        };
        let bodies = extract_pem_certificate_bodies(&raw);
        let Some(first_body) = bodies.first() else {
            continue;
        };
        let Some(der) = decode_base64_clean(first_body) else {
            continue;
        };
        let Ok((_, cert)) = parse_x509_certificate(&der) else {
            continue;
        };
        let not_after_ts = cert.validity().not_after.timestamp();
        let date_str = format_unix_timestamp_ymd(not_after_ts);
        let label = format!("{} ({})", fname, date_str);
        if not_after_ts <= now_ts {
            expired.push(label);
        } else if not_after_ts <= threshold_ts {
            expiring_soon.push(label);
        } else {
            valid.push(label);
        }
    }

    (valid, expiring_soon, expired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_constant_time_hex_eq() {
        assert!(constant_time_hex_eq(
            "9ca4000a486094dbcf46f5d5162375789a5e8b564ce754a87e4b90e06db0e177",
            "9CA4000A486094DBCF46F5D5162375789A5E8B564CE754A87E4B90E06DB0E177"
        ));
        assert!(!constant_time_hex_eq("abcdef", "abcdee"));
        assert!(!constant_time_hex_eq("abcdef", "abcd"));
        assert!(!constant_time_hex_eq("", ""));
    }

    #[test]
    fn test_base64_roundtrip() {
        let sample = vec![0x30u8, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xff, 0xaa, 0x55];
        let pem = encode_der_to_canonical_pem(&sample);
        let bodies = extract_pem_certificate_bodies(&pem);
        assert_eq!(bodies.len(), 1);
        let decoded = decode_base64_clean(bodies[0]).expect("valid base64");
        assert_eq!(decoded, sample);
    }

    #[test]
    fn test_format_unix_timestamp_ymd() {
        assert_eq!(format_unix_timestamp_ymd(0), "1970-01-01");
        assert_eq!(format_unix_timestamp_ymd(1893249600), "2029-12-29");
        assert_eq!(format_unix_timestamp_ymd(1893336000), "2029-12-30");
    }
}
