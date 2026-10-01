//! Silent Payments output descriptors (BIP-392) as exported by Sparrow, so a
//! user can paste one instead of hand-decoding hex keys.
//!
//! Accepted forms (BIP-393 annotations and the BIP-380 `#checksum` are both
//! optional; a checksum, when present, must be valid):
//!
//! - `sp([fp/352h/0h/0h]spscan1q…)?bh=N#cs` — the watch-only form Sparrow's
//!   *Copy Output Descriptor* produces: scan private key + spend public key.
//! - `sp(spspend1q…)` — scan private key + **spend private key**. Parsed so
//!   the spend public key can be derived; the spend secret is dropped at once
//!   and only [`SpDescriptor::had_spend_secret`] remembers it was there.
//! - `sp(<scan WIF or hex>,<spend pubkey hex | spend WIF>)` — the
//!   two-argument form of Sparrow's descriptor file export.
//!
//! HRPs: `spscan`/`spspend` on mainnet, `tspscan`/`tspspend` on every test
//! network (testnet3/4, signet and regtest), so the key only tells mainnet
//! from "some test network". `bh=` is the wallet's birth height; Sparrow only
//! writes it once the wallet has a confirmed transaction.

use std::fmt;

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{NetworkKind, PrivateKey};

/// The scan secret + spend public key carried by an SP descriptor. The
/// spend private key, if the descriptor had one, is never stored here.
#[derive(Clone, PartialEq, Eq)]
pub struct SpDescriptor {
    pub scan_secret: SecretKey,
    pub spend_pubkey: PublicKey,
    /// `Main` for `spscan`/`spspend` keys, `Test` for `tspscan`/`tspspend`.
    pub network_kind: NetworkKind,
    /// Wallet birth height from the BIP-393 `bh=` annotation.
    pub birth_height: Option<u64>,
    /// The descriptor contained the spend private key (dropped on parse).
    pub had_spend_secret: bool,
}

impl fmt::Debug for SpDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpDescriptor")
            .field("scan_secret", &"<redacted>")
            .field("spend_pubkey", &self.spend_pubkey)
            .field("network_kind", &self.network_kind)
            .field("birth_height", &self.birth_height)
            .field("had_spend_secret", &self.had_spend_secret)
            .finish()
    }
}

const WHERE_IN_SPARROW: &str = "in Sparrow open the wallet's Settings tab, right-click the \
     Descriptor field and choose Copy Output Descriptor";

impl SpDescriptor {
    /// Parse a descriptor (surrounding whitespace and line breaks ignored).
    pub fn parse(input: &str) -> Result<Self, String> {
        let text: String = input.split_whitespace().collect();
        if text.is_empty() {
            return Err("the descriptor is empty".to_string());
        }

        let body = match text.rsplit_once('#') {
            Some((body, checksum)) => {
                let expected = descriptor_checksum(body)
                    .ok_or("the descriptor contains characters descriptors cannot contain")?;
                if checksum != expected {
                    return Err(format!(
                        "descriptor checksum mismatch (got #{checksum}, expected #{expected}): \
                         the text was probably cut off or altered while copying; copy it again"
                    ));
                }
                body
            }
            None => text.as_str(),
        };

        let (script, annotations) = match body.split_once('?') {
            Some((script, annotations)) => (script, Some(annotations)),
            None => (body, None),
        };
        let birth_height = annotations.map(parse_birth_height).transpose()?.flatten();

        let inner = script
            .strip_prefix("sp(")
            .and_then(|s| s.strip_suffix(')'))
            .ok_or_else(|| {
                if script.starts_with("tr(") || script.starts_with("wpkh(") {
                    format!(
                        "this is not a Silent Payments descriptor (it starts with `{}`); \
                         use a Sparrow wallet created with policy type Silent Payments",
                        &script[..script.find('(').unwrap_or(0) + 1]
                    )
                } else {
                    format!("not an SP descriptor: expected `sp(...)`; {WHERE_IN_SPARROW}")
                }
            })?;

        let mut parsed = match inner.split_once(',') {
            None => parse_bech32_key(strip_origin(inner)?)?,
            Some((scan, spend)) => parse_two_keys(strip_origin(scan)?, strip_origin(spend)?)?,
        };
        parsed.birth_height = birth_height;
        Ok(parsed)
    }

    /// Does this descriptor's key HRP fit the friglet `network` name?
    pub fn matches_network(&self, network: &str) -> bool {
        match self.network_kind {
            NetworkKind::Main => network == "bitcoin",
            NetworkKind::Test => network != "bitcoin",
        }
    }

    /// Error text for [`Self::matches_network`] failures.
    pub fn network_mismatch(&self, network: &str) -> String {
        match self.network_kind {
            NetworkKind::Main => {
                format!("the descriptor is for a mainnet wallet (spscan), but network is {network}")
            }
            NetworkKind::Test => format!(
                "the descriptor is for a test-network wallet (tspscan), but network is {network}"
            ),
        }
    }

    pub fn scan_pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.scan_secret)
    }

    /// Hex scan secret, as the key file stores it.
    pub fn scan_secret_hex(&self) -> String {
        hex_encode(&self.scan_secret.secret_bytes())
    }

    /// Hex spend public key, as `spend_pubkey` in the config stores it.
    pub fn spend_pubkey_hex(&self) -> String {
        hex_encode(&self.spend_pubkey.serialize())
    }

    /// The watch-only text form: `sp(spscan1…)` with the birth height
    /// annotation and a fresh checksum. Key origins are not reproduced.
    pub fn to_watch_only_string(&self) -> String {
        let hrp = match self.network_kind {
            NetworkKind::Main => "spscan",
            NetworkKind::Test => "tspscan",
        };
        let mut payload = Vec::with_capacity(65);
        payload.extend_from_slice(&self.scan_secret.secret_bytes());
        payload.extend_from_slice(&self.spend_pubkey.serialize());
        let mut body = format!("sp({})", encode_v0(hrp, &payload));
        if let Some(bh) = self.birth_height {
            body.push_str(&format!("?bh={bh}"));
        }
        let checksum = descriptor_checksum(&body).expect("generated descriptor is ASCII");
        format!("{body}#{checksum}")
    }

    /// The wallet's BIP-352 receive address (label-less) on `network`, for
    /// comparing against Sparrow's Receive tab.
    pub fn sp_address(&self, network: &str) -> String {
        let hrp = match network {
            "bitcoin" => "sp",
            "regtest" => "sprt",
            _ => "tsp",
        };
        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&self.scan_pubkey().serialize());
        payload.extend_from_slice(&self.spend_pubkey.serialize());
        encode_v0(hrp, &payload)
    }
}

/// Drop a leading `[fingerprint/path]` key origin.
fn strip_origin(key: &str) -> Result<&str, String> {
    match key.strip_prefix('[') {
        Some(rest) => rest
            .split_once(']')
            .map(|(_, key)| key)
            .ok_or_else(|| "malformed key origin: missing `]`".to_string()),
        None => Ok(key),
    }
}

/// `bh=<height>` from a BIP-393 annotation list (`k=v&k=v`); other keys are
/// ignored.
fn parse_birth_height(annotations: &str) -> Result<Option<u64>, String> {
    for pair in annotations.split('&') {
        if let Some(value) = pair.strip_prefix("bh=") {
            return value
                .parse::<u64>()
                .map(Some)
                .map_err(|_| format!("invalid birth height annotation `bh={value}`"));
        }
    }
    Ok(None)
}

/// `spscan1…` / `spspend1…` (and the `t` test-network variants).
fn parse_bech32_key(key: &str) -> Result<SpDescriptor, String> {
    let lower = key.to_ascii_lowercase();
    let (network_kind, is_spend) = match lower.split_once('1').map(|(hrp, _)| hrp) {
        Some("spscan") => (NetworkKind::Main, false),
        Some("tspscan") => (NetworkKind::Test, false),
        Some("spspend") => (NetworkKind::Main, true),
        Some("tspspend") => (NetworkKind::Test, true),
        _ => {
            let shown: String = key.chars().take(12).collect();
            return Err(format!(
                "unsupported key `{shown}…` in sp(...): expected an spscan key; {WHERE_IN_SPARROW}"
            ));
        }
    };

    let mut checked = CheckedHrpstring::new::<Bech32m>(key)
        .map_err(|e| format!("invalid Silent Payments key encoding ({e}); copy it again"))?;
    let version = checked
        .remove_witness_version()
        .ok_or("invalid Silent Payments key: missing version")?;
    if version != Fe32::Q {
        return Err(format!(
            "unsupported Silent Payments key version {}",
            version.to_u8()
        ));
    }
    let payload: Vec<u8> = checked.byte_iter().collect();
    let expected = if is_spend { 64 } else { 65 };
    if payload.len() != expected {
        return Err(format!(
            "invalid Silent Payments key: {} payload bytes, expected {expected}",
            payload.len()
        ));
    }

    let scan_secret = SecretKey::from_slice(&payload[..32])
        .map_err(|e| format!("invalid scan private key in descriptor: {e}"))?;
    let spend_pubkey = if is_spend {
        let spend_secret = SecretKey::from_slice(&payload[32..64])
            .map_err(|e| format!("invalid spend private key in descriptor: {e}"))?;
        PublicKey::from_secret_key(&Secp256k1::signing_only(), &spend_secret)
    } else {
        PublicKey::from_slice(&payload[32..65])
            .map_err(|e| format!("invalid spend public key in descriptor: {e}"))?
    };
    Ok(SpDescriptor {
        scan_secret,
        spend_pubkey,
        network_kind,
        birth_height: None,
        had_spend_secret: is_spend,
    })
}

/// Two-argument form: scan private key (WIF or hex), then the spend public
/// key (hex) or spend private key (WIF or hex, dropped after deriving).
fn parse_two_keys(scan: &str, spend: &str) -> Result<SpDescriptor, String> {
    let (scan_secret, scan_kind) = parse_private_key(scan)
        .ok_or("the first key in sp(scan,spend) must be the scan private key (WIF or hex)")?;

    let (spend_pubkey, spend_kind, had_spend_secret) = if let Some(pk) = parse_hex_pubkey(spend) {
        (pk, None, false)
    } else if let Some((secret, kind)) = parse_private_key(spend) {
        (
            PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret),
            kind,
            true,
        )
    } else {
        return Err(
            "the second key in sp(scan,spend) must be the spend public key (66 hex characters)"
                .to_string(),
        );
    };

    let network_kind = match (scan_kind, spend_kind) {
        (Some(a), Some(b)) if a != b => {
            return Err("the scan and spend keys are for different networks".to_string());
        }
        (Some(kind), _) | (None, Some(kind)) => kind,
        (None, None) => {
            return Err(
                "cannot tell the network from hex keys: use the WIF scan key or the \
                 spscan form Sparrow copies"
                    .to_string(),
            );
        }
    };
    Ok(SpDescriptor {
        scan_secret,
        spend_pubkey,
        network_kind,
        birth_height: None,
        had_spend_secret,
    })
}

/// WIF (network known) or 64-hex (network unknown) private key.
fn parse_private_key(s: &str) -> Option<(SecretKey, Option<NetworkKind>)> {
    if let Ok(pk) = PrivateKey::from_wif(s) {
        return Some((pk.inner, Some(pk.network)));
    }
    if s.len() == 64 {
        let bytes = hex_decode(s)?;
        return SecretKey::from_slice(&bytes).ok().map(|k| (k, None));
    }
    None
}

fn parse_hex_pubkey(s: &str) -> Option<PublicKey> {
    if s.len() != 66 {
        return None;
    }
    PublicKey::from_slice(&hex_decode(s)?).ok()
}

fn encode_v0(hrp: &str, payload: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("static HRP is valid");
    payload
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .with_witness_version(Fe32::Q)
        .chars()
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// BIP-380 descriptor checksum of `desc` (everything before `#`), or `None`
/// when `desc` has a character outside the descriptor character set.
pub fn descriptor_checksum(desc: &str) -> Option<String> {
    const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    fn polymod(c: u64, val: u64) -> u64 {
        const GENERATOR: [u64; 5] = [
            0xf5dee51989,
            0xa9fdca3312,
            0x1bab10e32d,
            0x3706b1677a,
            0x644d626ffd,
        ];
        let top = c >> 35;
        let mut c = ((c & 0x7ffffffff) << 5) ^ val;
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                c ^= g;
            }
        }
        c
    }

    let mut c = 1u64;
    let mut cls = 0u64;
    let mut clscount = 0;
    for ch in desc.chars() {
        let pos = INPUT_CHARSET.find(ch)? as u64;
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = polymod(c, cls);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;
    Some(
        (0..8)
            .map(|j| CHECKSUM_CHARSET[((c >> (5 * (7 - j))) & 31) as usize] as char)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sparrow test fixture (Coldcard/Keystone/Specter testnet wallet).
    const SPARROW_TSPSCAN: &str = "tspscan1q05wxw5wc7wqmkf8cnfc6ry76qej8vhr3a3mmxmwgv35s0tlw24fs82k0npv2hv6p97s8sd9t7vpf44kluka9w863zjwxzfrym2ay9ccfzt06c4";
    const SPARROW_TSPSCAN_SCAN: &str =
        "7d1c6751d8f381bb24f89a71a193da0664765c71ec77b36dc8646907afee5553";
    const SPARROW_TSPSCAN_SPEND: &str =
        "03aacf9858abb3412fa07834abf3029ad6dfe5ba571f51149c612464daba42e309";

    /// Sparrow test fixture (mainnet, WalletLabelsTest).
    const SPARROW_SPSCAN: &str = "spscan1qu6d9s9lfd3a99nckpjw7as602lg0950wvcfwg7g4kakhsp32r57qx4853d0ylm42uewydgx6xgz0v20hgthsk2kr84f96jls3q0jywktrv8us5";
    const SPARROW_SPSCAN_SCAN: &str =
        "e69a5817e96c7a52cf160c9deec34f57d0f2d1ee6612e47915b76d78062a1d3c";
    const SPARROW_SPSCAN_SPEND: &str =
        "0354f48b5e4feeaae65c46a0da3204f629f742ef0b2ac33d525d4bf0881f223acb";

    /// Keys from drongo's test seed, in both the scan and the spend form.
    const DRONGO_SPSCAN: &str = "spscan1qpa55up5q9zn30790dw2pr7dpx0wn2ef9su2vcgn9jje5mwgvrukqyhxfs4kklqm4x58pywtcm2kzqrpxpj6mtt5rzpk2hyzgfhxclnekj2vrpm";
    const DRONGO_SPSPEND: &str = "spspend1qpa55up5q9zn30790dw2pr7dpx0wn2ef9su2vcgn9jje5mwgvrukf66kc2h8rg9l0sn5rdzfwtftrj2lm5p06tktue63sufn02s8q3vch3lrh8";
    const DRONGO_SCAN: &str = "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
    const DRONGO_SPEND_PUB: &str =
        "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";

    #[test]
    fn bip380_checksum_vectors() {
        assert_eq!(
            descriptor_checksum("raw(deadbeef)").as_deref(),
            Some("89f8spxm")
        );
        assert_eq!(
            descriptor_checksum("addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)").as_deref(),
            Some("02wpgw69")
        );
        assert_eq!(descriptor_checksum("raw(é)"), None);
    }

    #[test]
    fn sparrow_copy_output_descriptor_testnet() {
        let text = format!("sp([0f056943/352h/1h/0h]{SPARROW_TSPSCAN})#7eve6al9");
        let d = SpDescriptor::parse(&text).unwrap();
        assert_eq!(d.scan_secret_hex(), SPARROW_TSPSCAN_SCAN);
        assert_eq!(d.spend_pubkey_hex(), SPARROW_TSPSCAN_SPEND);
        assert_eq!(d.network_kind, NetworkKind::Test);
        assert_eq!(d.birth_height, None);
        assert!(!d.had_spend_secret);
        assert!(d.matches_network("signet") && d.matches_network("regtest"));
        assert!(!d.matches_network("bitcoin"));
    }

    #[test]
    fn mainnet_with_birth_height_annotation() {
        let text = format!("sp([deadbeef/352h/0h/0h]{DRONGO_SPSCAN})?bh=850000#ssufct9p");
        let d = SpDescriptor::parse(&text).unwrap();
        assert_eq!(d.scan_secret_hex(), DRONGO_SCAN);
        assert_eq!(d.spend_pubkey_hex(), DRONGO_SPEND_PUB);
        assert_eq!(d.network_kind, NetworkKind::Main);
        assert_eq!(d.birth_height, Some(850_000));

        let bare = SpDescriptor::parse(&format!("sp({SPARROW_SPSCAN})")).unwrap();
        assert_eq!(bare.scan_secret_hex(), SPARROW_SPSCAN_SCAN);
        assert_eq!(bare.spend_pubkey_hex(), SPARROW_SPSCAN_SPEND);
    }

    #[test]
    fn whitespace_and_line_breaks_are_ignored() {
        let (a, b) = DRONGO_SPSCAN.split_at(40);
        let text = format!("  sp([deadbeef/352h/0h/0h]{a}\n{b})?bh=850000#ssufct9p\n");
        assert_eq!(
            SpDescriptor::parse(&text).unwrap().birth_height,
            Some(850_000)
        );
    }

    #[test]
    fn spend_secret_form_derives_pubkey_and_flags_it() {
        let d = SpDescriptor::parse(&format!("sp({DRONGO_SPSPEND})")).unwrap();
        assert!(d.had_spend_secret);
        assert_eq!(d.scan_secret_hex(), DRONGO_SCAN);
        assert_eq!(d.spend_pubkey_hex(), DRONGO_SPEND_PUB);
        // The watch-only rendering is the spscan key Sparrow would show.
        let watch_only = d.to_watch_only_string();
        assert!(watch_only.starts_with(&format!("sp({DRONGO_SPSCAN})#")));
        let reparsed = SpDescriptor::parse(&watch_only).unwrap();
        assert!(!reparsed.had_spend_secret);
        assert_eq!(reparsed.spend_pubkey, d.spend_pubkey);
    }

    #[test]
    fn watch_only_string_round_trips_with_birth_height() {
        let d = SpDescriptor::parse(&format!("sp({SPARROW_TSPSCAN})?bh=123")).unwrap();
        let text = d.to_watch_only_string();
        assert!(text.starts_with(&format!("sp({SPARROW_TSPSCAN})?bh=123#")));
        assert_eq!(SpDescriptor::parse(&text).unwrap(), d);
    }

    #[test]
    fn two_argument_export_form() {
        let scan = SecretKey::from_slice(&hex_decode(DRONGO_SCAN).unwrap()).unwrap();
        let wif = PrivateKey::new(scan, bitcoin::Network::Bitcoin).to_wif();
        let text = format!(
            "sp([deadbeef/352h/0h/0h/1h/0]{wif},[deadbeef/352h/0h/0h/0h/0]{DRONGO_SPEND_PUB})"
        );
        let d = SpDescriptor::parse(&text).unwrap();
        assert_eq!(d.scan_secret_hex(), DRONGO_SCAN);
        assert_eq!(d.spend_pubkey_hex(), DRONGO_SPEND_PUB);
        assert_eq!(d.network_kind, NetworkKind::Main);
        assert!(!d.had_spend_secret);

        let err =
            SpDescriptor::parse(&format!("sp({DRONGO_SCAN},{DRONGO_SPEND_PUB})")).unwrap_err();
        assert!(err.contains("cannot tell the network"), "{err}");
    }

    #[test]
    fn rejects_bad_input_with_actionable_errors() {
        let cases = [
            ("", "empty"),
            (
                &format!("sp({SPARROW_TSPSCAN})#7eve6al8") as &str,
                "checksum mismatch",
            ),
            (&format!("sp({})", &SPARROW_TSPSCAN[..60]), "encoding"),
            (
                "tr([deadbeef/86h/0h/0h]xpub6...)",
                "not a Silent Payments descriptor",
            ),
            ("hello", "expected `sp(...)`"),
            ("sp(xpub661MyMwAqRbcF)", "unsupported key"),
            (&format!("sp({SPARROW_SPSCAN})?bh=abc"), "birth height"),
            (&format!("sp([deadbeef{SPARROW_SPSCAN})"), "key origin"),
        ];
        for (input, expected) in cases {
            let err = SpDescriptor::parse(input).unwrap_err();
            assert!(
                err.contains(expected),
                "{input:?}: expected `{expected}` in `{err}`"
            );
        }
    }

    #[test]
    fn debug_output_redacts_the_scan_secret() {
        let d = SpDescriptor::parse(&format!("sp({DRONGO_SPSCAN})")).unwrap();
        let debug = format!("{d:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(DRONGO_SCAN));
    }

    /// Address vectors from drongo's SilentPaymentScanAddressTest.
    #[test]
    fn sp_address_matches_sparrow_vectors() {
        let d = SpDescriptor::parse(&format!("sp({DRONGO_SPSCAN})")).unwrap();
        assert_eq!(
            d.sp_address("bitcoin"),
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
        );

        let seed = SpDescriptor {
            scan_secret: SecretKey::from_slice(
                &hex_decode("36dc57ced5f4a76059947802f094ea40d0c11c74d444a1e7d3ea5e74b8d83d45")
                    .unwrap(),
            )
            .unwrap(),
            spend_pubkey: parse_hex_pubkey(
                "03f92466aee84707997b5c596ac52a5867d5d9a4deef1338a9157218cdda9331ee",
            )
            .unwrap(),
            network_kind: NetworkKind::Test,
            birth_height: None,
            had_spend_secret: false,
        };
        assert_eq!(
            seed.sp_address("testnet"),
            "tsp1qq0grgkzt7uwfst33pyge7k9mrkag0r9vrklc695n0pw7kwwc7qddqqley3n2a6z8q7vhkhzedtzj5kr86hv6fhh0zvu2j9tjrrxa4ye3acuv6f3q"
        );
    }

    #[test]
    fn sp_address_uses_network_hrp() {
        let d = SpDescriptor::parse(&format!("sp({SPARROW_TSPSCAN})")).unwrap();
        assert!(d.sp_address("signet").starts_with("tsp1q"));
        assert!(d.sp_address("regtest").starts_with("sprt1q"));
        let main = SpDescriptor::parse(&format!("sp({SPARROW_SPSCAN})")).unwrap();
        assert!(main.sp_address("bitcoin").starts_with("sp1q"));
    }
}
