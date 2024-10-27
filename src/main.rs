use aegisvault::{
	algorithm::{Algorithm, Method},
	vault::{Aegis, Entry},
};
use anyhow::Result;
use std::fs::File;
use url::Url;
use urlencoding::decode;

const URI_IN: &str = "twofat.uri";
const JSON_OUT: &str = "aegis.json";
const PASSWORD: &str = "password";

fn main() -> Result<()> {
	let mut vault = Aegis::default();
	let file = std::fs::read_to_string(URI_IN).unwrap();
	for line in file.lines() {
		let mut otp = Entry::default();
		let uri = Url::parse(line).unwrap_or_else(|e| panic!("{e}"));
		let scheme = uri.scheme();
		assert!(scheme == "otpauth");
		let method = uri.host_str().ok_or_else(|| panic!("host_str error")).unwrap();
		let label = &uri.path().to_string()[1..];
		otp.method = match method {
			"totp" => Method::TOTP,
			"hotp" => Method::HOTP,
			"steam" => Method::Steam,
			"motp" => Method::Motp,
			"yandex" => Method::Yandex,
			_ => panic!("Unknown type"),
		};
		otp.label = decode(label).unwrap().to_string();
		let q = uri.query_pairs().collect::<Vec<_>>();
		for (key, val) in q.iter() {
			match key.to_owned() {
				std::borrow::Cow::Borrowed("secret") => otp.info.secret = val.to_string(),
				std::borrow::Cow::Borrowed("algorithm") => {
					otp.info.algorithm = match val.as_ref() {
						"SHA1" => Algorithm::SHA1,
						"SHA256" => Algorithm::SHA256,
						"SHA512" => Algorithm::SHA512,
						_ => panic!("Unknown HMAC algorithm"),
					}
				}
				std::borrow::Cow::Borrowed("digits") => otp.info.digits = val.parse::<u32>().unwrap(),
				std::borrow::Cow::Borrowed("period") => otp.info.period = Some(val.parse::<u32>().unwrap()),
				std::borrow::Cow::Borrowed("issuer") => otp.issuer = Some(decode(val).unwrap().to_string()),
				_ => panic!("Unknown key: {key}"),
			};
		}
		otp.info.counter = None;
		vault.add_entry(otp);
	}

	//let raw_unencrypted_vault = serde_json::ser::to_string_pretty(&vault).unwrap();
	//println!("{}", raw_unencrypted_vault);
	vault.save(&mut File::create(JSON_OUT)?, PASSWORD)?;

	//vault.encrypt(PASSWORD).unwrap();
	//let raw_encrypted_vault = serde_json::ser::to_string_pretty(&vault).unwrap();

	Ok(())
}
