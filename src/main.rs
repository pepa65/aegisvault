use aegisvault::{algorithm::{Algorithm, Method}, vault::{Aegis, Entry}};
use anyhow::Result;
use clap::Parser;
use rpassword::read_password;
use serde_json::ser::to_string_pretty;
use std::borrow::Cow::Borrowed;
use std::io::{stdout, Write};
use url::Url;
use urlencoding::decode;

#[derive(Parser, Debug)]
#[command(version, about)]
#[command(help_template(
  "\
{before-help}{name} {version} - {about}
{usage-heading} {usage}
{all-args}{after-help}
"
))]
struct Cli {
	#[clap(help = "The otpauth URI inputfile")]
	uri_file: std::path::PathBuf,
}

fn main() -> Result<()> {
	let arg = Cli::parse();
	eprint!("Password to be set on the Encrypted Aegis vault JSON output: ");
	stdout().flush().unwrap();
  let password = read_password().unwrap();
	let mut vault = Aegis::default();
	let file = std::fs::read_to_string(arg.uri_file).unwrap();
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
			_ => panic!("Unknown otpauth URI type"),
		};
		otp.label = decode(label).unwrap().to_string();
		let q = uri.query_pairs().collect::<Vec<_>>();
		for (key, val) in q.iter() {
			match key.clone() {
				Borrowed("secret") => otp.info.secret = val.to_string(),
				Borrowed("algorithm") => {
					otp.info.algorithm = match val.as_ref() {
						"SHA1" => Algorithm::SHA1,
						"SHA256" => Algorithm::SHA256,
						"SHA512" => Algorithm::SHA512,
						_ => panic!("Unknown HMAC algorithm"),
					}
				}
				Borrowed("digits") => otp.info.digits = val.parse::<u32>().unwrap(),
				Borrowed("period") => otp.info.period = Some(val.parse::<u32>().unwrap()),
				Borrowed("issuer") => otp.issuer = Some(decode(val).unwrap().to_string()),
				_ => panic!("Unknown key: {key}"),
			};
		}
		otp.info.counter = None;
		vault.add_entry(otp);
	}

	//vault.save(&mut File::create(OUTPUTFILE)?, &password)?;
	vault.encrypt(&password).unwrap();
	let raw_encrypted_vault = to_string_pretty(&vault).unwrap();
	println!("{raw_encrypted_vault}");
	Ok(())
}
