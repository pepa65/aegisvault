use aegisvault::{
	algorithm::{Algorithm, Method},
	vault::{Aegis, Entry},
};
use anyhow::Result;
use clap::Parser;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use rpassword::read_password;
use serde_json::ser::to_string_pretty;
use std::borrow::Cow::Borrowed;
use std::io::{Write, stdout};
use url::Url;
use urlencoding::decode;

// Cargo's color style: https://github.com/crate-ci/clap-cargo/blob/master/src/style.rs
const STYLE: Styles = Styles::styled()
	.header(AnsiColor::Green.on_default().effects(Effects::BOLD))
	.usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
	.literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
	.placeholder(AnsiColor::Cyan.on_default())
	.error(AnsiColor::Red.on_default().effects(Effects::BOLD))
	.valid(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
	.invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD));

#[derive(Parser, Debug)]
#[clap(version, about, styles = STYLE, help_template(
	"\
{before-help}{name} {version} - {about}
{usage-heading} {usage}
{all-args}{after-help}
"
))]
struct Cli {
	/// The otpauth-URI inputfile
	uri_file: std::path::PathBuf,
}

fn main() -> Result<()> {
	let arg = Cli::parse();
	eprint!("Password to be set on the Encrypted Aegis JSON output file: ");
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
