[![version](https://img.shields.io/crates/v/aegisvault.svg)](https://crates.io/crates/aegisvault)
[![build](https://github.com/pepa65/aegisvault/actions/workflows/ci.yml/badge.svg)](https://github.com/pepa65/aegisvault/actions/workflows/ci.yml)
[![dependencies](https://deps.rs/repo/github/pepa65/aegisvault/status.svg)](https://deps.rs/repo/github/pepa65/aegisvault)
[![docs](https://img.shields.io/badge/docs-aegisvault-blue.svg)](https://docs.rs/crate/aegisvault/latest)
[![license](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/pepa65/aegisvault/blob/main/LICENSE)
[![downloads](https://img.shields.io/crates/d/aegisvault.svg)](https://crates.io/crates/aegisvault)

# aegisvault 0.4.0
**Convert otpauth URI file to Encrypted Aegis vault JSON file**

* Documentation for the Aegis vault format can be found [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)
* The codebase was initially imported from [the Gnome Authenticator project](https://gitlab.gnome.org/World/Authenticator/-/blob/0.3.34747ecfd73cff50cda574e7bdbebab183ba8/src/backup/aegis.rs).
* This repo is after <https://github.com/louib/aegis-vault-rs>
* The Encrypted Aegis vault JSON files produced are Vault version 1, Database version 3.
* The included decrypt.py (decrypts an encrypted Aegis JSON file into plain JSON) is from:
  <https://github.com/beemdevelopment/Aegis/raw/refs/heads/master/docs/decrypt.py>
* The included `showdb.py` shows the JSON content of the `db` field of an encrypted Aegis JSON file.

## Documentation
Overall JSON structure for Vault version 1 (current):
```json
{
	"version": 1,
	"header": {},
	"db": {}
}
```
The `db` field stores the vault contents, either as a base64-encoded string of the encrypted content, or as an object with a `version` field, a list of `entries`, and a list of `groups` (this object gets encrypted and base64-encoded).

The JSON `header` field:
```json
{
	"slots": [
		{
			"type": 1,
			"uuid": "62141a6a-5d4c-48ef-bb06-db0c3642a0b8",
			"key": "ce586c1a4520f4c09c740dfd2878f875d18b95facbe4cc812cc31fc3e87bc68f",
			"key_params": {
				"nonce": "9bf72b47e87a165962adddc3",
				"tag": "c51ff5e48b3239e1b474f03319e42564"
			},
			"n": 32768,
			"r": 8,
			"p": 1,
			"salt": "8b115ba456d09adb0667f9a03c663846b35e71f21d24cf1abbaa1c72bd9cf89a",
			"repaired": true,
			"is_backup": false
		}
	],
	"params": {
		"nonce": "0123456789abcdef01234567",
		"tag": "0123456789abcdef0123456789abcdef"
	}
}
```

JSON `header` for unencrypted `db`:
```json
{
	"slots": null,
	"params": null
}
```

JSON `entry`:
```json
{
	"type": "totp",
	"uuid": "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d",
	"name": "Mason",
	"issuer": "Deno",
	"icon": null,
	"info": {
		"secret": "4SJHB4GSD43FZBAI7C2HLRJGPQ",
		"algo": "SHA1",
		"digits": 6,
		"period": 30
	}
}
```
If a `uuid` is not provided, it will be generated on import. Other fields in database version 4: `note` (""), `favorite` (false), `icon_mime` (null), `icon_hash` (null).

JSON `groups` (`db` version 3 onwards):
```json
[
	{
		`uuid`: "62141a5a-5d4c-48ef-bb06-db0c3642a0b8",
		`name`: "Group"
	}
]
```

## Install
### Install standalone single-binary
```sh
wget https://github.com/pepa65/aegisvault/releases/download/0.3.80/aegisvault
sudo mv aegisvault /usr/local/bin
sudo chown root:root /usr/local/bin/aegisvault
sudo chmod +x /usr/local/bin/aegisvault
```

### Install with cargo
If not installed yet, install a **Rust toolchain**, see <https://www.rust-lang.org/tools/install>

#### Direct from crates.io
`cargo install aegisvault`

#### Direct from repo
`cargo install --git https://github.com/pepa65/aegisvault`

#### Static build (avoiding GLIBC incompatibilities)
```sh
git clone https://github.com/pepa65/aegisvault
cd aegisvault
rustup target add x86_64-unknown-linux-musl
cargo rel  # Alias in .cargo/config.toml
```

The binary will be at `target/x86_64-unknown-linux-musl/release/aegisvault`

### Install with cargo-binstall
Even without a full Rust toolchain, rust binaries can be installed with the static binary `cargo-binstall`:

```sh
# Install cargo-binstall for Linux x86_64
# (Other versions are available at <https://crates.io/crates/cargo-binstall>)
wget github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz
tar xf cargo-binstall-x86_64-unknown-linux-musl.tgz
sudo chown root:root cargo-binstall
sudo mv cargo-binstall /usr/local/bin/
```

Only a linux-x86_64 (musl) binary available: `cargo-binstall aegisvault`

It will be installed in `~/.cargo/bin/` which will need to be added to `PATH`!

## Usage
```text
aegisvault 0.4.0 - Convert otpauth-URI file to Encrypted Aegis JSON on stdout
Usage: aegisvault <URI_FILE>
Arguments:
  <URI_FILE>  The otpauth-URI input

Options:
  -h, --help     Print help
  -V, --version  Print version
```

* Unencrypted otpauth-URI files consist of lines with this format (the position of the parameters can be changed):
  `otpauth://TYPE/NAME?secret=SECRET&algorithm=HMAC_ALGORITHM&digits=LENGTH&period=PERIOD&issuer=ISSUER`
  - `TYPE` can be `totp`/`hotp`/`steam`/`motp`/`yandex`.
  - `NAME` should not contain a `:` (colon) or `%` (percent), as it messes with URI encoding.
  - `SECRET` is the base32 RFC3548 seed (without the `=` padding!) for the OTPs.
  - `TYPE`, `NAME` and `SECRET` are mandatory.
  - `HMAC_ALGORITHM` is one of: `SHA1` (the default), `SHA256` or `SHA512` (or `MD5` for MOTP, with `period` 10).
  - `LENGTH` for `digits` is most often `6` (default), but can be set to `5` (for Steam), `7` (Twitch) or `8` (Microsoft).
  - `PERIOD` is almost always `30` (the default).
  - `HMAC_ALGORITHM`, `LENGTH` and `PERIOD` should be given but are optional (if not given will be set to their default values).
* The otpauth URI RFC: <https://www.ietf.org/archive/id/draft-linuxgemini-otpauth-uri-02.html>

## License
GPLv3
