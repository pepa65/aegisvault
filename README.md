[![version](https://img.shields.io/crates/v/aegisvault.svg)](https://crates.io/crates/aegisvault)
[![build](https://github.com/pepa65/aegisvault/actions/workflows/ci.yml/badge.svg)](https://github.com/pepa65/aegisvault/actions/workflows/ci.yml)
[![dependencies](https://deps.rs/repo/github/pepa65/aegisvault/status.svg)](https://deps.rs/repo/github/pepa65/aegisvault)
[![docs](https://img.shields.io/badge/docs-aegisvault-blue.svg)](https://docs.rs/crate/aegisvault/latest)
[![license](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/pepa65/aegisvault/blob/main/LICENSE)
[![downloads](https://img.shields.io/crates/d/aegisvault.svg)](https://crates.io/crates/aegisvault)

# aegisvault 0.3.62
**Convert otpauth URI file to Encrypted Aegis vault JSON file**

* Documentation for the Aegis vault format can be found [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)
* The codebase was initially imported from [the Gnome Authenticator project](https://gitlab.gnome.org/World/Authenticator/-/blob/0.3.34747ecfd73cff50cda574e7bdbebab183ba8/src/backup/aegis.rs).
* This repo is after <https://github.com/louib/aegis-vault-rs>
* The Encrypted Aegis vault JSON files produced are Vault version 1, Database version 2.
  (Database version 3 is used too, but importing version 2 is still supported.)
* The included decrypt.py is from:
  <https://github.com/beemdevelopment/Aegis/raw/refs/heads/master/docs/decrypt.py>

## Install
### Install standalone single-binary
```sh
wget https://github.com/pepa65/argisvault/releases/download/0.3.62/aegisvault
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
aegisvault 0.3.62 - Convert otpauth URI file to Encrypted Aegis vault JSON on stdout
Usage: aegisvault <URI_FILE>
Arguments:
  <URI_FILE>  The otpauth URI inputfile

Options:
  -h, --help     Print help
  -V, --version  Print version
```

* Unencrypted otpauth URI files consist of lines with this format:
  `otpauth://TYPE/NAME?secret=SECRET&algorithm=HMAC_ALGORITHM&digits=LENGTH&period=PERIOD&issuer=ISSUER`
  - `TYPE` can be `totp`/`hotp`/`steam`/`motp`/`yandex`.
  - `NAME` should not contain a `:` (colon) or `%` (percent), as it messes with URI encoding.
  - `SECRET` is the base32 RFC3548 seed (without the `=` padding!) for the OTPs.
  - `TYPE`, `NAME` and `SECRET` are mandatory.
  - `HMAC_ALGORITHM` is one of: `SHA1` (the default), `SHA256` or `SHA512`.
  - `LENGTH` for `digits` is most often `6` (default), but can be set to `5` (for Steam), `7` (Twitch) or `8` (Microsoft).
  - `PERIOD` is almost always `30` (the default).
  - `HMAC_ALGORITHM`, `LENGTH` and `PERIOD` should be given but are optional,
    and will be set to their respective default values.
* The otpauth URI RFC: <https://www.ietf.org/archive/id/draft-linuxgemini-otpauth-uri-01.html>

## License
GPLv3
