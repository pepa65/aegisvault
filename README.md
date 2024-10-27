# aegisvault
[![Build Status](https://github.com/pepa65/aegisvault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/pepa65/aegisvault/actions/workflows/ci.yml)
[![dependency status](https://deps.rs/repo/github/pepa65/aegisvault/status.svg)](https://deps.rs/repo/github/pepa65/aegisvault)
<!--[![Crates.io](https://img.shields.io/crates/v/aegisvault.svg)](https://crates.io/crates/aegisvault)-->
[![License file](https://img.shields.io/github/license/pepa65/aegisvault)](https://github.com/pepa65/aegisvault/blob/main/LICENSE)

**Convert otpauth URI file to Encrypted Aegis vault JSON file**

* Documentation for the Aegis vault format can be found [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)
* The codebase was initially imported from [the Gnome Authenticator project](https://gitlab.gnome.org/World/Authenticator/-/blob/03381747ecfd73cff50cda574e7bdbebab183ba8/src/backup/aegis.rs).
* This repo is after https://github.com/louib/aegis-vault-rs
* The Encrypted Aegis vault JSON files produced are Vault version 1, Database version 2.
  (Database version 3 is used too, but importing version 2 is still supported.)

## Usage
* Clone the repo: `git clone https://github.com/pepa65/aegisvault`
* Do `cd aegisvault`
* Edit `src/main.rs`:
  - Adjust the constant `URI_IN` for the (unencrypted) otpauth URI inputfile.
  - Adjust the constant `JSON_OUT` for the Encrypted Aegis Vault JSON outputfile.
  - Adjust the constant `PASSWORD` for the password to be set on the outputfile.
* Execute: `cargo run` in the repo's root directory.

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
* The otpauth URI RFC: https://www.ietf.org/archive/id/draft-linuxgemini-otpauth-uri-01.html

## License
GPLv3
