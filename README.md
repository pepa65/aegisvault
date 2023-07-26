# aegis-vault-rs
[![Build Status](https://github.com/louib/aegis-vault-rs/actions/workflows/merge.yml/badge.svg?branch=main)](https://github.com/louib/aegis-vault-rs/actions/workflows/merge.yml)
[![dependency status](https://deps.rs/repo/github/louib/aegis-vault-rs/status.svg)](https://deps.rs/repo/github/louib/aegis-vault-rs)
[![Crates.io](https://img.shields.io/crates/v/aegis-vault.svg)](https://crates.io/crates/aegis-vault)
[![License file](https://img.shields.io/github/license/louib/aegis-vault-rs)](https://github.com/louib/aegis-vault-rs/blob/main/LICENSE)

Library for parsing and dumping Aegis vaults

Documentation for the Aegis vault format can be found [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)

The codebase was initially imported from [the Gnome Authenticator project](https://gitlab.gnome.org/World/Authenticator/-/blob/03381747ecfd73cff50cda574e7bdbebab183ba8/src/backup/aegis.rs).

## Usage
### Save a database
```rust
use aegis_vault::{
    vault::{Aegis, Entry},
    algorithm::{Method}
};
use anyhow::Result;
use std::fs::File;

fn main() -> Result<()> {
    let mut vault = Aegis::default();

    let mut otp_entry = Entry::default();
    otp_entry.method = Method::TOTP;
    otp_entry.label = "Mason".to_string();
    otp_entry.issuer = Some("Deno".to_string());
    otp_entry.info.secret = "4SJHB4GSD43FZBAI7C2HLRJGPQ".to_string();
    otp_entry.info.period = Some(30);
    otp_entry.info.digits = 6;
    otp_entry.info.counter = None;
    vault.add_entry(otp_entry);

    vault.save(
      &mut File::create("my-aegis-vault.json")?,
      "password",
    )?;

    Ok(())
}
```
### Open a database
TODO

## License

GPL-3
