use std::error::Error;
use std::fmt;
use std::io::{self, Write};

use clap::{App, AppSettings, Arg};
use rayon::prelude::*;
use wireguard_vanity_lib::{measure_rate, search_re};
use x25519_dalek::{PublicKey, StaticSecret};
use regex::RegexBuilder;

fn format_rate(rate: f64) -> String {
    if rate > 1e9 {
        format!("{:.2}e9 keys/s", rate / 1e9)
    } else if rate > 1e6 {
        format!("{:.2}e6 keys/s", rate / 1e6)
    } else if rate > 1e3 {
        format!("{:.2}e3 keys/s", rate / 1e3)
    } else if rate > 1e0 {
        format!("{:.2} keys/s", rate)
    } else if rate > 1e-3 {
        format!("{:.2}e-3 keys/s", rate * 1e3)
    } else if rate > 1e-6 {
        format!("{:.2}e-6 keys/s", rate * 1e6)
    } else if rate > 1e-9 {
        format!("{:.2}e-9 keys/s", rate * 1e9)
    } else {
        format!("{:.3}e-12 keys/s", rate * 1e12)
    }
}

fn print(res: (StaticSecret, PublicKey)) -> Result<(), io::Error> {
    let private: StaticSecret = res.0;
    let public: PublicKey = res.1;
    let private_b64 = base64::encode(&private.to_bytes());
    let public_b64 = base64::encode(public.as_bytes());
    writeln!(
        io::stdout(),
        "public {}  private {}",
        &public_b64,
        &private_b64,
    )
}

#[derive(Debug)]
struct ParseError(String);
impl Error for ParseError {}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("wireguard-vanity-address")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("0.3.1")
        .author("Brian Warner <warner@lothar.com>")
        .about("finds Wireguard keypairs matching a given regex")
        .arg(
            Arg::with_name("RE")
                .required(true)
                .help("regex to match with"),
        )
        .get_matches();
    let re = RegexBuilder::new(matches.value_of("RE").unwrap())
        .unicode(false).build().unwrap();
    let raw_rate = measure_rate(&re);
    eprintln!("rate: {}", format_rate(raw_rate));
    (0..i64::MAX)
        .into_par_iter()
        .map(|_| search_re(&re))
        .try_for_each(print)?;
    Ok(())
}
