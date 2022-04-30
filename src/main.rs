// ---------
// deps & crates
// ---------
// all crates are confirmed to be compatible with MIT
extern crate shamir; // shamir
extern crate chacha20poly1305; // chacha20
extern crate clap; // clap (CLI parser)

// things from the stdlib
use std::env;
use std::io;
use std::fs;
use std::path;
use std::str;
use std::io::prelude::*;

// pulling from our crates
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

use shamir::SecretData;

use clap::Parser;

// -------
// CLI parsing
// -------

#[derive(Parser, Debug)]
#[clap(version, about)]
/// Encrypts and decrypts files using ChaCha20 and Shamir's Secret Sharing
struct Arguments {

    /// Path to the file needing encryption/decryption
    #[clap(parse(from_os_str), forbid_empty_values = true)]
    file: path::PathBuf,

    // Encrypt file
    #[clap(short, long, takes_value = false)]
    encrypt: bool,

    // Decrypt file
    #[clap(short, long, takes_value = false)]
    decrypt: bool,

    /// Path to the folder containing shares, or to write shares to (defaults to current working dir)
    #[clap(parse(from_os_str), short)]
    shares: Option<path::PathBuf>,
}

// ---------
// constants
// ---------
const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------
// functions
// ---------

fn read_file(filename: &String) -> Vec<u8> { // Raw function for reading files
    let contents = fs::read(filename)
        .expect("Error reading file -- does it exist?");
    
    return contents;
}

fn write_file(filename: &String, contents: &Vec<u8> ) -> std::io::Result<()> { // Raw function for writing out files
    let mut file = fs::File::create(filename)?;
    file.write_all(&contents)?;
    Ok(())
}

fn logo(){ // prints CCM logo
    //   ___  _  _   __    ___  _  _   __   _  _  __  ____ 
    //  / __)/ )( \ / _\  / __)/ )( \ / _\ ( \/ )(  )(  _ \
    // ( (__ ) __ (/    \( (__ ) __ (/    \/ \/ \ )(  )   /
    //  \___)\_)(_/\_/\_/ \___)\_)(_/\_/\_/\_)(_/(__)(__\_)

    println!("  ___  _  _   __    ___  _  _   __   _  _  __  ____ ");
    println!(" / __)/ )( \\ / _\\  / __)/ )( \\ / _\\ ( \\/ )(  )(  _ \\");
    println!("( (__ ) __ (/    \\( (__ ) __ (/    \\/ \\/ \\ )(  )   /");
    println!(" \\___)\\_)(_/\\_/\\_/ \\___)\\_)(_/\\_/\\_/\\_)(_/(__)(__\\_)");
    println!("----");
    println!("version {}", VERSION);
    println!("");
}


// ---------

fn main() {
    let args = Arguments::parse();
    logo(); // print logo

    println!("{:?}", args);
}