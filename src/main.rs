// ---------
// deps & crates
// ---------
// all crates are confirmed to be compatible with MIT
extern crate shamir; // shamir
extern crate chacha20poly1305; // chacha20

// things from the stdlib
use std::env;
use std::io;
use std::fs;
use std::str;
use std::io::prelude::*;

// pulling from our crates
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

use shamir::SecretData;

// ---------
// constants
// ---------

const VERSION_MAJOR: u8 = 0;
const VERSION_MINOR: u8 = 1;
const VERSION_PATCH: u8 = 0;

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
    println!("version {}.{}.{}", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
    println!("");
}

// ---------

fn main() {
    let args: Vec<String> = env::args().collect();
    logo(); // print logo

    let cnts = read_file(&args[1]);
    println!("{:?}", cnts);
}