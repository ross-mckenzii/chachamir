// ---------
// deps & crates
// ---------
// all crates are confirmed to be compatible with MIT

extern crate chacha20poly1305; // chacha20 implementation
extern crate clap; // clap (CLI parser)
extern crate path_clean; // Path clean (for absolute paths)
extern crate shamir; // shamir

// things from the stdlib
use std::env;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path::{PathBuf, Path};
use std::process;
use std::str;

// pulling from our crates
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use shamir::SecretData;

use clap::Parser;

use path_clean::PathClean;

// -------
// CLI parsing
// -------

#[derive(Parser, Debug)]
#[clap(version, about)]
/// Encrypts and decrypts files using ChaCha20 and Shamir's Secret Sharing
struct Arguments {

    /// Path to the file needing encryption/decryption
    #[clap(parse(from_os_str), forbid_empty_values = true)]
    file: PathBuf,

    // Encrypt file
    #[clap(short, long, takes_value = false)]
    encrypt: bool,

    // Decrypt file
    #[clap(short, long, takes_value = false)]
    decrypt: bool,

    /// Total number of shares to generate (max 65,535)
    #[clap(short, long)]
    players: Option<u16>,

    /// Number of shares needed to reconstruct the secret (max 65,535; cannot be more than total)
    #[clap(short, long)]
    threshold: Option<u16>,

    /// Path to the folder containing shares, or to write shares to (defaults to current working dir)
    #[clap(parse(from_os_str), short)]
    shares: Option<PathBuf>,
}

// ---------
// constants
// ---------
const VERSION: &str = env!("CARGO_PKG_VERSION");

// file header prefixes
const HEADER_FILE: [u8; 4] = [67, 67, 77, 0]; // "CCM[null]"
const HEADER_SHARE: [u8; 5] = [67, 67, 77, 83, 0]; // "CCMS[null]"

// ---------
// functions
// ---------

fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> { // absolute path code knicked from SO
    let path = path.as_ref();

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    }.clean();

    Ok(absolute)
}

fn stringify_path(path: &PathBuf) -> String { // turn path into string for printing
    let str_path = absolute_path(path).unwrap().into_os_string().into_string().unwrap();
    str_path
}

fn read_file(filepath: &Path) -> Vec<u8> { // Raw function for reading files
    let mut contents = vec![];
    fs::File::open(&filepath).unwrap().read_to_end(&mut contents);
    
    contents
}

fn write_file(dir: &Path, filename: &str, contents: &Vec<u8> ) -> PathBuf { // Raw function for writing out files
    let mut filepath = dir.to_owned();
    filepath.push(filename);
    
    let mut file = fs::File::create(filename).unwrap();
    file.write_all(&contents).expect("oh noes!");
    
    filepath
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

    if args.encrypt && args.decrypt { // attempting to encrypt and decrypt at the same time
        eprintln!("[!] Cannot encrypt and decrypt a file at the same time!");
        process::exit(1);
    }
    else if args.encrypt { // Encryption
        println!("[*] Chose to encrypt a file...");
        
        // Get target file from path buffer
        let target_file = PathBuf::from(&args.file );
        println!("[+] File: {}", stringify_path(&target_file) );

        // Get shares directory (default to current working dir)
        let mut shares_dir = match args.shares {
            Some(val) => val, // directory provided
            None => { // default to working dir
                println!("[+] Shares directory not provided... using current working directory");
                let default_dir = env::current_dir().unwrap();

                println!("");
                println!("[#] Would you like to continue,");
                println!("[#] using {} as the share directory?", stringify_path(&default_dir) );
                println!("[#] (Ctrl+C to abort; provide path to use that instead; empty for default)");

                // Wait for user confirmation
                let mut confirm = String::new();
                io::stdin().read_line(&mut confirm).expect("[!] Critical error with input");
                
                if !confirm.is_empty() {
                    PathBuf::from(confirm)
                } else {
                    default_dir
                }
                
            }
        };

        // print share dir being used
        println!("[+] Storing shares at {}", absolute_path(shares_dir).unwrap().into_os_string().into_string().unwrap() );
    }
    else if args.decrypt { // Decryption
        println!("[*] Chose to decrypt a file...");
    }
    else {
        println!("[#] You must choose to either encrypt or decrypt a file");
        println!("[#] Encrypt with flag -e or --encrypt");
        println!("[#] Decrypt with flag -d or --decrypt");
        process::exit(0);
    }

    process::exit(0);
}