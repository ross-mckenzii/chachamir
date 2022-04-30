// ---------
// deps & crates
// ---------
// all crates are confirmed to be compatible with MIT

extern crate chacha20poly1305; // chacha20 implementation
extern crate clap; // clap (CLI parser)
extern crate path_clean; // Path clean (for absolute paths)
extern crate rand; // RNG (for key generation)
extern crate sharks; // Shamir's Secret Sharing

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

use clap::Parser;

use path_clean::PathClean;

use rand::rngs::OsRng;
use rand::RngCore;

use sharks::{ Sharks, Share };

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
    #[clap(short, long, takes_value = false, conflicts_with = "decrypt", required_unless_present = "decrypt")]
    encrypt: bool,

    // Decrypt file
    #[clap(short, long, takes_value = false, conflicts_with = "encrypt", required_unless_present = "encrypt")]
    decrypt: bool,

    /// Total number of shares to generate (max 255)
    #[clap(short, long, required_unless_present = "decrypt")]
    players: Option<u8>,

    /// Number of shares needed to reconstruct the secret (max 255; cannot be more than total)
    #[clap(short, long, required_unless_present = "decrypt")]
    threshold: Option<u8>,

    /// Path to the folder containing shares, or to write shares to (defaults to current working dir)
    #[clap(parse(from_os_str), short, long)]
    shares: Option<PathBuf>,
}

// ---------
// constants
// ---------
// version
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

fn get_paths(cli_args: Arguments) -> [PathBuf; 2] { // Returns the file for encryption and folder for shares
    // Get target file from path buffer
    let target_file = PathBuf::from(&cli_args.file);
    println!("[+] File: {}", stringify_path(&target_file) );

    // Get shares directory (default to current working dir)
    let shares_dir = match cli_args.shares {
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

    let paths: [PathBuf; 2] = [target_file, shares_dir];
    paths
}

fn read_file(filepath: &Path) -> Vec<u8> { // Raw function for reading files
    let mut contents = vec![];
    let open = fs::File::open(&filepath);

    let mut open = match open { // handle file open
        Ok(file) => file,
        Err(error) => panic!("[!] Could not open file {}! | {:?}", filepath.display(), error),
    };

    let read_result = open.read_to_end(&mut contents);

    let read_result = match read_result { // handle file read
        Ok(res) => (),
        Err(error) => panic!("[!] Could not read file {}! | {:?}", filepath.display(), error),
    };

    contents
}

fn write_file(dir: &Path, contents: &Vec<u8> ) -> PathBuf { // Raw function for writing out files
    let filepath = dir.to_owned();
    
    let mut file = fs::File::create(&filepath).unwrap();
    file.write_all(&contents).expect("oh noes!");
    
    filepath
}

fn chacha_encrypt(u8_key: Vec<u8>, u8_nonce: Vec<u8>, plaintext: &[u8] ) -> Vec<u8> { // encrypt plaintext with chacha20
    let key = Key::from_slice(&u8_key);
    let cc20 = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&u8_nonce);

    let ciphertext = cc20.encrypt(nonce, plaintext)
        .expect("Failure when encrypting file");
    
    // Decrypt the ciphertext to ensure that it works
    let chk_plaintext = cc20.decrypt(nonce, ciphertext.as_ref())
    .expect("Failure when verifying ciphertext");

    if &plaintext == &chk_plaintext { // if everything is good
        ciphertext
    } else { // oh noes
        panic!("[!] Critical error in encryption process - decrypted ciphertext does not match plaintext!");
    }
}

fn chacha_decrypt(u8_key: Vec<u8>, u8_nonce: Vec<u8>, ciphertext: &[u8] ) -> Vec<u8> { // decrypt ciphertext with chacha20
    let key = Key::from_slice(&u8_key);
    let cc20 = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&u8_nonce);
    
    // Decrypt the ciphertext
    let plaintext = cc20.decrypt(nonce, ciphertext)
    .expect("Failure when decrypting ciphertext");

    plaintext
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

    if args.encrypt { // Encryption
        println!("[*] Chose to encrypt a file...");
        
        // Dirty way of getting Option<u8> -> u8
        let player_cnt = match args.players {
            Some(val) => val,
            None => 0
        };

        let threshold = match args.threshold {
            Some(val) => val,
            None => 0
        };

        // Checking against bad things

        if player_cnt < threshold {
            println!("[!] Share threshold exceeds maximum number of players. File would be unrecoverable!");
            process::exit(1);
        } else if player_cnt < 1 {
            println!("[!] Number of shares cannot be zero");
            process::exit(1);
        } else if threshold < 1 {
            println!("[!] Threshold of shares cannot be zero");
            process::exit(1);
        }

        let paths = get_paths(args);
        let target_file = &paths[0];
        let shares_dir = &paths[1];

        // print share dir being used
        println!("[+] Storing shares at {}", stringify_path(&shares_dir) );

        // Generate 256-bit key
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        println!("[-] Key generated");

        // Generate 86-bit nonce (also used to ID files)
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        println!("[-] Nonce generated");

        // Split into shares of the secret
        let sss = Sharks(threshold); // init sharks and set threshold
        let dealer = sss.dealer(&key);

        // push all the generated shares into a vector of vectors 0_0
        let mut shares: Vec<Vec<u8>> = Vec::new();
        for s in dealer.take(<usize as From<u8>>::from(player_cnt) ) {
            
            shares.push(Vec::from(&s) );
        };

        println!("[-] Derived {} share(s) from key | threshold {}", &shares.len(), &threshold);

        
    }
    else if args.decrypt { // Decryption
        println!("[*] Chose to decrypt a file...");

        let paths = get_paths(args);
        let target_file = &paths[0];
        let shares_dir = &paths[1];

        // print share dir being used
        println!("[+] Shares folder: {}", stringify_path(&shares_dir) );


    }

    process::exit(0);
}