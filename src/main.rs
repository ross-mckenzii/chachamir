// ---------
// deps & crates
// ---------
// all crates are confirmed to be compatible with MIT

extern crate chacha20poly1305; // chacha20 implementation
extern crate clap; // clap (CLI parser)
extern crate glob; // glob (for handling file directories)
extern crate hex; // Hex stuff (for using nonces as IDs)
extern crate path_clean; // Path clean (for absolute paths)
extern crate rand; // RNG (for key generation)
extern crate sharks; // Shamir's Secret Sharing

// things from the stdlib
use std::env;
use std::fs;
use std::io;
use std::io::{Result, Error, ErrorKind};
use std::io::{Read, Write};
use std::path::{PathBuf, Path};
use std::process;
use std::str;

// pulling from our crates
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use clap::{Parser, Subcommand};

use glob::glob;

use path_clean::PathClean;

use rand::rngs::OsRng;
use rand::RngCore;

use sharks::{ Sharks, Share };

// -------
// CLI parsing
// -------

#[derive(Parser)]
#[clap(version, about)]
/// Encrypts and decrypts files using ChaCha20 and Shamir's Secret Sharing
struct Arguments {
    /// Choose to encrypt or decrypt file
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt file
    Encrypt {
        /// Path to the file needing encryption
        #[clap(parse(from_os_str), forbid_empty_values = true)]
        file: PathBuf,

        /// Total number of shares to generate (max 255)
        players: u8,

        /// Number of shares needed to reconstruct the secret (max 255; cannot be more than total)
        threshold: u8,

        /// Path to the directory containing shares, or to write shares to (defaults to current working dir)
        #[clap(parse(from_os_str), short, long)]
        share_dir: Option<PathBuf>,
    },
    /// Decrypt file
    Decrypt {
        /// Path to the file needing decryption
        #[clap(parse(from_os_str), forbid_empty_values = true)]
        file: PathBuf,

        /// Treat all files in share directory as potential shares (not recommended)
        #[clap(short, long)]
        all: bool,

        /// Path to the directory containing shares, or to write shares to (defaults to current working dir)
        #[clap(parse(from_os_str), short, long)]
        share_dir: Option<PathBuf>,
    }
}

// ---------
// constants
// ---------
// package version
const VERSION: &str = env!("CARGO_PKG_VERSION");
// algorithm version (used for major changes to enc/dec algo -- added to file headers)
const ALGO_VERSION: u8 = 1;
// key length in bytes (can only be a 256-bit key for chacha20)
const KEY_LENGTH_BYTES: usize = 32;
// nonce length in bytes
const NONCE_LENGTH_BYTES: usize = 12;

// file header prefixes
const HEADER_FILE: [u8; 3] = [67, 67, 77]; // "CCM"
const HEADER_SHARE: [u8; 4] = [67, 67, 77, 83]; // "CCMS"

// number of bytes before nonce in header(s)
const HEADER_PRE_NONCE_BYTES_FILE: usize = 4;
const HEADER_PRE_NONCE_BYTES_SHARE: usize = 5;

// number of bytes total in header(s)
const HEADER_LENGTH_FILE: usize = 16;
const HEADER_LENGTH_SHARE: usize = 17;

// ---------
// functions
// ---------

fn absolute_path(path: impl AsRef<Path>) -> Result<PathBuf> { // absolute path code knicked from SO
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

fn get_paths(share_dir: Option<PathBuf>, target_file: PathBuf) -> [PathBuf; 2] { // Resolve the targeted file and share directory
    // Get target file from path buffer
    println!("[+] File: {}", stringify_path(&target_file) );

    let share_dir = match share_dir {
        Some(val) => PathBuf::from(val), // directory provided
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
                PathBuf::from(default_dir)
            }
        }
    };

    let paths: [PathBuf; 2] = [target_file, share_dir];
    paths
}

fn fatal_error(error: &io::Error, diagnosis: String) { // Fatal error handling (read: aborting)
    println!("");
    eprintln!("[!] {}", &diagnosis);
    eprintln!("[!] {}", &error.to_string() );
    println!("");
    process::exit(1);
}

fn share_from_file(file: &Path, nonce: &Vec<u8>) -> Result<Share> { // Pull shares back out of share files
    let mut share_header = read_file(&file);

    if share_header.len() < HEADER_LENGTH_SHARE { // this is clearly not a share and we will panic if we try to slice < header bytes
        return Err( Error::new( ErrorKind::Other, "Invalid share (file smaller than CCMS header)" ) )
    }

    let share_nonce = (&share_header[HEADER_PRE_NONCE_BYTES_SHARE..HEADER_LENGTH_SHARE]).to_vec(); // get share's nonce
    let share_contents: Vec<u8> = share_header.split_off(HEADER_LENGTH_SHARE); // Grab first 18 bytes of the share
    
    if share_header[0..(HEADER_SHARE.len() - 1)] != HEADER_SHARE { // share is missing header
        return Err( Error::new( ErrorKind::Other, "Invalid share (CCMS header missing)" ) )
    }

    if &share_nonce == nonce { // compare share nonce to file
        let found_share = Share::try_from(share_contents.as_slice());
        
        match found_share { // Share::try_from returns a borrowed string when it errors for some reason so we have to handle that
            Ok(sh) => Ok(sh),
            Err(err_string) => Err( Error::new( ErrorKind::Other, err_string ) )
        }
    }
    else {
        Err( Error::new( ErrorKind::Other, "Share does not match target file nonce" ) )
    }
}

fn is_encrypted(file: &Vec<u8>) -> Result<Vec<u8>> { // checks if the target file is encrypted; returns header if it is
    if file.len() < HEADER_LENGTH_FILE { // this is clearly not a CCM file and we will panic if we try to slice < header bytes
        return Err( Error::new( ErrorKind::Other, "File not encrypted (smaller than CCM header)" ) )
    }

    if file[0..(HEADER_FILE.len() - 1)] != HEADER_FILE { // file is missing header
        return Err( Error::new( ErrorKind::Other, "File not encrypted (CCM header missing)" ) )
    }

    Ok( file[0..(HEADER_FILE.len() - 1)].to_vec() ) // Returns header if successful
}

fn read_file(filepath: &Path) -> Vec<u8> { // Raw function for reading files
    let mut contents = vec![];
    let open = fs::File::open(&filepath);

    let mut open = match open { // handle file open
        Ok(file) => file,
        Err(error) => { // error out
            fatal_error(&error, format!("Could not open file {}", filepath.display()) );
            panic!("");
        }
    };

    let read_result = open.read_to_end(&mut contents);

    match read_result { // handle file read
        Ok(_res) => (),
        Err(error) => { // error out
            fatal_error(&error, format!("Could not read file {}", filepath.display()) );
            panic!("");
        }
    };

    contents
}

fn write_file<'a>(filepath: &'a Path, contents: &Vec<u8>) -> &'a Path { // Raw function for writing out files
    let file = fs::File::create(&filepath);

    let mut file = match file { // handle file creation
        Ok(res) => res,
        Err(error) => { // error out
            eprintln!("[!] Could not create file {}!", filepath.display());
            eprintln!("[!] {}", error.to_string());
            println!("");
            process::exit(1);
        }
    };

    let write_result = file.write_all(&contents);
    
    match write_result { // handle file write
        Ok(_res) => (),
        Err(error) => { // error out
            eprintln!("[!] Could not write file {}!", filepath.display());
            eprintln!("[!] {}", error.to_string());
            println!("");
            process::exit(1);
        }
    };

    filepath
}

fn chacha_encrypt(u8_key: Vec<u8>, u8_nonce: Vec<u8>, plaintext: &[u8] ) -> Vec<u8> { // encrypt plaintext with chacha20
    let key = Key::from_slice(&u8_key);
    let cc20 = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&u8_nonce);

    let ciphertext = cc20.encrypt(nonce, plaintext)
        .expect("Failure when encrypting file");
    
    // Decrypt the ciphertext to ensure that it works
    let chk_plaintext = chacha_decrypt(u8_key, u8_nonce, ciphertext.as_ref());

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

    match args.command { // which command are we running?
        Commands::Encrypt { ref file, players, threshold, share_dir } => { // Encryption
            println!("[*] Chose to encrypt a file...");
            println!("");

            // Take ownership of args
            let players = players.to_owned();
            let threshold = threshold.to_owned();

            // Checking against bad things
            if players < threshold {
                println!("[!] Share threshold exceeds maximum number of players. File would be unrecoverable!");
                process::exit(1);
            } else if players < 1 {
                println!("[!] Number of shares cannot be zero");
                process::exit(1);
            } else if threshold < 1 {
                println!("[!] Threshold of shares cannot be zero");
                process::exit(1);
            }

            let paths = get_paths(share_dir, file.to_owned() );
            let target_file = &paths[0];
            let shares_dir = &paths[1];

            // print share dir being used
            println!("[+] Storing shares at {}", stringify_path(&shares_dir) );

            // Generate 256-bit key
            let mut key = [0u8; KEY_LENGTH_BYTES];
            OsRng.fill_bytes(&mut key);
            println!("[-] Key generated");

            // Generate 86-bit nonce (also used to ID files)
            let mut nonce = [0u8; NONCE_LENGTH_BYTES];
            OsRng.fill_bytes(&mut nonce);
            println!("[-] Nonce generated");

            let hex_nonce = hex::encode(nonce); // hex representation of the nonce

            // Split into shares of the secret
            let sss = Sharks(threshold); // init sharks and set threshold
            let dealer = sss.dealer(&key);

            // push all the generated shares into a 2d vector
            let mut shares: Vec<Vec<u8>> = Vec::new();

            for s in dealer.take(<usize as From<u8>>::from(players) ) {
                shares.push(Vec::from(&s) );
            };

            println!("[-] Derived {} share(s) from key | threshold {}", &shares.len(), &threshold);

            // Recover the shares again for good measure
            let recovered_shares: Vec<Share> = shares.iter().map(|s| Share::try_from(s.as_slice()).unwrap()).collect();
            let recovered_key = sss.recover(&recovered_shares).unwrap(); // REMINDER: this is a Result, handle this later
            
            if recovered_key != key { // handle unrecoverable shares (should never happen?)
                panic!("[!] Unable to recover the key from our shares?!");
            }

            println!("[-] Share recovery succeeded");

            // read plaintext file to make sure we aren't saving useless shares if this fails
            let file_plaintext: Vec<u8> = read_file(&target_file);

            // Save shares to folder
            println!("");
            // --- Construct share header(s)
            // header "CCMS"
            let mut share_header: Vec<u8> = HEADER_SHARE.to_vec(); 
            // algorithm version
            share_header.push(ALGO_VERSION);
            // nonce
            share_header.extend(&nonce);
            // padding byte
            share_header.push(0);

            let mut share_i: u8 = 1;
            for s in shares {
                println!("[&] Writing share # {}...", share_i);
                // we do not include the share number or totals as that is encoded within the share data itself,
                // so just push the universal header and the share data

                let mut this_share_path = PathBuf::from(&shares_dir);

                let share_filename: String = share_i.to_string() 
                + "-" 
                + &hex_nonce;

                this_share_path.set_file_name(share_filename);
                this_share_path.set_extension("ccms");

                let share_full: Vec<u8> = share_header.iter().cloned().chain(s).collect();

                write_file(&this_share_path, &share_full);
                share_i += 1;
            };
            // Done with share stuff

            // Encrypt file
            let mut file_encrypted: Vec<u8> = chacha_encrypt(recovered_key, nonce.to_vec(), &file_plaintext);

            // --- Construct encrypted file for saving
            // header "CCM"
            let mut enc_file: Vec<u8> = HEADER_FILE.to_vec(); 
            // algorithm version
            enc_file.push(ALGO_VERSION);
            // nonce
            enc_file.extend(&nonce);
            // encrypted file contents
            enc_file.append(&mut file_encrypted);

            // Save to file
            let mut target_enc_file = PathBuf::from(&target_file);

            match target_enc_file.extension() { // add .ccm extension
                Some(ext) => {
                    let mut ext = ext.to_os_string();
                    ext.push(".ccm");
                    target_enc_file.set_extension(ext)
                }
                None => target_enc_file.set_extension(".ccm"),
            };

            write_file(&target_enc_file, &enc_file);
            println!("[&] Encrypted file written to {}", stringify_path(&target_enc_file) );

            // Done!
            println!("");
            println!("[*] Encryption complete! Have a nice day." );
        },

        Commands::Decrypt { ref file, all, share_dir } => { // Decryption
            println!("[*] Chose to decrypt a file...");
            println!("");

            let paths = get_paths(share_dir, file.to_owned() );
            let mut target_file = &paths[0];
            let shares_dir = &paths[1];

            // print share dir being used
            println!("[+] Shares directory: {}", stringify_path(&shares_dir) );

            // Process target file
            let mut target_file: Vec<u8> = read_file(&target_file);

            let target_header = match is_encrypted(&target_file) { // exit if file is not encrypted
                Ok(head) => head, // extract header if it is
                Err(err) => { 
                    println!("[!] Target file failed validation: {}", err.to_string() );
                    process::exit(1);
                }
            };

            let nonce: Vec<u8> = (&target_header[HEADER_PRE_NONCE_BYTES_FILE..HEADER_LENGTH_FILE]).to_vec(); // Nonce
            let file_contents: Vec<u8> = target_file.split_off(HEADER_LENGTH_FILE); // Separate contents from header

            println!("[+] Target file nonce: {}", hex::encode(&nonce) );

            // Gather shares
            let mut shares: Vec<Share> = Vec::new();
            let glob_pattern: String;
            
            if all { // If we've set to search all files
                glob_pattern = "*".to_string();
            }
            else {
                glob_pattern = stringify_path(&shares_dir).to_owned() + "*.ccms"; 
            } 
            
            for file in glob(&glob_pattern).expect("[!] Failed to read share file directory. Is it invalid?") {
                match file {
                    Ok(path) => {
                        let share_f = share_from_file(&path, &nonce);

                        match share_f {
                            Ok(shf) => {
                                println!("[%] Share retrieved from {}", &path.display());
                                shares.push(shf);
                            },
                            Err(err) => eprintln!("[^] Skipping {} | {}", &path.display(), &err.to_string() )
                        }
                    },
                    Err(e) => {
                        eprintln!("[^] Reading something in share directory failed | {}", &e.to_string() );
                    },
                }
            }

            // Attempt to recover key from shares



            // Decrypt file

            // Done!
        }
    }

    process::exit(0);
}