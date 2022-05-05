// ---------
// deps & crates
// ---------

extern crate chacha20poly1305; // chacha20 implementation
extern crate clap; // clap (CLI parser)
extern crate ed25519_dalek; // ed25519 (share integrity)
extern crate glob; // glob (for handling file directories)
extern crate hex; // Hex stuff (for using nonces as IDs)
extern crate infer; // MIME type recognition (not really necessary, just for post-decryption fun)
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

use ed25519_dalek::{Keypair, Signature, Signer, Verifier, PublicKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use glob::glob;

use path_clean::PathClean;

use rand::rngs::OsRng;
use rand::RngCore;

use sharks::{ Sharks, Share };

// -------
// CLI parsing
// -------

#[derive(Parser)]
#[clap(version, author, about)]
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

        /// Choose to sign files and shares for extra integrity (will cause additional overhead)
        #[clap(long)]
        sign: bool,
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

        /// Force shares to have valid signatures before use (only works with signed files)
        #[clap(long)]
        strict: bool
    },
    /// Print license information
    Licenses {},
}

/*----------+
| constants |
-----------*/

// package version
const VERSION: &str = env!("CARGO_PKG_VERSION");
// algorithm version (used for major changes to enc/dec algo -- added to file headers)
const ALGO_VERSION: u8 = 1;
// key length in bytes (can only be a 256-bit key for chacha20)
const KEY_LENGTH_BYTES: usize = 32;
// nonce length in bytes
const NONCE_LENGTH_BYTES: usize = 12;

struct ShareFromFile { // struct for storing info we retrieve from a share file
    threshold: u8,
    is_signed: bool,
    nonce: Vec<u8>,
    pub_key: Option<PublicKey>,
    signature: Option<Signature>,
    share_data: Share,
}

/*-----------------+
| file header crap |
-------------------*/
const HEADER_FILE: [u8; 3] = [67, 67, 77]; // "CCM"
const HEADER_SHARE: [u8; 4] = [67, 67, 77, 83]; // "CCMS"

// number of bytes before nonce in header(s)
const HEADER_PRE_NONCE_BYTES_FILE: usize = 6;
const HEADER_PRE_NONCE_BYTES_SHARE: usize = 7;

// location of the is_signed bool
const HEADER_IS_SIGNED_BYTE_FILE: usize = 6;
const HEADER_IS_SIGNED_BYTE_SHARE: usize = 7;

/* FILE HEADER STRUCTURE

Files (18 bytes w/o public key and sig)
67 67 77 VV TT SS NN NN NN NN NN NN NN NN NN NN NN NN
(32 byte public key)
(64 byte signature)
content

Shares (20 bytes w/o public key and sig)
67 67 77 83 VV TT SS NN NN NN NN NN NN NN NN NN NN NN NN 00
(32 byte public key)
(64 byte signature)
content

VV = version
TT = threshold
SS = is signed?
NN = nonce bytes
*/

// number of bytes total in header(s) before the signature or public key
const HEADER_LENGTH_FILE: usize = HEADER_FILE.len() + 1 + 1 + 1 + NONCE_LENGTH_BYTES; // 18 bytes
const HEADER_LENGTH_SHARE: usize = HEADER_SHARE.len() + 1 + 1 + 1 + NONCE_LENGTH_BYTES + 1; // 20 bytes

/*----------+
| functions |
-----------*/

fn absolute_path(path: impl AsRef<Path>) -> Result<PathBuf> { // absolute path code knicked from SO
    let path = path.as_ref();

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    }.clean();

    Ok(absolute)
}

fn strip_newline(input: &str) -> &str { // trailing newline stripper (also knicked from SO)
    input
        .strip_suffix("\r\n")
        .or(input.strip_suffix("\n"))
        .unwrap_or(input)
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

            nl();
            println!("[#] Would you like to continue,");
            println!("[#] using {} as the share directory?", stringify_path(&default_dir) );
            println!("[#] (Ctrl+C to abort; provide path to use that instead; empty for default)");

            // Wait for user confirmation
            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm).expect("[!] Critical error with input");
            
            let confirm: &str = strip_newline(&confirm[..]);

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

fn nl(){ // Newline
    println!("");
}

fn enl(){ // Newline to stderr
    eprintln!("");
}

fn fatal_error(error: &io::Error, diagnosis: String) { // Fatal error handling (read: aborting)
    nl();
    eprintln!("[!] {}", &diagnosis);
    eprintln!("[!] {}", &error.to_string() );
    nl();
    process::exit(1);
}

fn share_from_file(file: &Path, nonce: &Vec<u8>) -> Result<ShareFromFile> { // Pull shares back out of share files
    let mut share_header = read_file(&file);

    if share_header.len() < HEADER_LENGTH_SHARE { // this is clearly not a share and we will panic if we try to slice < header bytes
        return Err( Error::new( ErrorKind::Other, "Invalid share (file smaller than CCMS header)" ) )
    }

    let share_nonce = (&share_header[HEADER_PRE_NONCE_BYTES_SHARE..(HEADER_PRE_NONCE_BYTES_SHARE + NONCE_LENGTH_BYTES)]).to_vec(); // get share's nonce
    let share_threshold = share_header[HEADER_SHARE.len() + 1]; // threshold, according to this share
    let mut share_is_signed: bool = false; // is this share signed?
    let mut share_pubkey: Option<PublicKey> = None; // public key
    let mut share_signature: Option<Signature> = None; // signature

    if share_header[0..(HEADER_SHARE.len())] != HEADER_SHARE { // share is missing header
        return Err( Error::new( ErrorKind::Other, "Invalid share (CCMS header missing)" ) )
    }

    if &share_nonce == nonce { // compare share nonce to file

        // is this share signed?
        if share_header[HEADER_IS_SIGNED_BYTE_SHARE - 1] != 0 {
            share_is_signed = true;

            if share_header.len() < (HEADER_LENGTH_SHARE + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH) { 
                // this is clearly not a share and we will panic if we try to slice < header bytes
                return Err( Error::new( ErrorKind::Other, "Invalid share (file smaller than signed CCMS header)" ) )
            }

            let share_pubkey_res = PublicKey::from_bytes(&share_header[HEADER_LENGTH_SHARE..(HEADER_LENGTH_SHARE + PUBLIC_KEY_LENGTH)]);

            share_pubkey = match share_pubkey_res { // check for public key validity (ed25519 will throw if it's garbage)
                Ok(pk) => Some(pk),
                Err(error) => {
                    eprintln!("[^] Bad public key from {}", &file.display() );
                    eprintln!("[^] {}", error.to_string() );

                    return Err( Error::new( ErrorKind::Other, "Invalid share (bad public key)" ) )
                }
            };
            
            let share_signature_res = Signature::from_bytes(
                &share_header[(HEADER_LENGTH_SHARE + PUBLIC_KEY_LENGTH)..(HEADER_LENGTH_SHARE + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH)]
            );

            share_signature = match share_signature_res { // likewise for signatures
                Ok(sig) => Some(sig),
                Err(error) => {
                    eprintln!("[^] Bad signature from {}", &file.display() );
                    eprintln!("[^] {}", error.to_string() );
                    
                    return Err( Error::new( ErrorKind::Other, "Invalid share (bad signature)" ) )
                }
            };
        }

        let split_length = match share_is_signed { // change header length depending on if signed or unsigned
            false => HEADER_LENGTH_SHARE,
            true => (HEADER_LENGTH_SHARE + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH)
        };

        let share_contents: Vec<u8> = share_header.split_off(split_length); // Grab the contents from the share
        let found_share = Share::try_from(share_contents.as_slice());
        
        match found_share { // Share::try_from returns a borrowed string when it errors for some reason so we have to handle that
            Ok(sh) => {
                let share_tuple = ShareFromFile {
                    threshold: share_threshold,
                    nonce: share_nonce,
                    share_data: sh,
                    is_signed: share_is_signed,
                    pub_key: share_pubkey,
                    signature: share_signature,
                };

                Ok(share_tuple)
            },
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

    if file[0..HEADER_FILE.len()].to_vec() != HEADER_FILE { // file is missing header
        return Err( Error::new( ErrorKind::Other, "File not encrypted (CCM header missing)" ) )
    }

    // Returns full header if successful
    if file[HEADER_IS_SIGNED_BYTE_FILE] != 0 { // signed header
        Ok( file[0..HEADER_LENGTH_FILE + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH].to_vec() ) 
    }
    else { // unsigned header
        Ok( file[0..HEADER_LENGTH_FILE].to_vec() ) 
    }
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
            fatal_error(&error, format!("Could not create file {}", filepath.display()) );
            panic!("");
        }
    };

    let write_result = file.write_all(&contents);
    
    match write_result { // handle file write
        Ok(_res) => (),
        Err(error) => { // error out
            fatal_error(&error, format!("Could not write file {}", filepath.display()) );
            panic!("");
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
    let chk_plaintext = chacha_decrypt(u8_key, u8_nonce, ciphertext.as_ref()).unwrap();

    if &plaintext == &chk_plaintext { // if everything is good
        ciphertext
    } else { // oh noes
        panic!("[!] Critical error in encryption process - decrypted ciphertext does not match plaintext!");
    }
}

fn chacha_decrypt(u8_key: Vec<u8>, u8_nonce: Vec<u8>, ciphertext: &[u8] ) -> Result<Vec<u8>> { // decrypt ciphertext with chacha20
    let key = Key::from_slice(&u8_key);
    let cc20 = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&u8_nonce);
    
    // Decrypt the ciphertext
    let plaintext = match cc20.decrypt(nonce, ciphertext) {
        Ok(plain) => Ok(plain),
        Err(_error) => { // aead doesn't use a normal Error to avoid side-channel leaks
            Err( Error::new( ErrorKind::Other, "[reason obfuscated]" ) )
        } 
    };

    plaintext
}

fn construct_header_share(threshold: u8, is_signed: bool, nonce: &Vec<u8> ) -> Vec<u8> { // Construct a share header
    let mut share_header: Vec<u8> = HEADER_SHARE.to_vec(); 
    // algorithm version
    share_header.push(ALGO_VERSION);
    // threshold
    share_header.push(threshold);
    // is signed?
    if is_signed {
        share_header.push(1);
    }
    else {
        share_header.push(0);
    }

    // nonce
    share_header.extend(nonce);

    // padding
    share_header.push(0);

    return share_header
}

fn share_signature_verification(
    is_signed: bool, // whether the FILE is signed
    pub_key: Option<PublicKey>, // the FILE'S public key
    //signature: Option<Signature>, // the FILE'S signature
    shf: &ShareFromFile, // the share retrieved from a file
    path: &Path, // share path

    strict: bool ){ // verifies signatures between a file and a share

    let mut stop_user: bool = false; // set to true if we need to stop the user about share validity

    let pub_key = pub_key.unwrap();
    //let signature = signature.unwrap();

    let share_pub_key = match shf.pub_key {
        Some(pk) => pk,
        None => { // Share is missing a public key
            enl();
            eprintln!("[#] Signing mismatch from share {}", &path.display());
            eprintln!("[#] Share is missing a public key,");
            eprintln!("[#] its integrity cannot be verified.");

            die_on_strict(strict);
            stop_user = true;
            return
        }
    };

    let share_signature = match shf.signature {
        Some(pk) => pk,
        None => { // Share is missing a signature
            enl();
            eprintln!("[#] Signing mismatch from share {}", &path.display());
            eprintln!("[#] Share is missing a signature,");
            eprintln!("[#] its integrity cannot be verified.");

            die_on_strict(strict);
            stop_user = true;
            return
        }
    };

    if !is_signed && shf.is_signed { // file itself is not signed?
        enl();
        eprintln!("[#] Signing mismatch from share {}", &path.display());
        eprintln!("[#] Encrypted file is not signed,");
        eprintln!("[#] but this share believes it should be.");

        die_on_strict(strict);
        stop_user = true;
    }

    if share_pub_key.to_bytes() != pub_key.to_bytes() { // share and file use differing public keys 
        enl();
        eprintln!("[#] Signing mismatch from share {}", &path.display());
        eprintln!("[#] File and share do not use the same public key!");
        enl();
        eprintln!("[#] File public key:  {}", hex::encode( pub_key.to_bytes() ) );
        eprintln!("[#] Share public key: {}", hex::encode( share_pub_key.to_bytes() ) );

        die_on_strict(strict);
        stop_user = true;
    }

    if shf.is_signed { // Verify a share's signature
        // Reconstruct the conditions for the original share's signing
        let mut reconstructed_share = construct_header_share(shf.threshold, shf.is_signed, &shf.nonce);

        reconstructed_share.extend( share_pub_key.to_bytes() );
        reconstructed_share.extend(Vec::from(&shf.share_data) );

        let share_verification = share_pub_key.verify(&reconstructed_share, &share_signature);

        let _share_verification = match share_verification {
            Ok(v) => v,
            Err(error) => { // Share verification failed. Uh oh spaghetti-os
                enl();
                eprintln!("[#] Signing mismatch from share {}", &path.display());
                eprintln!("[#] Share verification from public key failed!");
                enl();
                eprintln!("[#] File public key:  {}", hex::encode( pub_key.to_bytes() ) );
                eprintln!("[#] Share public key: {}", hex::encode( share_pub_key.to_bytes() ) );
                enl();
                eprintln!("[#] -----------------------------------------------------" );
                eprintln!("[#] WARNING: THIS SHARE MAY BE CORRUPTED OR TAMPERED WITH" );
                eprintln!("[#]    FILE RECOVERY IS UNLIKELY WHEN USING THIS SHARE   " );
                eprintln!("[#]   ANY EXISTING FILE MAY BE OVERWRITTEN WITH GARBAGE  " );
                eprintln!("[#] -----------------------------------------------------" );
                enl();
                eprintln!("[#] More information:" );
                eprintln!("[#] {}", error.to_string() );
                die_on_strict(strict);
                stop_user = true;
            }
        };
    }

    if stop_user { // stop user if we have to
        ask_to_continue();
    }
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
    nl();
}

fn die_on_strict(is_strict: bool){ // Exit the program if a validation issue occurs with shares or files
    if is_strict {
        enl();
        eprintln!("[!] Will not decrypt using tampered data in strict mode!");
        eprintln!("[!] Aborting");
        process::exit(1);
    }
}

fn ask_to_continue(){ // Ask the user to confirm they wish to proceed (used for strict-killing errors in non-strict mode)
    eprintln!("");
    eprintln!("[#] Are you certain you wish to continue?");
    eprintln!("[#] (Ctrl+C to abort; Enter to continue)");

    // Wait for user confirmation
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).expect("[!] Critical error with input");
}

/*----------+
|   main    |
-----------*/

fn main() {
    let args = Arguments::parse();
    logo(); // print logo

    match args.command { // which command are we running?
        
        Commands::Licenses {} => { // Print license info
            let ccm_license = include_str!("../LICENSE");
            let licenses = include_str!("../COPYING.md");
            
            print!("{}",ccm_license);
            nl();
            println!("---");
            println!("Dependency licenses");
            println!("---");
            nl();
            print!("{}",licenses);
            nl();
            //println!("---");
            //nl();
        },

        Commands::Encrypt { ref file, players, threshold, share_dir, sign } => { // Encryption
            println!("[*] Chose to encrypt a file...");
            nl();

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

            // Creating a keypair doesn't cause that much overhead (benchmarked in the millisecond range)
            let mut ed25519_rng = OsRng{};
            let ed25519_keypair: Keypair = Keypair::generate( &mut ed25519_rng );
            let ed25519_bytes_pub: [u8; PUBLIC_KEY_LENGTH] = ed25519_keypair.public.to_bytes();

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
            nl();

            // --- Construct share header
            let share_header: Vec<u8> = construct_header_share(threshold, sign, &Vec::from(nonce));

            let mut share_i: i32 = 1;

            for s in shares { // iterate through shares
                println!("[&] Writing share # {}...", share_i);
                // we do not include the share number or totals as that is encoded within the share data itself,
                // so just push the universal header and the share data

                let mut this_share_path = PathBuf::from(&shares_dir);

                let share_filename: String = share_i.to_string() 
                + "-" 
                + &hex_nonce;

                this_share_path.push(share_filename);
                this_share_path.set_extension("ccms");

                let mut share_full: Vec<u8> = share_header.iter().cloned().collect();

                if sign { // are we signing shares?
                    share_full.extend(&ed25519_bytes_pub);

                    // sign the contents of the header (incl public key) + share content
                    
                    let share_signable = &mut share_full.clone();
                    share_signable.extend(&s);
                    
                    let share_ed25519_signature: Signature = ed25519_keypair.sign( &share_signable[..] );
                    // then add it to the file in between the header and contents

                    share_full.extend(&share_ed25519_signature.to_bytes() );

                    println!("[-] Signed share # {share_i}");
                }

                // write share content in
                let share_full: Vec<u8> = share_full.iter().cloned().chain(s).collect();

                write_file(&this_share_path, &share_full);
                share_i += 1;
            };
            // Done with share stuff
            nl();

            // Encrypt file
            let mut file_encrypted: Vec<u8> = chacha_encrypt(recovered_key, nonce.to_vec(), &file_plaintext);

            // --- Construct encrypted file for saving

            // header "CCM"
            let mut enc_file: Vec<u8> = HEADER_FILE.to_vec(); 

            // algorithm version
            enc_file.push(ALGO_VERSION);

            // threshold
            enc_file.push(threshold);

            // is signed?
            if sign {
                enc_file.push(1);
            }
            else {
                enc_file.push(0);
            }

            // nonce
            enc_file.extend(&nonce);

            // ----- signatures ---------------------

            if sign {
                enc_file.extend( ed25519_bytes_pub );

                let mut enc_file_signable: Vec<u8> = enc_file.clone();
                enc_file_signable.extend(&file_encrypted);

                let file_ed25519_signature: Signature = ed25519_keypair.sign( &enc_file_signable[..] );

                // add signature
                enc_file.extend(&file_ed25519_signature.to_bytes() );
                println!("[-] Signed encrypted file");

            }

            // --------------------------------------

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
            nl();
            println!("[*] Encryption complete! Have a nice day." );
        },

        Commands::Decrypt { ref file, all, share_dir, strict } => { // Decryption
            println!("[*] Chose to decrypt a file...");
            nl();

            let paths = get_paths(share_dir, file.to_owned() );
            let target_file = &paths[0];
            let shares_dir = &paths[1];

            // print share dir being used
            println!("[+] Shares directory: {}", stringify_path(&shares_dir) );

            nl();

            let (target_algo_version, mut threshold, is_signed, nonce, pub_key, signature, file_contents) = { // Process target file
                let mut target_file: Vec<u8> = read_file(&target_file);

                let target_header = match is_encrypted(&target_file) { // exit if file is not encrypted
                    Ok(head) => head, // extract header if it is
                    Err(err) => { 
                        println!("[!] Target file failed validation: {}", err.to_string() );
                        process::exit(1);
                    }
                };

                let file_algo_version: u8 = target_header[HEADER_FILE.len()]; // Algorithm version
                let file_threshold: u8 = target_header[HEADER_FILE.len() + 1]; // Threshold
                let file_nonce: Vec<u8> = (&target_header[HEADER_PRE_NONCE_BYTES_FILE..(HEADER_PRE_NONCE_BYTES_FILE + NONCE_LENGTH_BYTES)]).to_vec(); // Nonce

                let file_is_signed_u8 = target_file[HEADER_IS_SIGNED_BYTE_FILE - 1]; // is the file signed?
                let mut file_is_signed: bool = false;

                let mut file_pubkey: Option<PublicKey> = None; // public key, if it exists
                let mut file_signature: Option<Signature> = None; // signature, if it exists
                
                if file_is_signed_u8 != 0 { // Retrieve public key and signature from file
                    file_is_signed = true;

                    if target_file.len() < (HEADER_LENGTH_FILE + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH) { 
                        // this is clearly too small and we'll panic if we split on less than this
                        println!("[!] Target file failed validation: smaller than signed CCM header" );
                        process::exit(1);
                    }
        
                    let file_pubkey_res = PublicKey::from_bytes(
                        &target_header[HEADER_LENGTH_FILE..(HEADER_LENGTH_FILE + PUBLIC_KEY_LENGTH)]
                    );
        
                    file_pubkey = match file_pubkey_res {
                        Ok(pk) => Some(pk),
                        Err(error) => {
                            eprintln!("[!] Target file has a bad public key" );
                            eprintln!("[!] {}", error.to_string() );
                            
                            file_is_signed = false;
                            
                            die_on_strict(strict);
                            ask_to_continue();

                            None
                        }
                    };

                    let file_signature_res = Signature::from_bytes(
                        &target_header[(HEADER_LENGTH_FILE + PUBLIC_KEY_LENGTH)..(HEADER_LENGTH_FILE + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH)]
                    );

                    file_signature = match file_signature_res {
                        Ok(sig) => Some(sig),
                        Err(error) => {
                            eprintln!("[!] Target file has a bad signature" );
                            eprintln!("[!] {}", error.to_string() );

                            file_is_signed = false;
                            
                            die_on_strict(strict);
                            ask_to_continue();

                            None
                        }
                    };

                    if file_is_signed {
                        println!("[+] Target file is signed" );
                    }
                }
        
                let split_length = match file_is_signed { // change header length depending on if signed or unsigned
                    false => HEADER_LENGTH_FILE,
                    true => (HEADER_LENGTH_FILE + PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH)
                };

                let file_contents: Vec<u8> = target_file.split_off(split_length); // Separate contents from header

                (file_algo_version, file_threshold, file_is_signed, file_nonce, file_pubkey, file_signature, file_contents)
            };

            println!("[+] Target file is encrypted; algorithm version {}", target_algo_version.to_string() );

            nl();
            println!("[+] {} shares needed to decrypt", threshold.to_string() );
            println!("[+] Target file nonce: {}", hex::encode(&nonce) );

            nl();

            // Gather shares
            let mut shares: Vec<Share> = Vec::new();
            let glob_pattern: String;
            
            let mut path_str = stringify_path(&shares_dir).to_owned();

            if path_str.chars().last().unwrap() != '/' && path_str.chars().last().unwrap() != '\\' {
                path_str += "/" 
            }
            
            if all { // If we've set to search all files
                glob_pattern = path_str + "*"; 
            }
            else { // otherwise, only grab .ccms files
                glob_pattern = path_str + "*.ccms"; 
            } 
           
            println!("{:?}", glob_pattern);

            // horrible nesting incoming
            for file in glob(&glob_pattern).expect("[!] Failed to read share file directory. Is it invalid?") { // Push shares to vector
                match file {
                    Ok(path) => {
                        let share_f = share_from_file(&path, &nonce);

                        match share_f { // did the share grab fail?
                            Ok(shf) => {
                                println!("[%] Share retrieved from {}", &path.display());

                                if shf.threshold != threshold { // threshold mismatch (either the file or share has been tampered with)
                                    enl();
                                    eprintln!("[#] Threshold mismatch from share {}", &path.display());
                                    eprintln!("[#] File:  {}", threshold.to_string() );
                                    eprintln!("[#] Share: {}", shf.threshold.to_string() );
                                    enl();
                                    eprintln!("[#] Would you like to continue?");
                                    eprintln!("[#] If so, which threshold should we use?" );
                                    eprintln!("[#] (Ctrl+C to abort; provide threshold to use instead; empty for file's threshold)");

                                    // Wait for user confirmation
                                    let mut confirm = String::new();
                                    io::stdin().read_line(&mut confirm).expect("[!] Critical error with input");

                                    let confirm: &str = strip_newline(&confirm[..]);

                                    if confirm.is_empty() { // user gave no input
                                        eprintln!("[#] Okay. Continuing...");
                                    } else {
                                        let confirm = confirm.parse::<u8>();

                                        match confirm {
                                            Ok(number) => {
                                                threshold = number;
                                                eprintln!("[#] Using threshold of {} -- this might fail!", threshold.to_string() );
                                            },
                                            Err(err) => {
                                                eprintln!("[!] That's not a threshold number");
                                                eprintln!("[!] {}", err.to_string() );
                                                eprintln!("[!] Aborting...");
                                                process::exit(1);
                                            }
                                        };

                                    }
                                }

                                if is_signed && shf.is_signed { // file is signed, therefore more checks!
                                    share_signature_verification(is_signed, pub_key, /*signature,*/ &shf, &path, strict);
                                }

                                shares.push(shf.share_data);
                            },
                            Err(err) => eprintln!("[^] Skipping {} | {}", &path.display(), &err.to_string() )
                        }
                    },
                    Err(e) => {
                        eprintln!("[^] Reading something in share directory failed | {}", &e.to_string() );
                    },
                }
            }

            if shares.len() < 1 { // No shares to reconstruct the secret with
                println!("");
                println!("[!] Zero shares located");
                println!("[!] Cannot decrypt file with zero shares!");
                process::exit(1);
            }

            nl();

            if is_signed { // Check file signature
                let pub_key = pub_key.unwrap();
                let signature = signature.unwrap();

                // Reconstruct the conditions for the original file's signing
                // header "CCM"
                let mut reconstructed_file: Vec<u8> = HEADER_FILE.to_vec(); 
                // algorithm version
                reconstructed_file.push(target_algo_version);
                // threshold
                reconstructed_file.push(threshold);
                // file is always signed, using "1"
                reconstructed_file.push(1);
                // nonce
                reconstructed_file.extend(&nonce);
                // public key
                reconstructed_file.extend( &pub_key.to_bytes() );
                // contents
                reconstructed_file.extend(&file_contents);

                let file_verification = pub_key.verify(&reconstructed_file, &signature);

                let _file_verification = match file_verification {
                    Ok(v) => v,
                    Err(error) => { // File verification failed. Uh oh spaghetti-os
                        enl();
                        eprintln!("[#] Signing mismatch with encrypted file!");
                        eprintln!("[#] {}", &file.display());
                        eprintln!("[#] Signature verification against file's public key failed!");
                        enl();
                        eprintln!("[#] File public key:  {}", hex::encode( pub_key.to_bytes() ) );
                        enl();
                        eprintln!("[#] -----------------------------------------------------" );
                        eprintln!("[#] WARNING: THIS FILE MAY BE CORRUPTED OR TAMPERED WITH " );
                        eprintln!("[#] -----------------------------------------------------" );
                        enl();
                        eprintln!("[#] More information:" );
                        eprintln!("[#] {}", error.to_string() );

                        die_on_strict(strict);
                        ask_to_continue();
                    }
                };
            }

            // Attempt to recover key from shares
            println!("[-] Attempting key recovery with {} share(s)...", &shares.len() );

            let sss = Sharks(threshold);
            let recovered_key = match sss.recover(&shares) {
                Ok(key) => {
                    println!("[%] Recovery successful!");
                    key
                },
                Err(sss_err) => {
                    fatal_error( &Error::new(ErrorKind::Other, sss_err), "Could not recover the key from your shares!".to_string() );
                    process::exit(1);
                }
            };

            nl();
            println!("[-] Decrypting file...");

            // Decrypt file
            let file_plaintext: Vec<u8> = match chacha_decrypt(recovered_key, nonce.to_vec(), &file_contents) {
                Ok(plain) => plain,
                Err(error) => {
                    fatal_error(&error, "Failed to decrypt file!".to_string() );
                    process::exit(1);
                }
            };

            nl();

            // Try to guess MIME type cuz why not
            match infer::get(&file_plaintext){
                Some(mimetype) => {
                    println!("[-] File decrypted -- MIME type: {}", mimetype.mime_type() );
                },
                None => {
                    println!("[-] File decrypted -- MIME type: unknown (text? binary?)");
                }
            };

            nl();

            // Write out file
            let mut decrypted_path = PathBuf::from(target_file);

            let decrypted_path = match decrypted_path.extension() { // remove .ccm extension
                Some(ext) => {
                    if ext.to_str().unwrap() == "ccm" {
                        decrypted_path.set_extension("");
                        decrypted_path
                    }
                    else {
                        decrypted_path
                    }
                },
                None => decrypted_path,
            };

            write_file(Path::new(&decrypted_path), &file_plaintext);
            println!("[&] Decrypted file written to {}", stringify_path( &PathBuf::from(&decrypted_path) ) );

            // Done!
            nl();
            println!("[*] Decryption complete! Have a nice day." );
        }
    }

    process::exit(0);
}