extern crate shamir;
extern crate chacha20poly1305;

use std::io;
use std::fs::File;
use std::io::prelude::*;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

use shamir::SecretData;

fn main() {
    println!("Hello, world!");
}
