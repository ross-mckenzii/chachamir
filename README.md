# chachamir

![ChaChaMir](https://codeberg.org/ross-mckenzie/chachamir/raw/commit/3cc2743ad3b40d1ab8e344ca2813448152f1e643/assets/ccm_w_text.png "ChaChaMir")

ChaCha20-based file encryption tool, utilising Shamir's Secret Sharing to distribute its key. Can optionally use ed25519 signatures to ensure integrity of encrypted files and shares.

## Usage

### Encryption

```chachamir encrypt [OPTIONS] <FILE> <PLAYERS> <THRESHOLD>```

Where `<PLAYERS>` is the total number of shares you wish to create, and `<THRESHOLD>` is the threshold number of shares needed to reconstruct the key.

#### Options

`-s <SHARE_DIR>` = The folder for shares to be saved to (this will default to your current working directory if not specified)

`--sign` = Sign individual shares and the file to be encrypted with an ed25519 keypair. This can be used to ensure integrity of each share against corruption or malicious alteration, but can result in additional computational/memory overhead.

### Decryption

```chachamir decrypt [OPTIONS] <FILE>```

File will be decrypted in the same directory as the encrypted file.

#### Options

`-s <SHARE_DIR>` = The folder containing all of your shares (this will default to your current working directory if not specified)

`--strict` = Errors relating to signature verification will force the program to stop. Without this argument, the user will usually be asked if they wish to continue.

`--all` = If this flag is not enabled, all share files must have the extension `.ccms` to be detected. With this flag, all files in the folder will be checked for validity as a share.

## Building

Requires Rust and `cargo`. [Follow these instructions for installation.](https://doc.rust-lang.org/book/ch01-01-installation.html#installation)

Then, simply `cargo build` from the project directory.

## Precautions

Ensure that you distribute your shares to players via secure channels. In my demonstrations, files have been transferred over insecure channels (emails without PGP) for ease of testing. *An attacker who can intercept >= the threshold number of shares is able to decrypt files encrypted with this tool*. Shares should be treated with the same care as you would treat any other key material.

ChaChaMir does not shred the original, unencrypted file (or any shares generated). Secure erasure is left as an exercise for the user, as the tool cannot be certain that shredding the file will actually work properly in your environment. *This is true for most secure file erasure tools which do not overwrite all free space on your disk*. See [the `shred` manpage](https://linux.die.net/man/1/shred) for more information.

## Known Issues

* The maximum file size ChaChaMir can decrypt is limited by your RAM

The ChaCha20 library used needs to be refactored to use streaming encryption/decryption. Files that are many gigabytes in size will likely fail or crash the program. For now, ChaChaMir should be used to protect other, relatively-small key material (such as keyfiles which protect, for instance, a VeraCrypt container).

## Licenses

Please see `LICENSE` and `COPYING.md` for licenses.

Additionally, `chachamir licenses` will display the software's license and the licenses of all libraries used.