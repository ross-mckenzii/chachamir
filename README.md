# chachamir

![ChaChaMir](https://ross.exposed/img/ccm_w_text.png "ChaChaMir")

ChaCha20-based file encryption tool, utilising Shamir's Secret Sharing to distribute its key.

## Usage

### Encryption

`chachamir encrypt [OPTIONS] <FILE> <PLAYERS> <THRESHOLD>`

Where `<PLAYERS>` is the total number of shares you wish to create, and `<THRESHOLD>` is the threshold number of shares needed to reconstruct the key.

#### Options

`-s <SHARE_DIR>` = The folder for shares to be saved to (this will default to your current working directory if not specified)

### Decryption

`chachamir decrypt [OPTIONS] <FILE>`

File will be decrypted in the same directory as the encrypted file.

#### Options

`-s <SHARE_DIR>` = The folder containing all of your shares (this will default to your current working directory if not specified)

`--all` = If this flag is not enabled, all share files must have the extension `.ccms` to be detected. With this flag, all files in the folder will be checked for validity as a share.

## Building

Requires Rust and `cargo`. [Follow these instructions for installation.](https://doc.rust-lang.org/book/ch01-01-installation.html#installation)

Then, simply `cargo build` from the project directory.

## Precautions

Ensure that you distribute your shares to players via secure channels. In my demonstrations, files have been transferred over insecure channels (emails without PGP) for ease of testing. *An attacker who can intercept >= the threshold number of shares is able to decrypt files encrypted with this tool*. Shares should be treated with the same care as you would treat any other key material.

ChaChaMir does not shred the original, unencrypted file (or any shares generated). Secure erasure is left as an exercise for the user, as the tool cannot be certain that shredding the file will actually work properly in your environment. *This is true for most secure file erasure tools which do not overwrite all free space on your disk*. Verbatim from [the `shred` manpage](https://linux.die.net/man/1/shred):

```
Note that shred relies on a very important assumption: that the file system overwrites data in place. This is the traditional way to do things, but many modern file system designs do not satisfy this assumption. The following are examples of file systems on which shred is not effective, or is not guaranteed to be effective in all file system modes:

* log-structured or journaled file systems, such as those supplied with AIX and Solaris (and JFS, ReiserFS, XFS, Ext3, etc.)

* file systems that write redundant data and carry on even if some writes fail, such as RAID-based file systems

* file systems that make snapshots, such as Network Appliance's NFS server

* file systems that cache in temporary locations, such as NFS version 3 clients

* compressed file systems

In the case of ext3 file systems, the above disclaimer applies (and shred is thus of limited effectiveness) only in data=journal mode, which journals file data in addition to just metadata. In both the data=ordered (default) and data=writeback modes, shred works as usual. Ext3 journaling modes can be changed by adding the data=something option to the mount options for a particular file system in the /etc/fstab file, as documented in the mount man page (man mount).

In addition, file system backups and remote mirrors may contain copies of the file that cannot be removed, and that will allow a shredded file to be recovered later. 
```

## Known Issues

* There is currently no protection against malicious share holders modifying their shares to modify the retrieved secret.
* Likewise, there is currently no protection against corruption of shares.

These could be mitigated by adding a signature to both shares and files, allowing both share holders and the file holder to verify that neither the file nor shares have been tampered with. This is a planned feature of ChaChaMir for some point in the future.

## Licenses

Please see `LICENSE` and `COPYING.md` for licenses.