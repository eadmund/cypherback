# cypherback

Cypherback is a backup system designed to be secure from the ground
up.  No private data is ever uploaded to a remote server.  The
encryption protocols follow NSA's Suite B recommendations for Top
Secret information: SHA-384 and AES-256 in either CTR or GCM.

It supports deduplication in order to reduce storage costs.

Cypherback itself contains no cryptographic code; all cryptographic
primitives are implemented in the Go language libraries.

## Keys

There are six keys in use: a 384-bit metadata storage key, a 256-bit
metadata encryption key; a 384-bit metadata authentication key; a
384-bit chunk master key; a 384-bit chunk authentication key; and a
384-bit chunk storage key.

## Secrets

A secrets file encapsulates a set of keys.  PBKDF2 is used to
generate two keys: a 256-bit AES key encryption key and a 384-bit key
authentication key.  The number of PBKDF2 iterations is tuned to take
approximately one second of wall clock time.  The keys are encrypted
in CTR mode with a random IV; a 384-bit authentication tag is
appended.

This follows NIST SP 800-38F, which specifies that keys may be stored
under an approved encryption mode and an approved authentication mode.

A secrets file is uniquely identified by
SHA-384(["cypherback", version, metadata encryption key, metadata authentication key, chunk master key, chunk authentication key, chunk storage key]),
where version equals a zero byte for this documented version.

The current secrets file format is:

        Byte Length
          0    1    File version (0 for this version)
          1   32    Salt
         33    8    Number of PBKDF2 iterations
         41   48    SHA-384([KEK, KAK])
         99   16    IV
        --------    begin AES-256-CTR
        115   32      metadata master key
        147   48      metadata authentication key
        195   48      metadata storage key
        243   32      chunk master key
        275   48      chunk authentication key
        323   48      chunk storage key
        --------    end AES-256-CTR
        371   48    HMAC-SHA-384(authentication key, bytes 0-370)

A single invoker of cypherback may control multiple secrets files, but
only one secrets file is in use at any one time; that is, no backup set
or chunk is ever common to two or more secrets files.

It's probable that many backends will store the secrets file under its
own private path.

## Backup sets

There may be multiple backup sets per secret, all sharing chunks.  Each
backup set is stored under a random 384-bit name, which has no meaning
and is normally not user-visible.

Each logical backup forms a 'backup set,' which is a set of files and
their associated metadata.  The backup set format is inspired by tar,
but with some modifications for this use case, where data is stored
separately from metadata.  Each backup set is a sequence of backup runs,
preceded by a set header.  Each backup set is identified by a tag,
defaulting to a random 384-bit value (not the same as its storage name).

Each backup run is represented by a sequence of records, starting with a
start record indicating the date and the length in bytes of the
following records, and ending with the last record.  File contents are
not stored in the backup run or backup set; rather, each regular file
record contains references to its contents.

To run a backup, first the current backup set, if any, is downloaded,
then all files which have changed since the previous backup are added to
the backup set (FIXME: add a hash of each file's data to its record to
help this?; FIXME: add deletion records, making sure to handle
add-delete-add of the same file efficiently), then their chunks are
uploaded in random order, and finally the new backup set is uploaded.

The backup set is encrypted with AES in CTR mode under a key derived
from the metadata master key and a backup set nonce, as described
below.

The metadata encryption key and IV are generated under the NIST SP
800-108 KDF in Counter Mode protocol: HMAC-SHA-384(metadata master
key,
[0x0000000000000000, "metadata encryption", 0x00, backup set nonce, 0x0000000000000180]);
the first 256 bits are the key and the following 128 bits are the IV.

The nonce MUST be regenerated if any backup set information is
rewritten (e.g. when expiring old backup sets).

The final 48 bytes of the backup set consist of HMAC-SHA-384(metadata
authentication key, [key, IV, backup set data as written]).  These
bytes are not encrypted.  The backup set MUST NOT be considered valid
unless these final 48 bytes are correct.

A property of the stream-oriented format is that a new backup run may
be appended by overwriting past the authentication tag with the new
data, then appending a new authentication tag.

### Set header

The set begins with a set header.  As noted above, the set nonce MUST
be regenerated whenever the set is changed in any way other than being
appended to.

    Byte Length
      0     1    Maximum version of the following runs
      1    48    Backup set nonce
     --------    begin AES-256-CTR
     49     4      Backup tag length
     53     -      Backup tag
      -    48      HMAC-SHA-384(metadata authentication key, [max-version, nonce, key, IV, backup tag length, backup tag)

### Record format

All backup run records share the same header:

      Byte Length
        0     1    Version (currently 0)
        1     1    Type

N.b.: all integers are unsigned unless otherwise noted.

### Start record (type 0)

      Byte Length
         2    8    Unix time in seconds when this record was written
        10    4    Length in bytes of the backup run, including start and end records

### Hard link (type 1)

The hard link does _not_ share the same header as generic files, below.
The first link to a file is written normally, but any additional links
are written as hard link records pointing to the first.

      Byte Length
        0     4    Path length
        1     -    Path
        -     4    Target path length
        -     -    Target path

### Generic file/directory header

All files and directories share this header.

      Byte Length
        2     8    Mode
       10     8    UID
       18     8    GID
       26     8    Atime
       34     8    Mtime
       42     8    Ctime
       --------    begin variable-length fields
       50     4    Path length
       54     -    Path
        -     4    Username length
        -     -    Username
        -     4    Groupname length
        -     -    Groupname

### Directory (type 2)

There are no directory-specific data.

### Regular file (type 3)

      Length
         8    File size in bytes
         4    Number of chunks
         -    Chunk addresses

### FIFO (type 4)

There are no FIFO-specific data.

### Symlink (type 5)

      Length
         4    Target path length
         -    Target path

### Char device (type 6)

      Length
         8    Rdev

### Block device (type 7)

      Length
         8    Rdev

### End-of-run (type 8)

The end-of-backup-run record consists of the SHA-384 of the plaintext data
of this entire run, from the start-of-run record to the last-but-one record.

      Byte Length
        2    48    SHA-384

## File data

A file's contents are broken up into 256K chunks (in a future version,
variable-length chunks are a possibility).  Each chunk is encrypted with
AES in CTR mode under a unique chunk encryption key & IV as indicated
below.

Each chunk has the following format:

  Byte Length
    0     1    Version (currently 0)
    1    48    Chunk nonce
   --------    begin AES-256-CTR
   49     1      Compressed-p
   50     n      Data
   --------    end AES-256-CTR
    ?    48    HMAC-SHA-384(chunk authentication key,
                            [version, chunk nonce, key, IV, length(encrypted data),
                             encrypted data])

Each chunk is stored under the name HMAC-SHA-384(chunk storage key,
chunk plaintext).

The chunk encryption key and IV are generated under the NIST SP 800-108
KDF in Counter Mode protocol: HMAC-SHA-384(chunk master key, [0x00,
"chunk encryption", 0x00, chunk nonce, 0x0180]); the first 256 bits are
the key and the following 128 bits are the IV.

# Use of Galois/Counter Mode

A future version of this protocol should convert all uses of CTR to GCM.
In each case, a 128-bit authentication tag will be written before the
384-bit HMAC; the HMAC will include the authentication tag in its
authenticated data.

# Inspiration

Cypherback is inspired by a number of projects, most notably tarsnap
and cyphertite.  Thanks are also due to Ferguson, Schneier & Kohno for
their book Cryptography Engineering.
