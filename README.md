cypherback
==========

Cypherback is a backup system designed to be secure from the ground
up.  No private data is ever uploaded to a remote server.  The
encryption protocols follow NSA's Suite B recommendations for Top
Secret information: SHA-384 and AES-256 in either CTR or GCM.

It supports deduplication in order to reduce storage costs.

Cypherback itself contains no cryptographic code; all cryptographic
primitives are implemented in the Go language libraries.

Keys
----

There are five keys in use: a 256-bit metadata encryption key; a
384-bit metadata authentication key; a 384-bit chunk master key; a
384-bit chunk authentication key; and a 384-bit chunk storage key.
There is also a 64-bit metadata nonce.

Secrets
-------

A secrets file encapsulates a set of keys.  PBKDF2 is used to
generate two keys: a 256-bit AES key encryption key and a 384-bit key
authentication key.  The number of PBKDF2 iterations is tuned to take
approximately one second of wall clock time.  The keys are encrypted
in CTR mode with a random IV; a 384-bit authentication tag is
appended.

This follows NIST SP 800-38F, which specifies that keys may be stored
under an approved encryption mode and an approved authentication mode.

A secrets file is uniquely identified by SHA-384(["cypherback", version,
metadata encryption key, metadata authentication key, metadata nonce,
chunk master key, chunk authentication key, chunk storage key]), where
version equals a zero byte for this documented version.

The current secrets file format is:

        Byte Length
          0    1    File version (0 for this version)
          1   32    Salt
         33    8    Number of PBKDF2 iterations
         41   48    SHA-384([KEK, KAK])
         99   16    IV
        --------    begin AES-256-CTR
        115   32      metadata encryption key
        147   48      metadata authentication key
        195    8      metadata nonce
        203   32      chunk master key
        235   48      chunk authentication key
        283   48      chunk storage key
        --------    end AES-256-CTR
        331   48    HMAC-SHA-384(authentication key, bytes 0-330)

A single invoker of cypherback may control multiple secrets files, but
only one secrets file is in use at any one time; that is, no backup set
or chunk is ever common to two or more secrets files.

It's probable that many backends will store the secrets file under its
own private path.

Backup sets
-----------

Each logical backup forms a 'backup set,' which is a set of files and
their associated metadata.  The backup set format is inspired by tar,
but with some modifications for this use case, where data is stored
separately from metadata.  Each backup set is a sequence of backup runs.

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

The entire backup set is encrypted with AES in CTR mode under the
metadata encryption key; the IV is the metadata nonce concatenated
with 64 zero bits.  This means that is possible to determine the IV to
use for any block within the backup set stream simply by incrementing
the IV appropriately.

The final 48 bytes of the backup set consist of HMAC-SHA-384(metadata
authentication key, encrypted backup set).  These bytes are not
encrypted.

A property of the stream-oriented format is that a new backup run may
be appended by overwriting the authentication tag (and further bytes)
with the new data, then appending a new authentication tag.

The start-backup-run record has the following format:

  Byte Length
    0     1    Version (currently 0)
    1     1    Type (0 for start-backup-record)
    2     8    Unix time in seconds when this record was written
    10    4    Length in bytes of following records

Files
-----

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
                            [version, chunk nonce, length(encrypted data),
                             encrypted data])

Each chunk is stored under the name HMAC-SHA-384(chunk storage key,
chunk plaintext).

The chunk encryption key and IV are generated under the NIST SP 800-108
KDF in Counter Mode protocol: HMAC-SHA-384(chunk master key, [0x00,
"chunk encryption", 0x00, chunk nonce, 0x180]); the first 256 bits are
the key and the following 128 bits are the IV.

Use of Galois/Counter Mode
==========================

A future version of this protocol should convert all uses of CTR to GCM.
In each case, a 128-bit authentication tag will be written before the
384-bit HMAC; the HMAC will include the authentication tag in its
authenticated data.

Inspiration
===========

Cypherback is inspired by a number of projects, most notably tarsnap
and cyphertite.  Thanks are also due to Ferguson, Schneier & Kohno for
their book Cryptography Engineering.
