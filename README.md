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

There are four keys in use: a 256-bit metadata encryption key; a
256-bit chunk encryption key; a 384-bit chunk authentication key; and
a 384-bit chunk storage key.

Secrets
-------

A secrets file encapsulates a set of keys.  It is encrypted under a
key encryption key derived from the user's passphrase using PBKDF2
under a numbe of iterations intended to last approximately 1 second.
FIXME: follow the NIST key wrap specification.

Backup sets
-----------

Each logical backup forms a 'backup set,' which is a set of files and
their associated metadata.  The backup set format is inspired by tar,
but with some modifications for this unique use case.  Each backup set
is a sequence of backup runs.

Each backup run is represented by a sequence of records, starting with
a start record indicating the date, and ending with an end record.  In
between are file records which record metadata about the files
themselves.  File contents are not stored in the backup run or backup
set; rather, each regular file record contains references to its
contents.

To run a backup, first the current backup set is downloaded, then all
files which have changed since the previous backup are added to the
backup set (FIXME: add a hash of each file's data to its record to
help this?; FIXME: add deletion records), then their chunks are
uploaded in random order, and finally the new backup set is uploaded.
A property of the stream-oriented format is that the new records need
merely be appended to the old.

Files
-----

A file's contents are broken up into 256K chunks (in a future version,
variable-length chunks are a possibility).  Each chunk is encrypted
under the chunk encryption key with a random IV.  The chunk storage
format consists of one byte of version (currently 0); then a byte
representing a Boolean true or false, indicating whether or not the
chunk was compressed before encryption; then 256 bits (16 bytes) of
initialisation vector; then 4 bytes (FIXME: determine endianness)
indicating the length of the chunk; then LENGTH bytes of encrypted
data, and finally a 384-bit (48 bytes) authenticator, generated with
HMAC-SHA-384(chunk authentication key,
[version, compressed-p, IV, length, encrypted data]).

Inspiration
===========

Cypherback is inspired by a number of projects, most notably tarsnap
and cyphertite.  Thanks are also due to Ferguson, Schneier & Kohno for
their book Cryptography Engineering.
