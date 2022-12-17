# BOBCryptoKit

This library performs the decryption that is the reverse of ECIESwithSHA256 in the BC library using Apples CryptoKit and some additional code.

## ECIESwithSHA256 encryption/decryption 

This scheme relies on the following things
* Basic ECDH to establish a shared secret between the two parties
* The shared secret is used with ANSI X9.63 Key Derivation Function (KDF) using SHA256 to generate a key
  which has the same length as the message + the public key that is sent as
  part of the message.
* The message itself is encrypted/decrypted by a simple xor with each byte of the message and the corresponding byte in the key.
* An encrypted message consists of public key + encrypted message + mac
* The mac uses an 128-bit key (taken from the generated key) and SHA256 for the digest.
* The mac is calculated on the encrypted data except for the MAC and at the end it is also updated with 8 zero bytes.
 
