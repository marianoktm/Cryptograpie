# Cryptograpie
Simple Python script to perform encryption and decryption, powered by PyCryptodome.

The encryption algorithm is Salsa20. The key is derived from a password using scrypt. The derived key is then hashed, to be finally saved at the beginning of the ciphertext in sha256 format.

The DoubleCipher class is able to check whether the decryption password is correct or not.

The repo is work in progress. Next steps:
- Adding cli arguments
- Adding file support
