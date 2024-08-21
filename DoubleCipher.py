from Crypto.Cipher import Salsa20
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


class DoubleCipher:
    def encrypt(self, plaintext, password):
        # Generating salt and key with scrypt
        # The key will be 32 bytes (256 bit) because it will be used with Salsa20
        # Other values are taken from the PyCryptodome documentation
        salt = get_random_bytes(16)
        key = self.__generatekey(password, salt)

        # Generating the key digest
        sha256hasher = SHA256.new()
        sha256hasher.update(key)
        keydigest = sha256hasher.digest()

        # Generating the base ciphertext
        salsa20cipher = Salsa20.new(key)
        ciphertext_base = salsa20cipher.encrypt(plaintext=plaintext)
        ciphertext_final = salsa20cipher.nonce + salt + keydigest + ciphertext_base

        return ciphertext_final

    def decrypt(self, bigciphertext, password):
        # Decomposing the "big" ciphertext
        nonce, salt, keydigest, ciphertext = self.__decomposeciphertext(bigciphertext)

        # Generating a key to check with the key from the big ciphertext
        checkkey = self.__generatekey(password, salt)

        # Generating the check key digest
        sha256hasher = SHA256.new()
        sha256hasher.update(checkkey)
        checkkeydigest = sha256hasher.digest()

        # If the new key digest is different than the extracted digest, then the password is wrong
        if checkkeydigest != keydigest:
            return False, None

        # Else the password is right, proceed to decrypt the ciphertext
        salsa20cipher = Salsa20.new(checkkey, nonce)
        plaintext = salsa20cipher.decrypt(ciphertext)

        return True, plaintext

    def __generatekey(self, password, salt):
        return scrypt(password, salt, 32, N=2 ** 14, r=8, p=1)

    def __decomposeciphertext(self, ciphertext):
        # Defining the sizes of nonce, salt, and key
        nonce_size = 8  # 8 bytes
        salt_size = 16  # 16 bytes
        key_size = 32  # 32 bytes

        # Extracting the nonce, salt, key, and ciphertext
        nonce = ciphertext[:nonce_size]
        salt = ciphertext[nonce_size:nonce_size + salt_size]
        key = ciphertext[nonce_size + salt_size:nonce_size + salt_size + key_size]
        ciphertext = ciphertext[nonce_size + salt_size + key_size:]

        return nonce, salt, key, ciphertext
