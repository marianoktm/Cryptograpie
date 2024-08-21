from DoubleCipher import DoubleCipher


def main():
    plaintext1 = b'Ciao sono una stringa da cifrare'

    print(plaintext1)

    cipher = DoubleCipher()
    bigciphertext1 = cipher.encrypt(plaintext=plaintext1, password="prova123")

    result, plaintext = cipher.decrypt(bigciphertext=bigciphertext1, password="prova123")

    if result:
        print(plaintext)
    else:
        print("error")


if __name__ == '__main__':
    main()
