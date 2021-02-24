class RC4 :
    def __init__(self):
        self.S = []

    def preprocess_hex_chars(self, text) :
        """
        Preprocess text by decoding hex characters into ASCII characters
        """
        preprocessed_text = ''

        i = 0
        while i < len(text) :
            if '\\x' == text[i:i+2] :
                c = int(text[i+2:i+4], base=16)
                preprocessed_text += chr(c)
                i += 4
            else :
                preprocessed_text += text[i]
                i += 1

        return preprocessed_text

    def ksa(self, key) :
        """
        Key-Scheduling Algorithm

        Initialize S array, and then permute it using a key
        """
        if len(key) < 2 :
            raise Exception("Key must be at least 2 characters long")

        self.S = [i for i in range(256)]

        j = 0
        for i in range(256) :
            j = (j + self.S[i] + ord(key[i % len(key)])) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def prga(self, plaintext) :
        """
        Pseudo-Random Generation Algorithm

        Generate keystream by swapping S[i] and S[j], then summing them
        """
        if len(plaintext) == 0 :
            raise Exception("Plaintext cannot be empty")

        keystream = ''
        i = 0; j = 0
        for idx in range(len(plaintext)) :
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            t = (self.S[i] + self.S[j]) % 256
            keystream += chr(self.S[t])

        return keystream

    def encrypt(self, plaintext, key) :
        """
        Encrypt plaintext by given key using RC4 algorithm
        """
        if len(plaintext) == 0 :
            raise Exception("Plaintext cannot be empty")
        if len(key) < 2 :
            raise Exception("Key must be at least 2 characters long")

        ciphertext = ''

        self.ksa(key)
        keystream = self.prga(plaintext)
        for idx in range(len(plaintext)) :
            c = chr(ord(keystream[idx]) ^ ord(plaintext[idx]))
            ciphertext += c if c.isprintable() else r'\x{0:02x}'.format(ord(c))

        return ciphertext

    def decrypt(self, ciphertext, key) :
        """
        Decrypt ciphertext by given key using RC4 algorithm
        """
        if len(ciphertext) == 0 :
            raise Exception("Ciphertext cannot be empty")
        if len(key) < 2 :
            raise Exception("Key must be at least 2 characters long")

        ciphertext = self.preprocess_hex_chars(ciphertext)

        plaintext = ''

        self.ksa(key)
        keystream = self.prga(ciphertext)
        for idx in range(len(ciphertext)) :
            p = chr(ord(keystream[idx]) ^ ord(ciphertext[idx]))
            plaintext += p if p.isprintable() else r'\x{0:02x}'.format(ord(p))

        return plaintext

# print(r"\x{0:02x}".format(ord('a')))
# print(u'\x61')
# print('\x61')

# rc4 = RC4()
# key = "secret_key"
# cip = rc4.encrypt("kriptografi sangat menyenangkan", key)
# print(cip)
# pla = rc4.decrypt(cip, key)
# print(pla)