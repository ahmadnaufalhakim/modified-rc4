class ModRC4 :
    N = 256

    def __init__(self) :
        self.S1 = []
        self.S2 = []

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

    def ksa(self, key_1, key_2) :
        """
        Key-Scheduling Algorithm

        Consists of 3 operation layers:

        1. Initialize S1 and S2 array, and then permute it using a key_1 and key_2
        2. Create an initialization vector (IV) using both keys, and then using the created IV and both keys to permute S1 and S2 array again
        3. Permute S1 and S2 array for the last time using both keys and a counter variable 'count' with a certain rule
        """
        if len(key_1) < 2 or len(key_2) < 2 :
            raise Exception("Key 1 and key 2 must be at least 2 characters long")

        # Operation layer 1
        self.S1 = [i for i in range(ModRC4.N)]
        self.S2 = [(ModRC4.N-i-1) for i in range(ModRC4.N)]

        j1 = j2 = 0
        for i in range(ModRC4.N) :
            j1 = (j1 + self.S1[i] + ord(key_1[i % len(key_1)])) % ModRC4.N
            j2 = (j2 + self.S2[i] + ord(key_2[i % len(key_2)])) % ModRC4.N
            self.S1[i], self.S1[j1] = self.S1[j1], self.S1[i]
            self.S2[i], self.S2[j2] = self.S2[j2], self.S2[i]

        # Operation layer 2
        IV = ''
        idx1 = idx2 = 0
        IV += chr(ord(key_1[idx1 % len(key_1)]) ^ ord(key_2[idx2 % len(key_2)]))
        while idx1 != len(key_1)-1 or idx2 != len(key_2)-1 :
            idx1 = (idx1 + 1) % len(key_1)
            idx2 = (idx2 + 1) % len(key_2)
            IV += chr(ord(key_1[idx1 % len(key_1)]) ^ ord(key_2[idx2 % len(key_2)]))

        j1 = j2 = 0
        for i in range(ModRC4.N//2) :
            j1 = ((j1 + self.S1[ModRC4.N//2-i-1]) ^ (ord(key_1[(ModRC4.N//2-i-1) % len(key_1)]) + ord(IV[(ModRC4.N//2-i-1) % len(IV)]))) % ModRC4.N
            j2 = ((j2 + self.S2[ModRC4.N//2-i-1]) ^ (ord(key_2[(ModRC4.N//2-i-1) % len(key_2)]) + ord(IV[(ModRC4.N//2-i-1) % len(IV)]))) % ModRC4.N
            self.S1[(ModRC4.N//2-i-1)], self.S1[j1] = self.S1[j1], self.S1[(ModRC4.N//2-i-1)]
            self.S2[(ModRC4.N//2-i-1)], self.S2[j2] = self.S2[j2], self.S2[(ModRC4.N//2-i-1)]

        for i in range(ModRC4.N//2, ModRC4.N) :
            j1 = ((j1 + self.S1[i]) ^ (ord(key_1[i % len(key_1)]) + ord(IV[i % len(IV)]))) % ModRC4.N
            j2 = ((j2 + self.S2[i]) ^ (ord(key_2[i % len(key_2)]) + ord(IV[i % len(IV)]))) % ModRC4.N
            self.S1[i], self.S1[j1] = self.S1[j1], self.S1[i]
            self.S2[i], self.S2[j2] = self.S2[j2], self.S2[i]

        # Operation layer 3
        j1 = j2 = 0
        for count in range(ModRC4.N) :
            i = count//2 if count % 2 == 0 else ModRC4.N-(count+1)//2
            j1 = (j1 + self.S1[i] + ord(key_1[i % len(key_1)])) % ModRC4.N
            j2 = (j2 + self.S2[i] + ord(key_2[i % len(key_2)])) % ModRC4.N
            self.S1[i], self.S1[j1] = self.S1[j1], self.S1[i]
            self.S2[i], self.S2[j2] = self.S2[j2], self.S2[i]

    def prga(self, plaintext) :
        """
        Pseudo-Random Generation Algorithm

        Generate keystream by swapping S1[i] with S1[j1], and S2[i] with S2[j2], then summing them
        """
        if len(plaintext) == 0 :
            raise Exception("Plaintext cannot be empty")

        keystream = ''
        i = 0
        j1 = j2 = 0
        for idx in range(len(plaintext)) :
            i = (i + 1) % ModRC4.N
            j1 = (j1 + self.S1[i]) % ModRC4.N
            j2 = (j2 + self.S2[i]) % ModRC4.N
            self.S1[i], self.S1[j1] = self.S1[j1], self.S1[i]
            self.S2[i], self.S2[j2] = self.S2[j2], self.S2[i]
            t = ((self.S1[i] + self.S1[j1]) + (self.S2[i] + self.S2[j2])) % ModRC4.N
            keystream += chr(self.S1[t] ^ self.S2[t])

        return keystream

    def encrypt(self, plaintext, key_1, key_2) :
        """
        Encrypt plaintext by given key 1 and key 2 using RC4 algorithm
        """
        if len(plaintext) == 0 :
            raise Exception("Plaintext cannot be empty")
        if len(key_1) < 2 or len(key_2) < 2 :
            raise Exception("Key 1 and key 2 must be at least 2 characters long")

        ciphertext = ''

        self.ksa(key_1, key_2)
        keystream = self.prga(plaintext)
        for idx in range(len(plaintext)) :
            c = chr(ord(keystream[idx]) ^ ord(plaintext[idx]))
            ciphertext += c if c.isprintable() else r'\x{0:02x}'.format(ord(c))

        return ciphertext

    def encrypt_binary(self, plaintext, key_1, key_2) :
        """
        Encrypt plaintext by given key 1 and key 2 using RC4 algorithm
        """
        if len(plaintext) == 0 :
            raise Exception("Plaintext cannot be empty")
        if len(key_1) < 2 or len(key_2) < 2 :
            raise Exception("Key 1 and key 2 must be at least 2 characters long")

        ciphertext = []

        self.ksa(key_1, key_2)
        keystream = self.prga(plaintext)
        for idx in range(len(plaintext)) :
            c = ord(keystream[idx]) ^ plaintext[idx]
            ciphertext.append(c)

        return ciphertext

    def decrypt(self, ciphertext, key_1, key_2) :
        """
        Decrypt ciphertext by given key 1 and key 2 using RC4 algorithm
        """
        if len(ciphertext) == 0 :
            raise Exception("Ciphertext cannot be empty")
        if len(key_1) < 2 or len(key_2) < 2 :
            raise Exception("Key 1 and key 2 must be at least 2 characters long")

        ciphertext = self.preprocess_hex_chars(ciphertext)

        plaintext = ''

        self.ksa(key_1, key_2)
        keystream = self.prga(ciphertext)
        for idx in range(len(ciphertext)) :
            p = chr(ord(keystream[idx]) ^ ord(ciphertext[idx]))
            plaintext += p if p.isprintable() else r'\x{0:02x}'.format(ord(p))

        return plaintext

    def decrypt_binary(self, ciphertext, key_1, key_2) :
        """
        Decrypt ciphertext by given key 1 and key 2 using RC4 algorithm
        """
        if len(ciphertext) == 0 :
            raise Exception("Ciphertext cannot be empty")
        if len(key_1) < 2 or len(key_2) < 2 :
            raise Exception("Key 1 and key 2 must be at least 2 characters long")

        plaintext = []

        self.ksa(key_1, key_2)
        keystream = self.prga(ciphertext)
        for idx in range(len(ciphertext)) :
            p = ord(keystream[idx]) ^ ciphertext[idx]
            plaintext.append(p)

        return plaintext

# mrc4 = ModRC4()
# key_1 = "hakim"
# key_2 = "ipul"
# cip = mrc4.encrypt("kriptografi sangat menyenangkan", key_1, key_2)
# # <b\x80_dî\x81,ew\xadPò/+Ù«8ÉZ¼3\x8dÖª~ùUÛö©
# print(cip)
# pla = mrc4.decrypt(cip, key_1, key_2)
# print(pla)