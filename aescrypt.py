#!/usr/bin/env python
import binascii
import os
import struct
import time

class InvalidFileFormatException(Exception):
    def __init__(self, message):
        Exception(self, message)

class AESCrypt(object):
    def __init__(self, password):
        self.aes_fh = None
        self.password = password

        self.version = None
        self.extensions = None
        self.key_iv = None
        self.iv = None
        self.key = None
        self.key_hmac = None
        self.hmac = None

        self.padded_size = None
        self.original_size = None

    def get_password_key(self):
        # todo convert password into a key
        pass

    def encrypt(self, raw_file, aes_file):
        pass

    def decrypt(self, aes_file, raw_file):
        if not os.path.exists(aes_file):
            raise InvalidFileFormatException("Path does not exist:" + aes_file)

        if not os.path.isfile(aes_file):
            raise InvalidFileFormatException("Path exists, but is not a regular file:" + aes_file)

        self.aes_size = os.path.getsize(aes_file)

        if self.aes_size < 53:
            raise InvalidFileFormatException("File format is invalid or file is incomplete")

        self.aes_fh = open(aes_file, 'r')

        self.read_header()

        if self.version == 0:
            self.get_size_modulus()
        else:
            self.read_reserved()

        if self.version == 2:
            self.read_extensions()

        if self.version == 0:
            self.get_iv()
            self.get_length()
            self.get_hmac()
        else:
            self.get_key_iv()
            self.get_iv_and_key()
            self.get_key_hmac()
            self.get_length()
            self.get_size_modulus()
            self.get_hmac()

    def read_header(self):
        header = self.aes_fh.read(4)
        aes_id,self.version = struct.unpack('>3sB', header)

        if aes_id != "AES":
            raise InvalidFileFormatException("File is of the wrong type or is corrupt")
        if self.version < 0 or self.version > 2:
            raise InvalidFileFormatException("Version (" + str(self.version) + ") is not supported")
        if self.version == 0 and self.aes_size < 53:
            raise InvalidFileFormatException("File is marked as verison " + str(self.version) + " but is too small")
        if self.version > 0 and self.version < 3 and self.aes_size < 134:
            raise InvalidFileFormatException("File is marked as verison " + str(self.version) + " but is too small")

    def read_reserved(self):
        self.aes_fh.read(1) # skip reserved octet
        
    def read_extensions(self):
        self.extensions = {}
        extension_index = -1 
        more = True
        while more:
            extension_index += 1
            extension = self.read_extension()
            if extension is None:
                more = False
            else:
                self.extensions[extension_index] = extension

    def read_extension(self):
        extension_len = struct.unpack("!H", self.aes_fh.read(2))[0]
        if extension_len == 0:
            return None
        extension = self.aes_fh.read(extension_len)
        return self.parse_extension(extension)

    def parse_extension(self, extension):
        z_str = struct.pack("!B", 0)

        extension_len = len(extension)
        id_end = extension_len
        for i in range(0, extension_len):
            if extension[i] == z_str:
                id_end = i
                break

        if id_end == 0:
            return ("", "") # an empty extensions

        extension_id = struct.unpack("!" + str(id_end) + "s", extension[:id_end])[0]
        data_start = id_end + 1
        data_len = extension_len - data_start

        extension_data = ""
        if data_start < extension_len:
            extension_data = struct.unpack("!" + str(data_len) + "s", extension[data_start:])[0]

        return (extension_id, extension_data)

    def get_key_iv(self):
        self.key_iv = self.aes_fh.read(16)

    def get_iv(self):
        self.iv = self.aes.fh.read(16)

    def get_iv_and_key(self):
        iv_key = self.aes_fh.read(48) # TODO: remove
        self.iv = iv_key [:16] 
        self.key = iv_key[16:]
        return  # TODO: remove

        password_key = self.get_password_key()

        if self.version == 0:
            self.iv =  self.aes_fh.read(16)
            self.key = password_key
            return 

        # read cyphertext containing real key and IV from the file
        key_iv_cypher = self.aes_fh.read(48)

        # decrypt the real key and IV
        iv_key = ""#decrypt
        self.iv = iv_key[:16]
        self.key = iv_key[16:]

    def get_key_hmac(self):
        self.key_hmac = self.aes_fh.read(32)

    def get_length(self):
        start_offset = self.aes_fh.tell()
        print "cipher text start offset is", start_offset
        self.aes_fh.seek(-32 if self.version == 0 else -33, 2)
        end_offset = self.aes_fh.tell()
        print "cipher text end offset is", end_offset
        self.padded_size = end_offset - start_offset

    def get_size_modulus(self):
        print "file size is", self.aes_size
        print "offset before size_modulus read is", self.aes_fh.tell()
        self.size_modulus = struct.unpack("!B", self.aes_fh.read(1))[0]
        self.original_size = self.padded_size - (16 - self.size_modulus)

    def get_hmac(self):
        self.hmac = self.aes_fh.read(32)

def hexlify(value):
    return binascii.hexlify(value) if value is not None else value

def main():
    aescrypt = AESCrypt("buzuli")
    aescrypt.decrypt("test.txt.aes", "test.txt.out")

    print "        password:", aescrypt.password
    print "         version:", aescrypt.version
    print "      extensions:", aescrypt.extensions
    print "          key iv:", hexlify(aescrypt.key_iv)
    print "              iv:", hexlify(aescrypt.iv)
    print "             key:", hexlify(aescrypt.key)
    print "        key hmac:", hexlify(aescrypt.key_hmac)
    print "    size modulus:", aescrypt.size_modulus
    print "            hmac:", hexlify(aescrypt.hmac)
    print "   aes file size:", aescrypt.aes_size
    print "     padded size:", aescrypt.padded_size
    print "   original size:", aescrypt.original_size

if __name__ == "__main__":
    main()

#############################################################################
# Original code ported from the Java reference code by Bram Cohen, April 2001,
# with the following statement:
#
#         this code is public domain, unless someone makes
#         an intellectual property claim against the reference
#         code, in which case it can be made public domain by
#         deleting all the comments and renaming all the variables
#
class Rijndael(object):
    """
    A pure python (slow) implementation of rijndael with a decent interface.

    To do a key setup::

        r = Rijndael(key, block_size = 16)

    key must be a string of length 16, 24, or 32
    blocksize must be 16, 24, or 32. Default is 16

    To use::

        ciphertext = r.encrypt(plaintext)
        plaintext = r.decrypt(ciphertext)

    If any strings are of the wrong length a ValueError is thrown
    """

    @classmethod
    def create(cls):

        if hasattr(cls, "RIJNDAEL_CREATED"):
            return

        # [keysize][block_size]
        cls.num_rounds = {16: {16: 10, 24: 12, 32: 14}, 24: {16: 12, 24: 12, 32: 14}, 32: {16: 14, 24: 14, 32: 14}}

        cls.shifts = [[[0, 0], [1, 3], [2, 2], [3, 1]],
                [[0, 0], [1, 5], [2, 4], [3, 3]],
                [[0, 0], [1, 7], [3, 5], [4, 4]]]

        A = [[1, 1, 1, 1, 1, 0, 0, 0],
            [0, 1, 1, 1, 1, 1, 0, 0],
            [0, 0, 1, 1, 1, 1, 1, 0],
            [0, 0, 0, 1, 1, 1, 1, 1],
            [1, 0, 0, 0, 1, 1, 1, 1],
            [1, 1, 0, 0, 0, 1, 1, 1],
            [1, 1, 1, 0, 0, 0, 1, 1],
            [1, 1, 1, 1, 0, 0, 0, 1]]

        # produce log and alog tables, needed for multiplying in the
        # field GF(2^m) (generator = 3)
        alog = [1]
        for i in xrange(255):
            j = (alog[-1] << 1) ^ alog[-1]
            if j & 0x100 != 0:
                j ^= 0x11B
            alog.append(j)

        log = [0] * 256
        for i in xrange(1, 255):
            log[alog[i]] = i

        # multiply two elements of GF(2^m)
        def mul(a, b):
            if a == 0 or b == 0:
                return 0
            return alog[(log[a & 0xFF] + log[b & 0xFF]) % 255]

        # substitution box based on F^{-1}(x)
        box = [[0] * 8 for i in xrange(256)]
        box[1][7] = 1
        for i in xrange(2, 256):
            j = alog[255 - log[i]]
            for t in xrange(8):
                box[i][t] = (j >> (7 - t)) & 0x01

        B = [0, 1, 1, 0, 0, 0, 1, 1]

        # affine transform:  box[i] <- B + A*box[i]
        cox = [[0] * 8 for i in xrange(256)]
        for i in xrange(256):
            for t in xrange(8):
                cox[i][t] = B[t]
                for j in xrange(8):
                    cox[i][t] ^= A[t][j] * box[i][j]

        # cls.S-boxes and inverse cls.S-boxes
        cls.S =  [0] * 256
        cls.Si = [0] * 256
        for i in xrange(256):
            cls.S[i] = cox[i][0] << 7
            for t in xrange(1, 8):
                cls.S[i] ^= cox[i][t] << (7-t)
            cls.Si[cls.S[i] & 0xFF] = i

        # T-boxes
        G = [[2, 1, 1, 3],
            [3, 2, 1, 1],
            [1, 3, 2, 1],
            [1, 1, 3, 2]]

        AA = [[0] * 8 for i in xrange(4)]

        for i in xrange(4):
            for j in xrange(4):
                AA[i][j] = G[i][j]
                AA[i][i+4] = 1

        for i in xrange(4):
            pivot = AA[i][i]
            if pivot == 0:
                t = i + 1
                while AA[t][i] == 0 and t < 4:
                    t += 1
                    assert t != 4, 'G matrix must be invertible'
                    for j in xrange(8):
                        AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
                    pivot = AA[i][i]
            for j in xrange(8):
                if AA[i][j] != 0:
                    AA[i][j] = alog[(255 + log[AA[i][j] & 0xFF] - log[pivot & 0xFF]) % 255]
            for t in xrange(4):
                if i != t:
                    for j in xrange(i+1, 8):
                        AA[t][j] ^= mul(AA[i][j], AA[t][i])
                    AA[t][i] = 0

        iG = [[0] * 4 for i in xrange(4)]

        for i in xrange(4):
            for j in xrange(4):
                iG[i][j] = AA[i][j + 4]

        def mul4(a, bs):
            if a == 0:
                return 0
            r = 0
            for b in bs:
                r <<= 8
                if b != 0:
                    r = r | mul(a, b)
            return r

        cls.T1 = []
        cls.T2 = []
        cls.T3 = []
        cls.T4 = []
        cls.T5 = []
        cls.T6 = []
        cls.T7 = []
        cls.T8 = []
        cls.U1 = []
        cls.U2 = []
        cls.U3 = []
        cls.U4 = []

        for t in xrange(256):
            s = cls.S[t]
            cls.T1.append(mul4(s, G[0]))
            cls.T2.append(mul4(s, G[1]))
            cls.T3.append(mul4(s, G[2]))
            cls.T4.append(mul4(s, G[3]))

            s = cls.Si[t]
            cls.T5.append(mul4(s, iG[0]))
            cls.T6.append(mul4(s, iG[1]))
            cls.T7.append(mul4(s, iG[2]))
            cls.T8.append(mul4(s, iG[3]))

            cls.U1.append(mul4(t, iG[0]))
            cls.U2.append(mul4(t, iG[1]))
            cls.U3.append(mul4(t, iG[2]))
            cls.U4.append(mul4(t, iG[3]))

        # round constants
        cls.rcon = [1]
        r = 1
        for t in xrange(1, 30):
            r = mul(2, r)
            cls.rcon.append(r)

        cls.RIJNDAEL_CREATED = True

    def __init__(self, key, block_size = 16):

        # create common meta-instance infrastructure
        self.create()

        if block_size != 16 and block_size != 24 and block_size != 32:
            raise ValueError('Invalid block size: ' + str(block_size))
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise ValueError('Invalid key size: ' + str(len(key)))
        self.block_size = block_size

        ROUNDS = Rijndael.num_rounds[len(key)][block_size]
        BC = block_size / 4
        # encryption round keys
        Ke = [[0] * BC for i in xrange(ROUNDS + 1)]
        # decryption round keys
        Kd = [[0] * BC for i in xrange(ROUNDS + 1)]
        ROUND_KEY_COUNT = (ROUNDS + 1) * BC
        KC = len(key) / 4

        # copy user material bytes into temporary ints
        tk = []
        for i in xrange(0, KC):
            tk.append((ord(key[i * 4]) << 24) | (ord(key[i * 4 + 1]) << 16) |
                (ord(key[i * 4 + 2]) << 8) | ord(key[i * 4 + 3]))

        # copy values into round key arrays
        t = 0
        j = 0
        while j < KC and t < ROUND_KEY_COUNT:
            Ke[t / BC][t % BC] = tk[j]
            Kd[ROUNDS - (t / BC)][t % BC] = tk[j]
            j += 1
            t += 1
        tt = 0
        rconpointer = 0
        while t < ROUND_KEY_COUNT:
            # extrapolate using phi (the round key evolution function)
            tt = tk[KC - 1]
            tk[0] ^= (Rijndael.S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^  \
                     (Rijndael.S[(tt >>  8) & 0xFF] & 0xFF) << 16 ^  \
                     (Rijndael.S[ tt        & 0xFF] & 0xFF) <<  8 ^  \
                     (Rijndael.S[(tt >> 24) & 0xFF] & 0xFF)       ^  \
                     (Rijndael.rcon[rconpointer]    & 0xFF) << 24
            rconpointer += 1
            if KC != 8:
                for i in xrange(1, KC):
                    tk[i] ^= tk[i-1]
            else:
                for i in xrange(1, KC / 2):
                    tk[i] ^= tk[i-1]
                tt = tk[KC / 2 - 1]
                tk[KC / 2] ^= (Rijndael.S[ tt        & 0xFF] & 0xFF)       ^ \
                              (Rijndael.S[(tt >>  8) & 0xFF] & 0xFF) <<  8 ^ \
                              (Rijndael.S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^ \
                              (Rijndael.S[(tt >> 24) & 0xFF] & 0xFF) << 24
                for i in xrange(KC / 2 + 1, KC):
                    tk[i] ^= tk[i-1]
            # copy values into round key arrays
            j = 0
            while j < KC and t < ROUND_KEY_COUNT:
                Ke[t / BC][t % BC] = tk[j]
                Kd[ROUNDS - (t / BC)][t % BC] = tk[j]
                j += 1
                t += 1
        # inverse MixColumn where needed
        for r in xrange(1, ROUNDS):
            for j in xrange(BC):
                tt = Kd[r][j]
                Kd[r][j] = Rijndael.U1[(tt >> 24) & 0xFF] ^ \
                           Rijndael.U2[(tt >> 16) & 0xFF] ^ \
                           Rijndael.U3[(tt >>  8) & 0xFF] ^ \
                           Rijndael.U4[ tt        & 0xFF]
        self.Ke = Ke
        self.Kd = Kd

    def encrypt(self, plaintext):
        if len(plaintext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Ke = self.Ke

        BC = self.block_size / 4
        ROUNDS = len(Ke) - 1
        if BC == 4:
            Rijndael.SC = 0
        elif BC == 6:
            Rijndael.SC = 1
        else:
            Rijndael.SC = 2
        s1 = Rijndael.shifts[Rijndael.SC][1][0]
        s2 = Rijndael.shifts[Rijndael.SC][2][0]
        s3 = Rijndael.shifts[Rijndael.SC][3][0]
        a = [0] * BC
        # temporary work array
        t = []
        # plaintext to ints + key
        for i in xrange(BC):
            t.append((ord(plaintext[i * 4    ]) << 24 |
                      ord(plaintext[i * 4 + 1]) << 16 |
                      ord(plaintext[i * 4 + 2]) <<  8 |
                      ord(plaintext[i * 4 + 3])        ) ^ Ke[0][i])
        # apply round transforms
        for r in xrange(1, ROUNDS):
            for i in xrange(BC):
                a[i] = (Rijndael.T1[(t[ i           ] >> 24) & 0xFF] ^
                        Rijndael.T2[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        Rijndael.T3[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        Rijndael.T4[ t[(i + s3) % BC]        & 0xFF]  ) ^ Ke[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Ke[ROUNDS][i]
            result.append((Rijndael.S[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Rijndael.S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Rijndael.S[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((Rijndael.S[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return string.join(map(chr, result), '')

    def decrypt(self, ciphertext):
        if len(ciphertext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(ciphertext)))
        Kd = self.Kd

        BC = self.block_size / 4
        ROUNDS = len(Kd) - 1
        if BC == 4:
            Rijndael.SC = 0
        elif BC == 6:
            Rijndael.SC = 1
        else:
            Rijndael.SC = 2
        s1 = Rijndael.shifts[Rijndael.SC][1][1]
        s2 = Rijndael.shifts[Rijndael.SC][2][1]
        s3 = Rijndael.shifts[Rijndael.SC][3][1]
        a = [0] * BC
        # temporary work array
        t = [0] * BC
        # ciphertext to ints + key
        for i in xrange(BC):
            t[i] = (ord(ciphertext[i * 4    ]) << 24 |
                    ord(ciphertext[i * 4 + 1]) << 16 |
                    ord(ciphertext[i * 4 + 2]) <<  8 |
                    ord(ciphertext[i * 4 + 3])        ) ^ Kd[0][i]
        # apply round transforms
        for r in xrange(1, ROUNDS):
            for i in xrange(BC):
                a[i] = (Rijndael.T5[(t[ i           ] >> 24) & 0xFF] ^
                        Rijndael.T6[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        Rijndael.T7[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        Rijndael.T8[ t[(i + s3) % BC]        & 0xFF]  ) ^ Kd[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Kd[ROUNDS][i]
            result.append((Rijndael.Si[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Rijndael.Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Rijndael.Si[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((Rijndael.Si[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return string.join(map(chr, result), '')

    # @staticmethod
    # def encrypt_block(key, block):
    #     return Rijndael(key, len(block)).encrypt(block)

    # @staticmethod
    # def decrypt_block(key, block):
    #     return Rijndael(key, len(block)).decrypt(block)

    @staticmethod
    def test():
        def t(kl, bl):
            b = 'b' * bl
            r = Rijndael('a' * kl, bl)
            x = r.encrypt(b)
            assert x != b
            assert r.decrypt(x) == b
        t(16, 16)
        t(16, 24)
        t(16, 32)
        t(24, 16)
        t(24, 24)
        t(24, 32)
        t(32, 16)
        t(32, 24)
        t(32, 32)
# Rijndael
#############################################################################

