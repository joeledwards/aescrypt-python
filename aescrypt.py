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

        


