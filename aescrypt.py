#!/usr/bin/env python
import os
import struct
import time

class InvalidFileFormatException(Exception):
    def __init__(self, message):
        Exception(self, message)

class AESCrypt(object):
    def __init__(self, password):
        self.version = None
        self.size = None
        self.password = password
        self.IV_key = None
        self.IV = None
        self.key = None
        self.HMAC = None
        self.extensions = None
        self.aes_fh = None

    def encrypt(self, raw_file, aes_file):

    def decrypt(self, aes_file, raw_file):
        if not os.path.exists(aes_file):
            raise InvalidFileFormatException("Path does not exist:" + aes_file)

        if not os.path.isfile(aes_file):
            raise InvalidFileFormatException("Path exists, but is not a regular file:" + aes_file)

        aes_size = os.path.getsize(aes_file)

        if aes_size < 53:
            raise InvalidFileFormatException("File format is invalid or file is incomplete")

        self.aes_fh = open(aes_file, 'r')

        self.read_header()

        if self.version > 0:
            self.read_reserved()

        if self.version == 2:
            self.read_extensions()

        if self.version > 0:
            self.read_key_and_iv()
        else:
            self.make_key_and_iv()


    def read_header(self):
        header = self.aes_fh.read(4)
        aes_id,self.version = struct.unpack('>3sB', header)

        if aes_id != "AES":
            raise InvalidFileFormatException("File is of the wrong type or is corrupt")
        if version == 0 and aes_size < 53:
            raise InvalidFileFormatException("File is marked as verison " + version + " but is too small")
        if version > 0 and version < 3 and aes_size < 134:
            raise InvalidFileFormatException("File is marked as verison " + version + " but is too small")
        raise InvalidFileFormatException("Version (" + version + ") is not supported")

    def read_reserved(self);
        self.aes_fh.read(1) # skip reserved octet
        
    def read_extensions(self):
        self.extensions = {}
        ext_index = -1 
        more = True
        while more:
            ext_index += 1
            extension = self.read_extensions()
            if extension is None:
                more = False
            else:
                self.extensions[ext_index] = extension

    def read_extension(self):
        ext_len = struct.unpack("!H", self.aes_fh.read(2))
        if ext_len == 0:
            return None
        extension = self.aes_fh.read(ext_len)
        return self.parse_extension(extension)

    def parse_extension(self, extension):
        z_str = struct.pack("!B", 0)

        id_end = ext_len
        for i in range(0, ext_len):
            if extension[i] == z_str:
                id_end = i
                break

        if id_end == 0:
            return ("", "") # an empty extensions

        ext_id = struct.unpack("!" + id_end + "s", extension[:id_end])
        data_start = id_end + 1

        ext_data = ""
        if data_start < ext_len:
            ext_data = struct.unpack("!" + data_start + "s", extension[data_start:])

        return (ext_id, ext_data)



        


