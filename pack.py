#!/usr/bin/env python
import binascii
import struct
import hashlib

packed = struct.pack("!4s", "Joel")
result = struct.unpack("!3s", packed[:3])[0]
print result

packed = struct.pack("!4sB", "Joel", 0)
print type(packed[4])
print packed[4] == 0
print packed[4] == struct.pack("!B", 0)

import sha256
message = "Joel"
packed = struct.pack("!4sB", message, 0)
print binascii.hexlify(hashlib.sha256(packed).digest())
