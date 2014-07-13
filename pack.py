#!/usr/bin/env python

import struct

packed = struct.pack("!4s", "Joel")
result = struct.unpack("!3s", packed[:3])
print result

packed = struct.pack("!4sB", "Joel", 0)
print type(packed[4])
print packed[4] == 0
print packed[4] == struct.pack("!B", 0)
