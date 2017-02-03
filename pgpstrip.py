# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import, print_function, unicode_literals

from pgpdump import AsciiData
from pgpdump.packet import (
    PublicKeyPacket,
    PublicSubkeyPacket,
    SignaturePacket,
    UserIDPacket,
)
from pgpdump.utils import crc24
import base64
import struct
import sys


data = []
keys = []
has_uid = False
for packet in AsciiData(open(sys.argv[1]).read().encode('ascii')).packets():
    # RFC 4880, 4.2.1
    length = struct.pack('>i', packet.length).lstrip(b'\0')
    length_type = {
        1: 0,
        2: 1,
        4: 2,
    }.get(len(length))
    if length_type is None:
        print('Cannot encode a packet of length {}'.format(packet.length),
              file=sys.stderr)
        sys.exit(1)

    # Only keep the first uid, self-signatures, and public keys/subkeys
    if isinstance(packet, UserIDPacket):
        if has_uid:
            continue
        has_uid = True
    elif isinstance(packet, SignaturePacket):
        if (packet.key_id not in keys and
                packet.raw_sig_type not in (0x18, 0x19)):
            continue
    elif isinstance(packet, (PublicKeyPacket, PublicSubkeyPacket)):
        keys.append(packet.key_id)
    else:
        continue

    # RFC 4880, 4.2
    tag = 0x80 | (packet.raw << 2) | length_type
    data.append(bytes(bytearray((tag,))))
    data.append(bytes(length))
    data.append(bytes(packet.data))


data = b''.join(data)
crc = struct.pack('>i', crc24(bytearray(data)))[1:]
data = base64.b64encode(data).decode('ascii')

print('-----BEGIN PGP PUBLIC KEY BLOCK-----')
print()
for off in range(0, len(data), 64):
    print(data[off:off + 64])
print('={}'.format(base64.b64encode(crc).decode('ascii')))
print('-----END PGP PUBLIC KEY BLOCK-----')
