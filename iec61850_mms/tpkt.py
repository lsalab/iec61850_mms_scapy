"""
Basic Scapy Definitions for TPKT (RFC 1006 - ISO Transport Service on top of the TCP Version: 3"

Source documents for these definitions:
    -   https://tools.ietf.org/html/rfc1006
"""

from scapy.packet import Packet, Raw
from scapy.fields import ByteField, LenField
from cotp.packets import COTP

TPKT_ISO_TSAP_PORT = 102
TPKT_VERSION = 0x03


class TPKT(Packet):
    name = "TPKT"
    fields_desc = [ByteField("version", TPKT_VERSION),
                   ByteField("reserved", 0x00),
                   LenField("length", None, fmt="!H", adjust=lambda x: x + 4)]
    
    def extract_padding(self, s: bytes):
        return s[:self.getfieldval('length')-4], s[self.getfieldval('length')-4:]
    
    def do_dissect_payload(self, s: bytes):
        if s is not None:
            p = COTP(s, _internal=1, _underlayer=self)
            self.add_payload(p)


