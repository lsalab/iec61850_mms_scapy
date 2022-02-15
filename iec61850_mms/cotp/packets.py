"""
Basic Scapy Definitions for COTP (ISO 8327/X.225 - Connection-Oriented Transport Protocol)

Source documents for these definitions:
    -   https://www.itu.int/rec/T-REC-X.225-199511-I/en
    -   https://www.fit.vut.cz/research/publication-file/11832/TR-61850.pdf

Limited Support for:
    - Data (DT)
    - Connection Requests (CR)
    - Connection Responses (CC)
"""


from scapy.packet import Packet
from scapy.fields import BitField, BitEnumField, XByteField, ByteEnumField, XByteEnumField, \
                         LenField, ShortField, XShortField, XStrLenField, PacketListField, \
                         FieldLenField, FieldListField, FlagsField, ThreeBytesField, \
                         X3BytesField, XLongField, MultipleTypeField

from .enums import *


class COTP_Parameter(Packet):
    name = "COTP Parameter"
    fields_desc = [
        XByteEnumField("code", None, COTP_PARAMETER_CODES),
        FieldLenField("length", None, fmt="B", length_of="value"),
        MultipleTypeField(
            [
                (XStrLenField("value", None, length_from=lambda x: x.length), lambda pkt: pkt.code in [0xc1, 0xc2, 0xc5, 0xc7, 0xe0]),
                (ByteEnumField("value", 0x07, TPDU_SIZE), lambda pkt: pkt.code == 0xc0),
                (XByteField("value", 0x01), lambda pkt: pkt.code == 0xc4),
                (FlagsField("value", 0x01, 8, TPDU_AOS_FLAGS), lambda pkt: pkt.code == 0xc6),
                (ShortField("value", 0x0000), lambda pkt: pkt.code in [0x85, 0x87, 0x8a, 0x8b, 0xc3]),
                (FieldListField("value", [], ThreeBytesField('', 0), count_from=lambda pkt: pkt.length // 3), lambda pkt: pkt.code == 0x89),
                (X3BytesField("value", 0), lambda pkt: pkt == 0x86),
                (XLongField("value", 0), lambda pkt: pkt.code in [0x88, 0x8c])
            ],
            XStrLenField("value", None, length_from=lambda x: x.length)
        )
    ]

    def extract_padding(self, s):
        return '', s

class COTP_Connection_Parameter(Packet):
    name = "COTP Parameter"
    fields_desc = [
        ByteEnumField("code", None, COTP_PARAMETER_CODES)
    ]

class COTP_CR(Packet):
    '''
    Connection Request (CR) TPDU

    As defined by RFC905, section 13.3
    '''
    name = "COTP Connection Request (CR)"
    fields_desc = [
        LenField("length", None, fmt="!B", adjust=lambda x: x + 5),
        BitEnumField("TPDU", 0b1110, 4, TPDU_CODE_TYPES),
        BitField("CDT", 0b0000, 4),
        XShortField("destination_reference", None),
        XShortField("source_reference", None),
        BitField("class", 0, 4),
        BitField("reserved", 0, 2),
        BitField("extended_format", 0, 1),
        BitField("explicit", 0, 1),
        PacketListField("parameters", None, COTP_Parameter)
    ]


# class COTP_Connection_Confirm(Packet):
#     name = "COTP Connection Confirm (CC)"
#     fields_desc = COTP_Connection_Request.fields_desc


class COTP_Data(Packet):
    name = "COTP Data (DT)"
    fields_desc = [XByteField("length", 2),
                   XByteField("tpdu_code", 0x0f),
                   BitField("last_data_unit", 1, 1),
                   BitField("tpdu_number", 0, 7)]

COTP_TPDU_PAYLOADS = {
    # 0x10: 'ED Expedited Data',
    # 0x20: 'EA Expedited Data Acknowledgement',
    # 0x50: 'RJ Reject',
    # 0x60: 'AK Data Acknowledgment',
    # 0x70: 'ER TDPU Error',
    # 0x80: 'DR Disconnect Request',
    # 0xc0: 'DC Disconnect Confirm',
    # 0xd0: 'CC Connection Confirm',
    0xe0: COTP_CR,
    # 0xf0: 'DT Data'
}

class COTP(Packet):
    name = 'COTP Connection-Oriented Transport Protocol'

    def guess_payload_class(self, payload):
        ln = len(payload)
        
        if ln < 2:
            return self.default_payload_class(payload)
        
        tpdu_code = int(payload[1]) & 0xf0
        
        if tpdu_code in COTP_TPDU_PAYLOADS:
            return COTP_TPDU_PAYLOADS[tpdu_code]
        
        return self.default_payload_class(payload)


