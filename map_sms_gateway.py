#!/usr/bin/python3
# GSM MAP / SIGTRAN MAP SMS Gateway — lab use only, do not use in production
# Protocol stack: SCTP → M3UA → MTP3 → SCCP (XUDT) → TCAP → MAP
# Supports: SRI-SM (respond), MT-FSM (originate via SRI then deliver),
#           MO-FSM (originate), long messages (GSM-7 + UCS-2), concat SMS

import socket
import struct
import threading
import logging
import logging.handlers
import time
import random
import sys
import json
import configparser
import traceback
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
# ---------------------------------------------------------------------------
# Configuration loaded from INI file (--config)
# ---------------------------------------------------------------------------
CFG: Dict[str, Any] = {}

# SRI-SM response table.  Keys: exact MSISDN, prefix (abc*), suffix (*abc),
# or substring (*abc*).  Longest match wins.
SRI_TABLE: Dict[str, Dict[str, str]] = {}

# Menu presets loaded from INI [menu_presets]
MENU_PRESETS: Dict[str, str] = {}

# Path to optional INI config file (set by --config CLI arg)
_CFG_FILE: Optional[str] = None
_CFG_FILE: Optional[str] = None

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
IPPROTO_SCTP        = 132

# M3UA message classes
M3UA_MGMT           = 0
M3UA_TRANSFER       = 1
M3UA_ASPSM          = 3
M3UA_ASPTM          = 4

# M3UA message types
M3UA_DATA           = 1
M3UA_ASPUP          = 1
M3UA_ASPDN          = 2
M3UA_BEAT           = 3
M3UA_ASPUP_ACK      = 4
M3UA_ASPDN_ACK      = 5
M3UA_BEAT_ACK       = 6
M3UA_ASPAC          = 1
M3UA_ASPIA          = 2
M3UA_ASPAC_ACK      = 3
M3UA_ASPIA_ACK      = 4

# M3UA parameter tags
TAG_ROUTING_CTX     = 0x0006
TAG_PROTO_DATA      = 0x0210

# SCCP message types
SCCP_UDT            = 0x09
SCCP_XUDT           = 0x11
SCCP_SSN_PRESENT    = 0x02
SCCP_PC_PRESENT     = 0x01

# TCAP message tags
TCAP_BEGIN          = 0x62
TCAP_CONTINUE       = 0x65
TCAP_END            = 0x64
TCAP_ABORT          = 0x67

# MAP operation codes
MAP_SRI_SM          = 45
MAP_MT_FSM          = 44
MAP_MO_FSM          = 46
MAP_REPORT_SM_DS    = 47   # reportSM-DeliveryStatus
MAP_ALERT_SC        = 64   # alertServiceCentre
MAP_ATSI            = 62   # anyTimeSubscriberInformation

# MAP Application Context Name OIDs
ACN_SRI_SM          = "0.4.0.0.1.0.20.3"
ACN_MO_RELAY        = "0.4.0.0.1.0.21.3"
ACN_MT_RELAY        = "0.4.0.0.1.0.25.3"
ACN_ALERT_SC        = "0.4.0.0.1.0.23.2"   # shortMsgAlertContext-v2 (most common)
ACN_ALERT_SC_V1     = "0.4.0.0.1.0.23.1"   # shortMsgAlertContext-v1 (older)
ACN_ALERT_SC_V3     = "0.4.0.0.1.0.23.3"   # shortMsgAlertContext-v3 (newer)
ACN_ATSI_V3         = "0.4.0.0.1.0.29.3"   # anyTimeInfoEnquiry-v3
ACN_ATSI_V2         = "0.4.0.0.1.0.29.2"   # anyTimeInfoEnquiry-v2
OID_TCAP_DIALOGUE   = "0.0.17.773.1.1.1"

# MAP error codes — localValue assignments from MAP-Errors ASN.1 module
# (3GPP TS 29.002, confirmed against Wireshark MAP dissector)
MAP_ERROR_CODES: Dict[int, str] = {
    1:  'unknownSubscriber',
    2:  'unknownBaseStation',
    3:  'unknownMSC',
    4:  'unidentifiedSubscriber',
    5:  'unknownEquipment',
    6:  'roamingNotAllowed',
    7:  'illegalSubscriber',
    8:  'bearerServiceNotProvisioned',
    9:  'teleserviceNotProvisioned',
    10: 'illegalEquipment',
    11: 'callBarred',
    12: 'forwardingViolation',
    13: 'cugReject',
    14: 'illegalSS-Operation',
    15: 'ss-ErrorStatus',
    16: 'ss-NotAvailable',
    17: 'ss-SubscriptionViolation',
    18: 'ss-Incompatibility',
    19: 'facilityNotSupported',
    20: 'noHandoverNumberAvailable',
    21: 'subsequentHandoverFailure',
    22: 'absentSubscriber',
    23: 'incompatibleTerminal',
    24: 'shortTermDenial',
    25: 'longTermDenial',
    26: 'subscriberBusyForMT-SMS',
    27: 'absentSubscriberSM',
    28: 'messageWaitingListFull',
    29: 'systemFailure',
    30: 'dataMissing',
    31: 'unexpectedDataValue',
    32: 'sm-DeliveryFailure',        # confirmed by Wireshark / 3GPP TS 29.002 ASN.1
    33: 'callBarred',
    34: 'orNotAllowed',
    35: 'unknownAlphabet',
    36: 'ussd-Busy',
    37: 'pw-RegistrationFailure',
    38: 'negativePW-Check',
    39: 'noRoamingNumberAvailable',
    40: 'tracingBufferFull',
    41: 'targetCellOutsideGroupCallArea',
    42: 'numberOfPW-AttemptsViolation',
    43: 'numberChanged',
    44: 'busySubscriber',
    45: 'noSubscriberReply',
    46: 'forwardingFailed',
    47: 'ati-NotAllowed',
    48: 'unauthorizedRequestingNetwork',
    49: 'unauthorizedLCSClient',
    50: 'positionMethodFailure',
    51: 'unknownOrUnreachableLCSClient',
    52: 'mm-EventNotSupported',
    53: 'informationNotAvailable',
    54: 'unknownAlphabet',
    55: 'ussd-Busy',
    56: 'illegalSubscriber',
    57: 'deliveryFailure',
    58: 'deactivationFailure',
    59: 'technicalError',
}

# SM-DeliveryFailure sub-causes (3GPP TS 29.002 §17.6.7.4)
SM_DELIVERY_FAILURE_CAUSE: Dict[int, str] = {
    0: 'memoryCapacityExceeded',
    1: 'equipmentProtocolError',
    2: 'equipmentNotSM-Equipped',
    3: 'unknownServiceCentre',
    4: 'sc-Congestion',
    5: 'invalidSME-Address',
    6: 'subscriberNotSC-Subscriber',
}

# TCAP Reject problem codes (ITU-T Q.773)
TCAP_REJECT_GENERAL: Dict[int, str] = {
    0: 'unrecognisedComponent',
    1: 'mistypedComponent',
    2: 'badlyStructuredComponent',
}
TCAP_REJECT_INVOKE: Dict[int, str] = {
    0: 'duplicateInvokeID',
    1: 'unrecognisedOperation',
    2: 'mistypedParameter',
    3: 'resourceLimitation',
    4: 'initiatingRelease',
    5: 'unrecognisedLinkedID',
    6: 'linkedResponseUnexpected',
    7: 'unexpectedLinkedOperation',
}
TCAP_REJECT_RR: Dict[int, str] = {
    0: 'unrecognisedInvokeID',
    1: 'resultResponseUnexpected',
    2: 'mistypedParameter',
}
TCAP_REJECT_RE: Dict[int, str] = {
    0: 'unrecognisedInvokeID',
    1: 'errorResponseUnexpected',
    2: 'mistypedParameter',
}


# ===========================================================================
# Section 1 — INI config loader
# ===========================================================================

def load_config(path: str) -> bool:
    """Load INI file into CFG / SRI_TABLE / MENU_PRESETS.  Returns True on success."""
    global CFG, SRI_TABLE, MENU_PRESETS
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    try:
        if not parser.read(path, encoding='utf-8'):
            return False

        CFG.clear()
        CFG.update({
            # Transport
            'sctp_host': parser.get('transport', 'sctp_host', fallback=''),
            'sctp_port': parser.getint('transport', 'sctp_port', fallback=0),
            'log_file': parser.get('transport', 'log_file', fallback=''),
            'log_level': parser.get('transport', 'log_level', fallback='INFO'),
            # Point codes and global titles
            'local_pc': parser.getint('signaling', 'local_pc', fallback=0),
            'remote_pc': parser.getint('signaling', 'remote_pc', fallback=0),
            'local_gt': parser.get('signaling', 'local_gt', fallback=''),
            'remote_gt': parser.get('signaling', 'remote_gt', fallback=''),
            'hlr_gt': parser.get('signaling', 'hlr_gt', fallback=''),
            'msc_gt': parser.get('signaling', 'msc_gt', fallback=''),
            'vlr_gt': parser.get('signaling', 'vlr_gt', fallback=''),
            'smsc_gt': parser.get('signaling', 'smsc_gt', fallback=''),
            'fsmsc_gt': parser.get('signaling', 'fsmsc_gt', fallback=''),
            # M3UA routing
            'route_context': parser.getint('m3ua', 'route_context', fallback=0),
            'network_indicator': parser.getint('m3ua', 'network_indicator', fallback=0),
            'ssn': parser.getint('m3ua', 'ssn', fallback=0),
            'called_ssn': parser.getint('m3ua', 'called_ssn', fallback=0),
            'calling_ssn': parser.getint('m3ua', 'calling_ssn', fallback=0),
            # SCCP message selection
            'sccp_message_type': parser.get('sccp', 'message_type', fallback='xudt').strip().lower(),
            'sccp_hop_counter': parser.getint('sccp', 'hop_counter', fallback=15),
            # IMSI generation defaults
            'imsi_mcc': parser.get('imsi', 'imsi_mcc', fallback=''),
            'imsi_mnc': parser.get('imsi', 'imsi_mnc', fallback=''),
            # Example addresses shown in startup banner / menu
            'example_oa': parser.get('examples', 'example_oa', fallback=''),
            'example_da': parser.get('examples', 'example_da', fallback=''),
            # Housekeeping
            'dialogue_ttl': parser.getint('housekeeping', 'dialogue_ttl', fallback=120),
            'cleanup_interval': parser.getint('housekeeping', 'cleanup_interval', fallback=30),
            # MAP behavior
            'mt_response_mode': parser.get('map', 'mt_response_mode', fallback='success'),
            'alert_sc_acn': parser.get('map', 'alert_sc_acn', fallback=''),
        })

        if CFG['sccp_message_type'] not in ('udt', 'xudt'):
            CFG['sccp_message_type'] = 'xudt'

        sri_table: Dict[str, Dict[str, str]] = {}
        if parser.has_section('sri_table'):
            for key, value in parser.items('sri_table'):
                raw = str(value).strip()
                if not raw:
                    continue
                if ',' in raw:
                    nnn, imsi = [part.strip() for part in raw.split(',', 1)]
                elif '|' in raw:
                    nnn, imsi = [part.strip() for part in raw.split('|', 1)]
                else:
                    nnn, imsi = raw, ''
                sri_table[key] = {'nnn': nnn, 'imsi': imsi}
        SRI_TABLE = sri_table

        MENU_PRESETS.clear()
        MENU_PRESETS.update({
            'short_gsm7_mo': parser.get('menu_presets', 'short_gsm7_mo', fallback=''),
            'short_gsm7_mt': parser.get('menu_presets', 'short_gsm7_mt', fallback=''),
            'short_ucs2': parser.get('menu_presets', 'short_ucs2', fallback=''),
            'long_gsm7': parser.get('menu_presets', 'long_gsm7', fallback=''),
            'long_ucs2': parser.get('menu_presets', 'long_ucs2', fallback=''),
        })
        return True
    except Exception:
        return False

# ===========================================================================
# Section 2 — Logging
# ===========================================================================

class _TsFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        record.msg = f'{ts} {record.msg}'
        return super().format(record)

def make_logger(log_level: str) -> logging.Logger:
    log = logging.getLogger('map_sms_gateway')
    log.setLevel(logging.DEBUG)
    for h in log.handlers[:]:
        log.removeHandler(h)
        try: h.close()
        except Exception: pass
    # Stop previous queue listener if present
    old_listener = getattr(log, '_queue_listener', None)
    if old_listener:
        try: old_listener.stop()
        except Exception: pass

    # Use a memory queue + background listener so log I/O never blocks the send path.
    # The QueueListener drains the queue on a dedicated daemon thread.
    import queue as _queue
    log_queue = _queue.Queue(maxsize=0)  # unbounded — we never want sends to block on logging

    fh = logging.FileHandler(CFG.get('log_file') or 'map_sms_gateway.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(_TsFormatter('%(message)s'))

    level = getattr(logging, log_level.upper(), logging.INFO)
    handlers = [fh]
    if level < logging.ERROR:
        ch = logging.StreamHandler()
        ch.setLevel(level)
        ch.setFormatter(logging.Formatter('%(message)s'))
        handlers.append(ch)

    listener = logging.handlers.QueueListener(log_queue, *handlers, respect_handler_level=True)
    listener.start()

    qh = logging.handlers.QueueHandler(log_queue)
    qh.setLevel(logging.DEBUG)
    log.addHandler(qh)

    # Keep a reference so it can be stopped on reload
    log._queue_listener = listener  # type: ignore[attr-defined]
    log.propagate = False
    return log


# ===========================================================================
# Section 3 — ASN.1 / BER primitives
# ===========================================================================

def asn1_tl(tag: int, value: bytes) -> bytes:
    """Encode tag + definite-form length + value."""
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + value

def asn1_read(buf: bytes, off: int) -> Optional[Tuple[int,int,int,int,int]]:
    """Read one TLV at offset.  Returns (tag, length, val_start, val_end, next_off) or None."""
    if off >= len(buf):
        return None
    tag = buf[off]; off += 1
    if off >= len(buf):
        return None
    fb = buf[off]; off += 1
    if fb & 0x80:
        n = fb & 0x7F
        if n == 0 or off + n > len(buf):
            return None
        length = int.from_bytes(buf[off:off + n], 'big')
        off += n
    else:
        length = fb
    end = off + length
    if end > len(buf):
        return None
    return tag, length, off, end, end

def encode_oid(dotted: str) -> bytes:
    """Encode dotted-decimal OID string to DER bytes (tag 0x06 included)."""
    parts = [int(x) for x in dotted.split('.')]
    first = 40 * parts[0] + parts[1]
    body = []
    for arc in [first] + parts[2:]:
        if arc < 0x80:
            body.append(arc)
        else:
            chunk = []
            while arc:
                chunk.insert(0, (arc & 0x7F) | 0x80)
                arc >>= 7
            chunk[-1] &= 0x7F
            body.extend(chunk)
    return asn1_tl(0x06, bytes(body))

def bcd_encode(digits: str) -> bytes:
    """Pack digit string into semi-octet BCD (TBCD).  Odd length padded with 0xF."""
    s = digits
    if len(s) % 2:
        s += 'F'
    out = bytearray()
    for i in range(0, len(s), 2):
        lo = 0xF if s[i] == 'F' else int(s[i])
        hi = 0xF if s[i+1] == 'F' else int(s[i+1])
        out.append((hi << 4) | lo)
    return bytes(out)

def bcd_decode(data: bytes) -> Optional[str]:
    """Unpack TBCD bytes to digit string, stripping filler 0xF nibbles."""
    digits = ''
    for b in data:
        lo, hi = b & 0x0F, (b >> 4) & 0x0F
        if lo != 0xF:
            digits += str(lo)
        if hi != 0xF:
            digits += str(hi)
    return digits if digits else None

def parse_ton_npi(addr: str) -> Tuple[int, int, str]:
    """Parse 'TON.NPI.digits' or bare 'digits'.  Returns (ton, npi, digits)."""
    parts = str(addr).split('.')
    if len(parts) >= 3:
        ton, npi = int(parts[0]), int(parts[1])
        digits = ''.join(ch for ch in ''.join(parts[2:]) if ch.isdigit())
    else:
        ton, npi = 1, 1
        digits = ''.join(ch for ch in addr if ch.isdigit())
    return ton, npi, digits

def build_address_string(ton: int, npi: int, digits: str) -> bytes:
    """Build MAP AddressString: TOA byte + TBCD digits."""
    toa = 0x80 | ((ton & 0x07) << 4) | (npi & 0x0F)
    return bytes([toa]) + bcd_encode(''.join(ch for ch in digits if ch.isdigit()))


# ===========================================================================
# Section 4 — GSM SMS encoding
# ===========================================================================

# GSM 7-bit default alphabet — extension table characters count as 2 septets
_GSM7_EXT = set('^{}\\[]~|€')

_GSM7_EXT_MAP = {
    '^': 0x14, '{': 0x28, '}': 0x29, '\\': 0x2F,
    '[': 0x3C, '~': 0x3D, ']': 0x3E, '|': 0x40, '€': 0x65,
}

_GSM7_BASE_MAP = {
    0x00: '@',  0x01: '£', 0x02: '$', 0x03: '¥', 0x04: 'è', 0x05: 'é',
    0x06: 'ù',  0x07: 'ì', 0x08: 'ò', 0x09: 'Ç', 0x0A: '\n', 0x0D: '\r',
    0x10: 'Δ',  0x11: '_', 0x12: 'Φ', 0x13: 'Γ', 0x14: 'Λ', 0x15: 'Ω',
    0x16: 'Π',  0x17: 'Ψ', 0x18: 'Σ', 0x19: 'Θ', 0x1A: 'Ξ',
}

def gsm7_septet_len(text: str) -> int:
    """Count septets needed (extension chars count 2)."""
    return sum(2 if ch in _GSM7_EXT else 1 for ch in text)

def gsm7_pack(text: str) -> bytes:
    """Pack text string into GSM 7-bit octet stream."""
    septets = []
    for ch in text:
        if ch in _GSM7_EXT_MAP:
            septets += [0x1B, _GSM7_EXT_MAP[ch]]
        else:
            septets.append(ord(ch) & 0x7F)
    out = bytearray()
    acc = bits = 0
    for s in septets:
        acc |= (s & 0x7F) << bits
        bits += 7
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits:
        out.append(acc & 0xFF)
    return bytes(out)

def gsm7_pack_with_udh(udh: bytes, text: str) -> Tuple[bytes, int]:
    """Pack GSM 7-bit text with User Data Header prepended.
    Returns (ud_bytes, udl_in_septets).  Handles pad-bit alignment.
    """
    header = bytes([len(udh)]) + udh
    hdr_octets = len(header)
    pad_bits = (7 - (hdr_octets * 8) % 7) % 7

    packed = gsm7_pack(text)
    if pad_bits:
        shifted = bytearray()
        carry = 0
        for b in packed:
            shifted.append(((b << pad_bits) & 0xFF) | carry)
            carry = (b >> (8 - pad_bits)) & ((1 << pad_bits) - 1)
        if gsm7_septet_len(text) > 0:
            shifted.append(carry)
        packed = bytes(shifted)

    hdr_septets = (hdr_octets * 8 + 6) // 7
    udl = hdr_septets + gsm7_septet_len(text)
    expected = (udl * 7 + 7) // 8
    ud = header + packed
    if len(ud) < expected:
        ud += b'\x00' * (expected - len(ud))
    return ud, udl

def gsm7_unpack(data: bytes, septet_count: int, start_bit: int = 0, limit: int = 999) -> str:
    """Unpack GSM 7-bit octets into a string, up to limit chars."""
    def get_septet(i):
        s = start_bit + i * 7
        bi, bo = s // 8, s % 8
        b0 = data[bi] if bi < len(data) else 0
        b1 = data[bi+1] if bi+1 < len(data) else 0
        return ((b0 >> bo) | ((b1 << (8 - bo)) & 0xFF)) & 0x7F

    ext_inv = {v: k for k, v in _GSM7_EXT_MAP.items()}
    out = []
    i = 0
    while i < septet_count and len(out) < limit:
        s = get_septet(i); i += 1
        if s == 0x1B and i < septet_count:
            e = get_septet(i); i += 1
            out.append(ext_inv.get(e, '?'))
        elif s in _GSM7_BASE_MAP:
            out.append(_GSM7_BASE_MAP[s])
        elif 0x20 <= s <= 0x7E:
            out.append(chr(s))
        else:
            out.append('?')
    return ''.join(out)

def needs_ucs2(text: str) -> bool:
    return any(ord(ch) > 0x7F for ch in text)

def make_concat_udh(ref: int, total: int, seq: int) -> bytes:
    """Build 8-bit reference concatenated SMS UDH (IEI 0x00)."""
    return bytes([0x00, 0x03, ref & 0xFF, total & 0xFF, seq & 0xFF])

def bcd2(v: int) -> int:
    """Pack a decimal value 0–99 into a BCD byte (SCTS style)."""
    return ((v % 10) << 4) | (v // 10)

def build_scts() -> bytes:
    """Build 7-byte Service Centre Time Stamp from current local time."""
    t = time.localtime()
    return bytes([
        bcd2(t.tm_year % 100), bcd2(t.tm_mon),  bcd2(t.tm_mday),
        bcd2(t.tm_hour),       bcd2(t.tm_min),  bcd2(t.tm_sec),
        0x00,  # UTC offset 0
    ])

def split_for_concat(text: str) -> List[Dict[str, Any]]:
    """Split text into segments for concatenated SMS.
    Returns list of {'enc': 'gsm7'|'ucs2', 'text': str}.
    Single-segment messages are returned as a one-element list.
    """
    if needs_ucs2(text):
        if len(text) <= 70:
            return [{'enc': 'ucs2', 'text': text}]
        return [{'enc': 'ucs2', 'text': text[i:i+67]} for i in range(0, len(text), 67)]
    if gsm7_septet_len(text) <= 160:
        return [{'enc': 'gsm7', 'text': text}]
    segs = []
    i = 0
    while i < len(text):
        used, j = 0, i
        while j < len(text):
            add = 2 if text[j] in _GSM7_EXT else 1
            if used + add > 153:
                break
            used += add; j += 1
        segs.append({'enc': 'gsm7', 'text': text[i:j]})
        i = j
    return segs


# ===========================================================================
# Section 5 — TPDU builders and parsers
# ===========================================================================

def build_sms_deliver(oa_ton: int, oa_npi: int, oa_digits: str, text: str,
                      udh: Optional[bytes] = None) -> bytes:
    """Build SMS-DELIVER TPDU (MTI=0x00)."""
    fo = 0x04  # MMS=1 (no more messages)
    if udh:
        fo |= 0x40  # UDHI
    digs = ''.join(ch for ch in oa_digits if ch.isdigit())
    toa  = 0x80 | ((oa_ton & 0x07) << 4) | (oa_npi & 0x0F)
    OA   = bytes([len(digs), toa]) + bcd_encode(digs)
    scts = build_scts()

    if needs_ucs2(text):
        dcs = 0x08
        if udh:
            ud_raw = bytes([len(udh)]) + udh + text.encode('utf-16-be')
            udl = len(ud_raw)
        else:
            ud_raw = text.encode('utf-16-be')
            udl = len(ud_raw)
    else:
        dcs = 0x00
        if udh:
            ud_raw, udl = gsm7_pack_with_udh(udh, text)
        else:
            ud_raw = gsm7_pack(text)
            udl    = gsm7_septet_len(text)

    return bytes([fo]) + OA + bytes([0x00, dcs]) + scts + bytes([udl]) + ud_raw

def build_sms_submit(da_ton: int, da_npi: int, da_digits: str, text: str,
                     udh: Optional[bytes] = None) -> bytes:
    """Build SMS-SUBMIT TPDU (MTI=0x01)."""
    fo = 0x01
    if udh:
        fo |= 0x40
    mr   = random.randint(0, 255)
    digs = ''.join(ch for ch in da_digits if ch.isdigit())
    toa  = 0x80 | ((da_ton & 0x07) << 4) | (da_npi & 0x0F)
    DA   = bytes([len(digs), toa]) + bcd_encode(digs)

    if needs_ucs2(text):
        dcs = 0x08
        if udh:
            ud_raw = bytes([len(udh)]) + udh + text.encode('utf-16-be')
            udl = len(ud_raw)
        else:
            ud_raw = text.encode('utf-16-be')
            udl = len(ud_raw)
    else:
        dcs = 0x00
        if udh:
            ud_raw, udl = gsm7_pack_with_udh(udh, text)
        else:
            ud_raw = gsm7_pack(text)
            udl    = gsm7_septet_len(text)

    return bytes([fo, mr]) + DA + bytes([0x00, dcs, udl]) + ud_raw

def parse_tpdu_preview(tpdu: bytes, limit: int = 160) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """Best-effort extract (pid, dcs, text_preview) from an SMS TPDU."""
    if not tpdu or len(tpdu) < 2:
        return None, None, None
    fo  = tpdu[0]
    mti = fo & 0x03
    udhi = bool(fo & 0x40)

    try:
        if mti == 0x00:  # SMS-DELIVER
            idx = 1
            oa_len = tpdu[idx]; idx += 2 + (oa_len + 1) // 2
            if idx + 2 > len(tpdu): return None, None, None
            pid, dcs = tpdu[idx], tpdu[idx+1]; idx += 9  # +2 pid/dcs +7 scts
            udl = tpdu[idx]; idx += 1
            ud = tpdu[idx:]
        elif mti == 0x01:  # SMS-SUBMIT
            idx = 2
            da_len = tpdu[idx]; idx += 2 + (da_len + 1) // 2
            if idx + 2 > len(tpdu): return None, None, None
            pid, dcs = tpdu[idx], tpdu[idx+1]; idx += 2
            vpf = (fo >> 3) & 0x03
            if vpf == 0x02:   idx += 1
            elif vpf == 0x03: idx += 7
            udl = tpdu[idx]; idx += 1
            ud = tpdu[idx:]
        else:
            return None, None, None

        if dcs == 0x08:  # UCS-2
            start = (1 + ud[0]) if (udhi and ud) else 0
            text  = ud[start:].decode('utf-16-be', errors='ignore')[:limit]
        else:  # GSM 7-bit
            if udhi and ud:
                udhl = ud[0]
                hdr_oct = 1 + udhl
                hdr_sep = (hdr_oct * 8 + 6) // 7
                pad     = (7 - (hdr_oct * 8) % 7) % 7
                text    = gsm7_unpack(ud[hdr_oct:], max(0, udl - hdr_sep), pad, limit)
            else:
                text = gsm7_unpack(ud, min(udl, limit), 0, limit)

        return pid, dcs, text.replace('\n', '\\n').replace('\r', '\\r').replace('\x00', '\\x00')

    except Exception:
        return None, None, None

def _extract_tpdu_from_blob(blob: bytes) -> Optional[bytes]:
    """Given an OCTET STRING blob from MAP, return the innermost TPDU.
    Handles raw TPDU or RP-DATA wrapper (strips RP header + RP-User-Data IE).
    """
    if not blob:
        return None
    # Detect RP-DATA (RP-MTI 0x01 in low 3 bits)
    if len(blob) >= 3 and (blob[0] & 0x07) == 0x01:
        i = 2
        while i + 2 <= len(blob):
            iei = blob[i]; i += 1
            ielen = blob[i]; i += 1
            if i + ielen > len(blob): break
            ie = blob[i:i+ielen]; i += ielen
            if iei == 0x04 and ie:
                L = ie[0]
                return ie[1:1+L] if 1+L <= len(ie) else ie[1:]
    return blob  # assume raw TPDU


# ===========================================================================
# Section 6 — TCAP helpers
# ===========================================================================

def new_otid() -> bytes:
    return struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))

def build_dialogue_portion(acn: str, is_request: bool) -> bytes:
    """Build TCAP dialogue portion (AARQ for BEGIN, AARE for END/response)."""
    pv  = asn1_tl(0x80, b'\x07\x80')
    acn_enc = asn1_tl(0xA1, encode_oid(acn))
    dlg_oid = encode_oid(OID_TCAP_DIALOGUE)

    if is_request:
        aarq = asn1_tl(0x60, pv + acn_enc)
        inner = asn1_tl(0xA0, aarq)
    else:
        result  = asn1_tl(0xA2, b'\x02\x01\x00')
        rsd     = asn1_tl(0xA3, asn1_tl(0xA1, b'\x02\x01\x00'))
        aare    = asn1_tl(0x61, pv + acn_enc + result + rsd)
        inner   = asn1_tl(0xA0, aare)

    external = asn1_tl(0x28, dlg_oid + inner)
    return asn1_tl(0x6B, external)

def build_tcap_begin(otid_bytes: bytes, acn: str, component: bytes) -> bytes:
    """Build TCAP BEGIN with dialogue portion and one component."""
    otid = asn1_tl(0x48, otid_bytes)
    dlg  = build_dialogue_portion(acn, is_request=True)
    return asn1_tl(TCAP_BEGIN, otid + dlg + component)

def build_tcap_begin_dialogue_only(otid_bytes: bytes, acn: str) -> bytes:
    """Build TCAP BEGIN carrying only the dialogue portion (no component)."""
    otid = asn1_tl(0x48, otid_bytes)
    dlg  = build_dialogue_portion(acn, is_request=True)
    return asn1_tl(TCAP_BEGIN, otid + dlg)

def build_tcap_continue(our_otid: bytes, peer_otid: bytes, component: bytes) -> bytes:
    """Build TCAP CONTINUE with a component."""
    otid = asn1_tl(0x48, our_otid)
    dtid = asn1_tl(0x49, peer_otid)
    return asn1_tl(TCAP_CONTINUE, otid + dtid + component)

def build_tcap_end(peer_otid: bytes, component: bytes,
                   include_dialogue: bool = False, acn: str = '') -> bytes:
    """Build TCAP END.  Optionally includes AARE dialogue portion."""
    dtid = asn1_tl(0x49, peer_otid)
    dlg  = build_dialogue_portion(acn, is_request=False) if include_dialogue else b''
    return asn1_tl(TCAP_END, dtid + dlg + component)

def build_tcap_continue_response(peer_otid: bytes, acn: str) -> bytes:
    """Build a bare TCAP CONTINUE response (AARE, no component) for handshake."""
    our = new_otid()
    otid = asn1_tl(0x48, our)
    dtid = asn1_tl(0x49, peer_otid)
    dlg  = build_dialogue_portion(acn, is_request=False)
    return asn1_tl(TCAP_CONTINUE, otid + dtid + dlg)

def extract_tid(tcap: bytes, tag: int) -> Optional[bytes]:
    """Extract OTID (0x48) or DTID (0x49) from TCAP bytes."""
    node = asn1_read(tcap, 0)
    if not node: return None
    _, _, vs, ve, _ = node
    off = vs
    while off < ve:
        n = asn1_read(tcap, off)
        if not n: break
        t, _, nvs, nve, off = n
        if t == tag:
            return tcap[nvs:nve]
    return None

def get_otid(tcap: bytes) -> Optional[bytes]: return extract_tid(tcap, 0x48)
def get_dtid(tcap: bytes) -> Optional[bytes]: return extract_tid(tcap, 0x49)

def parse_tcap(tcap: bytes) -> Dict[str, Any]:
    """Parse a TCAP PDU.
    Returns dict with keys: tcap_tag, otid, dtid, invoke_id, op_code, msisdn.
    op_code is int for local ops, ('oid', str) for OID-based ops, None if absent.
    """
    result = {'tcap_tag': None, 'otid': None, 'dtid': None,
              'invoke_id': None, 'op_code': None, 'msisdn': None}

    def _read(buf, off): return asn1_read(buf, off)

    top = _read(tcap, 0)
    if not top: return result
    result['tcap_tag'] = top[0]
    _, _, vs, ve, _ = top

    # Walk top-level elements
    off = vs
    cp_range = None
    while off < ve:
        n = _read(tcap, off)
        if not n: break
        tag, _, nvs, nve, off = n
        if tag == 0x48: result['otid'] = tcap[nvs:nve]
        elif tag == 0x49: result['dtid'] = tcap[nvs:nve]
        elif tag == 0x6C: cp_range = (nvs, nve)

    if not cp_range: return result

    # Walk component portion
    cp_vs, cp_ve = cp_range
    coff = cp_vs
    while coff < cp_ve:
        cn = _read(tcap, coff)
        if not cn: break
        ctag, _, cvs, cve, coff = cn
        if ctag not in (0xA1, 0xA2, 0xA3, 0xA4): continue

        # Invoke ID (first 0x02 child)
        ioff = cvs
        fn = _read(tcap, ioff)
        if fn and fn[0] == 0x02:
            try: result['invoke_id'] = int.from_bytes(tcap[fn[2]:fn[3]], 'big')
            except: pass
            ioff = fn[4]

        if ctag == 0xA1:   # Invoke — look for op code
            scan = ioff
            while scan < cve and result['op_code'] is None:
                sn = _read(tcap, scan)
                if not sn: break
                st, _, svs, sve, scan = sn
                if st == 0x02 and (sve - svs) <= 2:
                    v = int.from_bytes(tcap[svs:sve], 'big')
                    if 1 <= v <= 255: result['op_code'] = v
                elif st == 0x80:
                    result['op_code'] = int.from_bytes(tcap[svs:sve], 'big')
                elif st == 0x06:
                    def _dec_oid(b):
                        if not b: return ''
                        arcs = [b[0]//40, b[0]%40]
                        v2 = 0
                        for byte in b[1:]:
                            v2 = (v2 << 7) | (byte & 0x7F)
                            if not (byte & 0x80):
                                arcs.append(v2); v2 = 0
                        return '.'.join(map(str, arcs))
                    result['op_code'] = ('oid', _dec_oid(tcap[svs:sve]))
                elif st == 0xA0:
                    inner = _read(tcap, svs)
                    if inner and inner[0] in (0x80, 0x02):
                        result['op_code'] = int.from_bytes(tcap[inner[2]:inner[3]], 'big')

        elif ctag == 0xA2:  # ReturnResultLast — extract op code from result seq
            rn = _read(tcap, ioff)
            if rn and rn[0] == 0x30:
                on = _read(tcap, rn[2])
                if on:
                    if on[0] == 0x02:
                        result['op_code'] = int.from_bytes(tcap[on[2]:on[3]], 'big')
                    elif on[0] == 0x80:
                        result['op_code'] = int.from_bytes(tcap[on[2]:on[3]], 'big')
        break

    result['msisdn'] = _scan_for_msisdn(tcap)
    return result

def _scan_for_msisdn(tcap: bytes) -> Optional[str]:
    """Heuristic scan for an MSISDN (TON=0x91, length 3-15) in raw TCAP bytes."""
    for i in range(len(tcap) - 5):
        if tcap[i] in (0x04, 0x80, 0x81, 0x82):
            L = tcap[i+1]
            if 3 <= L <= 15 and i + 2 + L <= len(tcap):
                blob = tcap[i+2:i+2+L]
                if blob and blob[0] == 0x91:
                    digits = bcd_decode(blob[1:])
                    if digits and len(digits) >= 8:
                        return digits
    return None

def get_component_tag(tcap: bytes) -> int:
    """Return the tag of the first component inside the component portion."""
    top = asn1_read(tcap, 0)
    if not top: return -1
    _, _, vs, ve, _ = top
    off = vs
    while off < ve:
        n = asn1_read(tcap, off)
        if not n: break
        tag, _, nvs, _, off = n
        if tag == 0x6C:
            inner = asn1_read(tcap, nvs)
            return inner[0] if inner else -1
    return -1

def extract_component_bytes(tcap: bytes) -> Optional[bytes]:
    """Return the raw component-portion TLV bytes (tag 0x6C + length + value)."""
    top = asn1_read(tcap, 0)
    if not top: return None
    _, _, vs, ve, _ = top
    off = vs
    while off < ve:
        n = asn1_read(tcap, off)
        if not n: break
        tag, length, nvs, nve, off = n
        if tag == 0x6C:
            if length < 0x80:
                hdr = bytes([0x6C, length])
            else:
                lb = length.to_bytes((length.bit_length()+7)//8, 'big')
                hdr = bytes([0x6C, 0x80 | len(lb)]) + lb
            return hdr + tcap[nvs:nve]
    return None

def _parse_abort_cause(tcap: bytes) -> str:
    """Parse TC-ABORT (0x67) and return a human-readable cause string.

    TC-ABORT may carry:
      P-Abort (tag 0x4A): provider-initiated, carries an ENUMERATED cause code.
      U-Abort (tag 0x6B): user-initiated — contains AARE dialogue PDU with
                          result, result-source-diagnostic, and offered ACN.
      Component portion (0x6C): may contain a ReturnError or Reject.
    """
    P_ABORT_CAUSES = {
        0: 'unrecognisedMessageType',
        1: 'unrecognisedTransactionID',
        2: 'badlyFormattedTransactionPortion',
        3: 'incorrectTransactionPortion',
        4: 'resourceUnavailable',
    }
    # AARE result codes (ITU-T X.217)
    AARE_RESULTS = {0: 'accepted', 1: 'reject-permanent', 2: 'reject-transient'}
    # result-source-diagnostic
    AARE_DIAG_USER = {
        0: 'null', 1: 'no-reason-given', 2: 'application-context-name-not-supported',
        3: 'calling-AP-title-not-recognized', 4: 'calling-AP-invocation-identifier-not-recognized',
        5: 'calling-AE-qualifier-not-recognized', 6: 'calling-AE-invocation-identifier-not-recognized',
        7: 'called-AP-title-not-recognized', 8: 'called-AP-invocation-identifier-not-recognized',
        9: 'called-AE-qualifier-not-recognized', 10: 'called-AE-invocation-identifier-not-recognized',
    }
    AARE_DIAG_PROV = {
        0: 'null', 1: 'no-reason-given', 2: 'no-common-acse-version',
    }

    try:
        top = asn1_read(tcap, 0)
        if not top or top[0] != TCAP_ABORT: return 'TC-ABORT (no detail)'
        _, _, vs, ve, _ = top
        off = vs
        while off < ve:
            n = asn1_read(tcap, off)
            if not n: break
            tag, _, nvs, nve, off = n

            if tag == 0x49: continue                    # DTID — skip

            if tag == 0x4A:                             # P-Abort cause
                code = int.from_bytes(tcap[nvs:nve], 'big') if nve > nvs else 0
                name = P_ABORT_CAUSES.get(code, f'cause#{code}')
                return f'P-Abort  cause={code} ({name})'

            if tag == 0x6B:                             # U-Abort dialogue portion
                # Walk inside 0x6B -> External (0x28) -> 0xA0 -> AARE (0x61)
                detail = _parse_uabort_aare(tcap, nvs, nve)
                return f'U-Abort  {detail}'

            if tag == 0x6C:                             # component in abort
                return parse_tcap_error(tcap)
    except Exception:
        pass
    return 'TC-ABORT (unparseable)'


def _parse_uabort_aare(tcap: bytes, vs: int, ve: int) -> str:
    """Parse the AARE dialogue PDU inside a U-Abort 0x6B tag.

    Structure:
      0x6B { External(0x28) { 0x06(oid) 0xA0 { AARE(0x61) {
        0xA1(acn OID)
        0xA2(result ENUM)
        0xA3(result-source-diagnostic CHOICE { 0xA1(user diag) | 0xA2(provider diag) })
      }}}}
    """
    AARE_RESULTS  = {0: 'accepted', 1: 'reject-permanent', 2: 'reject-transient'}
    DIAG_USER     = {
        0: 'null', 1: 'no-reason-given',
        2: 'application-context-name-not-supported',
    }
    DIAG_PROV     = {0: 'null', 1: 'no-reason-given', 2: 'no-common-acse-version'}

    try:
        offered_acn = None
        result_str  = None
        diag_str    = None

        # Walk 0x6B content
        off = vs
        while off < ve:
            n = asn1_read(tcap, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag != 0x28: continue            # External

            # Walk External
            eoff = nvs
            while eoff < nve:
                en = asn1_read(tcap, eoff)
                if not en: break
                et, _, evs, eve, eoff = en
                if et != 0xA0: continue         # encoding wrapper

                # Walk 0xA0
                aoff = evs
                while aoff < eve:
                    an = asn1_read(tcap, aoff)
                    if not an: break
                    at, _, avs, ave, aoff = an
                    if at != 0x61: continue     # AARE PDU

                    # Walk AARE
                    roff = avs
                    while roff < ave:
                        rn = asn1_read(tcap, roff)
                        if not rn: break
                        rt, _, rvs, rve, roff = rn

                        if rt == 0xA1:          # application-context-name
                            oid_n = asn1_read(tcap, rvs)
                            if oid_n and oid_n[0] == 0x06:
                                offered_acn = _decode_oid_bytes(tcap[oid_n[2]:oid_n[3]])

                        elif rt == 0xA2:        # result
                            enum_n = asn1_read(tcap, rvs)
                            if enum_n and enum_n[0] == 0x0A and rve > rvs:
                                val = tcap[enum_n[2]]
                                result_str = AARE_RESULTS.get(val, f'result#{val}')

                        elif rt == 0xA3:        # result-source-diagnostic
                            dn = asn1_read(tcap, rvs)
                            if dn:
                                inner = asn1_read(tcap, dn[2])
                                if inner and inner[3] > inner[2]:
                                    dval = tcap[inner[2]]
                                    if dn[0] == 0xA1:   # dialogue-service-user
                                        dname = DIAG_USER.get(dval, f'diag#{dval}')
                                        diag_str = f'user({dname})'
                                    elif dn[0] == 0xA2: # dialogue-service-provider
                                        dname = DIAG_PROV.get(dval, f'diag#{dval}')
                                        diag_str = f'provider({dname})'

        parts = []
        if result_str:  parts.append(f'result={result_str}')
        if diag_str:    parts.append(f'diagnostic={diag_str}')
        if offered_acn: parts.append(f'offered-ACN={offered_acn}')
        if parts:
            return '  '.join(parts)
    except Exception:
        pass
    return '(user-initiated, no AARE detail)'


def parse_tcap_error(tcap: bytes) -> str:
    """Parse a TCAP PDU containing a ReturnError (0xA3) or Reject (0xA4) component
    and return a human-readable description of the error.

    ReturnError structure:
      0xA3 { invokeId(0x02), errorCode(0x02|local), [params] }
      For sm-DeliveryFailure(27): params = 0x30 { 0x0A enumCause }

    Reject structure:
      0xA4 { invokeId(0x02|0x05/null), problem(0x80|0x81|0x82|0x83 + code) }
    """
    try:
        top = asn1_read(tcap, 0)
        if not top: return 'malformed TCAP'
        _, _, vs, ve, _ = top

        # Find component portion (0x6C)
        off = vs
        while off < ve:
            n = asn1_read(tcap, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag != 0x6C: continue

            # Read first component
            cn = asn1_read(tcap, nvs)
            if not cn: break
            ctag, _, cvs, cve, _ = cn

            if ctag == 0xA3:
                # ReturnError — parse invokeId then errorCode
                p = cvs
                # skip invokeId (0x02)
                id_n = asn1_read(tcap, p)
                if id_n and id_n[0] == 0x02: p = id_n[4]
                # error code
                ec_n = asn1_read(tcap, p)
                if not ec_n: return 'ReturnError (unreadable error code)'
                if ec_n[0] == 0x02:
                    code = int.from_bytes(tcap[ec_n[2]:ec_n[3]], 'big')
                    name = MAP_ERROR_CODES.get(code, f'error#{code}')
                    detail = f'ReturnError  code={code} ({name})'
                    # For sm-DeliveryFailure (localValue 32), parse sub-cause
                    if code == 32:
                        p2 = ec_n[4]
                        seq_n = asn1_read(tcap, p2)
                        if seq_n and seq_n[0] == 0x30:
                            enum_n = asn1_read(tcap, seq_n[2])
                            if enum_n and enum_n[0] == 0x0A:
                                sub = int.from_bytes(tcap[enum_n[2]:enum_n[3]], 'big')
                                sub_name = SM_DELIVERY_FAILURE_CAUSE.get(sub, f'cause#{sub}')
                                detail += f'  cause={sub} ({sub_name})'
                    return detail
                return 'ReturnError (unknown error code format)'

            elif ctag == 0xA4:
                # Reject — parse invokeId then problem tag+code
                p = cvs
                id_n = asn1_read(tcap, p)
                if id_n and id_n[0] in (0x02, 0x05): p = id_n[4]
                prob_n = asn1_read(tcap, p)
                if not prob_n: return 'Reject (unreadable problem)'
                prob_tag = prob_n[0]
                prob_code = int.from_bytes(tcap[prob_n[2]:prob_n[3]], 'big') if prob_n[3] > prob_n[2] else 0
                prob_tables = {
                    0x80: ('general',      TCAP_REJECT_GENERAL),
                    0x81: ('invoke',       TCAP_REJECT_INVOKE),
                    0x82: ('returnResult', TCAP_REJECT_RR),
                    0x83: ('returnError',  TCAP_REJECT_RE),
                }
                if prob_tag in prob_tables:
                    prob_type, tbl = prob_tables[prob_tag]
                    prob_name = tbl.get(prob_code, f'problem#{prob_code}')
                    return f'Reject  {prob_type}Problem={prob_code} ({prob_name})'
                return f'Reject  problem=0x{prob_tag:02X}/{prob_code}'

    except Exception:
        pass
    return 'unknown error component'


def _infer_acn_from_tcap(tcap: bytes) -> Optional[str]:
    """Extract the ACN OID string from a TCAP dialogue portion (if present).
    Structure: 0x6B -> 0x28 (External) -> 0x06 (dialogue-as-id) + 0xA0 -> 0x60/0x61 (AARQ/AARE)
               -> 0xA1 (context-application-name) -> 0x06 (ACN OID value)
    """
    try:
        top = asn1_read(tcap, 0)
        if not top: return None
        _, _, vs, ve, _ = top
        off = vs
        while off < ve:
            n = asn1_read(tcap, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag != 0x6B: continue
            # Walk inside dialogue portion (0x6B)
            p = nvs
            while p < nve:
                en = asn1_read(tcap, p)
                if not en: break
                et, _, evs, eve, p = en
                if et != 0x28: continue  # External
                # Walk inside External (0x28): skip 0x06 dialogue-as-id, find 0xA0
                q = evs
                while q < eve:
                    an = asn1_read(tcap, q)
                    if not an: break
                    at, _, avs, ave, q = an
                    if at != 0xA0: continue  # wrapper around AARQ/AARE
                    # Walk inside 0xA0: find 0x60 (AARQ) or 0x61 (AARE)
                    r = avs
                    while r < ave:
                        rn = asn1_read(tcap, r)
                        if not rn: break
                        rt, _, rvs, rve, r = rn
                        if rt not in (0x60, 0x61): continue
                        # Walk inside AARQ/AARE: find 0xA1 (context-application-name)
                        s = rvs
                        while s < rve:
                            sn = asn1_read(tcap, s)
                            if not sn: break
                            st, _, svs, sve, s = sn
                            if st == 0xA1:
                                oid_n = asn1_read(tcap, svs)
                                if oid_n and oid_n[0] == 0x06:
                                    return _decode_oid_bytes(tcap[oid_n[2]:oid_n[3]])
            break
    except Exception:
        pass
    return None

def _decode_oid_bytes(b: bytes) -> str:
    """Decode raw OID value bytes (without tag/length) to dotted string."""
    if not b: return ''
    arcs = [b[0] // 40, b[0] % 40]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            arcs.append(val); val = 0
    return '.'.join(map(str, arcs))


# ===========================================================================
# Section 7 — MAP component builders
# ===========================================================================

def _invoke(op: int, params: bytes, iid: Optional[int] = None) -> bytes:
    """Wrap params in an Invoke component with random (or given) invoke ID."""
    if iid is None:
        iid = random.randint(1, 127)
    iid_enc = asn1_tl(0x02, bytes([iid & 0xFF]))
    op_enc  = asn1_tl(0x02, bytes([op & 0xFF]))
    return asn1_tl(0x6C, asn1_tl(0xA1, iid_enc + op_enc + params))

def _return_result(iid: int, op: int, params: bytes) -> bytes:
    """Wrap in a ReturnResultLast component."""
    op_enc  = asn1_tl(0x02, bytes([op & 0xFF]))
    seq     = asn1_tl(0x30, op_enc + asn1_tl(0x30, params))
    content = asn1_tl(0x02, bytes([iid & 0xFF])) + seq
    return asn1_tl(0x6C, asn1_tl(0xA2, content))

def _return_result_ack(iid: int) -> bytes:
    """ReturnResultLast carrying only invoke ID (ack without parameters)."""
    return asn1_tl(0x6C, asn1_tl(0xA2, asn1_tl(0x02, bytes([iid & 0xFF]))))

def _return_error(iid: int, error_code: int, params: bytes = b'') -> bytes:
    """Build a ReturnError component (0xA3) with a local error code."""
    iid_enc  = asn1_tl(0x02, bytes([iid & 0xFF]))
    ec_enc   = asn1_tl(0x02, bytes([error_code & 0xFF]))
    return asn1_tl(0x6C, asn1_tl(0xA3, iid_enc + ec_enc + params))

def build_sri_sm_component(msisdn_addr: str, sc_addr: str) -> bytes:
    """Build SRI-SM Invoke component."""
    ton, npi, digits = parse_ton_npi(msisdn_addr)
    msisdn_as = build_address_string(ton, npi, digits)
    sc_ton, sc_npi, sc_digs = parse_ton_npi(sc_addr)
    sc_as = build_address_string(sc_ton, sc_npi, sc_digs)

    p_msisdn = asn1_tl(0x80, msisdn_as)
    p_pri    = asn1_tl(0x81, b'\xff')          # priority flag
    p_sca    = asn1_tl(0x82, sc_as)
    params   = asn1_tl(0x30, p_msisdn + p_pri + p_sca)
    return _invoke(MAP_SRI_SM, params)

def build_sri_sm_response(iid: int, msisdn: str, otid: bytes) -> bytes:
    """Build SRI-SM TCAP END response with IMSI and NNN.

    IMSI / NNN resolution rules (checked in order):
    1. Exact MSISDN match in SRI_TABLE  -> use values verbatim
    2. Pattern match (prefix/suffix/substring key):
         'abc*'  IMSI/NNN suffix wildcard: prefix 'abc' + last N digits of MSISDN
                 to pad to exactly 15 digits for IMSI, or 15 for NNN.
         'auto'  -> _generate_imsi(msisdn)  (IMSI) / msc_gt (NNN)
         '{msisdn}' / '{msin}' -> explicit substitution placeholders
    3. No match -> _generate_imsi() for IMSI, msc_gt for NNN
    """
    digs    = ''.join(ch for ch in msisdn if ch.isdigit())
    profile = _sri_lookup(msisdn)
    exact   = digs in SRI_TABLE and isinstance(SRI_TABLE.get(digs), dict)

    def _resolve(val: str, target_len: int, fallback_fn) -> str:
        """Resolve an IMSI or NNN template value against the current MSISDN.

        val ending with '*': fill remaining digits from the tail of MSISDN.
        val == 'auto' or empty: call fallback_fn().
        val containing {msisdn}/{msin}: explicit substitution.
        Plain digits: return as-is (truncated to target_len).
        """
        if not val or val.strip().lower() == 'auto':
            return fallback_fn()

        if val.endswith('*'):
            # Prefix + MSISDN tail to reach target_len digits
            prefix = ''.join(c for c in val[:-1] if c.isdigit())
            need   = target_len - len(prefix)
            if need <= 0:
                return prefix[:target_len]
            # Take the last `need` digits of MSISDN; pad with leading zeros if short
            tail = digs[-need:] if len(digs) >= need else digs.zfill(need)
            return (prefix + tail)[:target_len]

        # {msisdn} / {msin} substitution
        if '{' in val:
            msin_len = max(1, target_len - 5)   # reasonable MSIN length estimate
            msin = digs[-msin_len:] if len(digs) >= msin_len else digs.zfill(msin_len)
            val  = val.replace('{msisdn}', digs).replace('{msin}', msin)

        return ''.join(c for c in val if c.isdigit())[:target_len]

    if profile:
        raw_imsi = str(profile.get('imsi', ''))
        raw_nnn  = str(profile.get('nnn',  ''))
        if exact:
            # Exact match: verbatim digits, no wildcard expansion
            imsi   = ''.join(c for c in raw_imsi if c.isdigit()) or _generate_imsi(msisdn)
            nnn_gt = ''.join(c for c in raw_nnn  if c.isdigit()) or str(CFG.get('msc_gt', ''))
        else:
            imsi   = _resolve(raw_imsi, 15, lambda: _generate_imsi(msisdn))
            nnn_gt = _resolve(raw_nnn,  15, lambda: str(CFG.get('msc_gt', '')))
    else:
        imsi   = _generate_imsi(msisdn)
        nnn_gt = str(CFG.get('msc_gt', ''))

    # Safety truncation
    imsi   = imsi[:15]
    nnn_gt = nnn_gt[:15]

    imsi_el = asn1_tl(0x04, bcd_encode(imsi))
    nnn_as  = bytes([0x91]) + bcd_encode(nnn_gt)
    li      = asn1_tl(0xA0, asn1_tl(0x81, nnn_as))
    params  = imsi_el + li

    component = _return_result(iid, MAP_SRI_SM, params)
    dtid  = asn1_tl(0x49, otid)
    dlg   = build_dialogue_portion(ACN_SRI_SM, is_request=False)
    return asn1_tl(TCAP_END, dtid + dlg + component)

def build_mt_fsm_component(imsi: str, sc_addr: str, tpdu: bytes) -> bytes:
    """Build mt-forwardSM Invoke component."""
    sm_rp_da = asn1_tl(0x80, bcd_encode(imsi))
    sc_ton, sc_npi, sc_digs = parse_ton_npi(sc_addr)
    sm_rp_oa = asn1_tl(0x84, build_address_string(sc_ton, sc_npi, sc_digs))
    sm_rp_ui = asn1_tl(0x04, tpdu)
    params   = asn1_tl(0x30, sm_rp_da + sm_rp_oa + sm_rp_ui)
    return _invoke(MAP_MT_FSM, params)


def build_alert_sc_component(msisdn: str, sc_addr: str) -> bytes:
    """Build alertServiceCentre Invoke component (MAP op 64).

    AlertServiceCentreArg ::= SEQUENCE {
        msisdn      ISDN-AddressString,   -- subscriber who is now reachable
        serviceCentreAddress ISDN-AddressString
    }
    Sent by MSC/VLR to notify SMSC that a previously absent subscriber is now
    reachable so the SMSC can retry pending MT messages (MWI retry flow).
    """
    ton,    npi,    digs    = parse_ton_npi(msisdn)
    sc_ton, sc_npi, sc_digs = parse_ton_npi(sc_addr)
    ms_as = asn1_tl(0x04, build_address_string(ton,    npi,    digs))
    sc_as = asn1_tl(0x04, build_address_string(sc_ton, sc_npi, sc_digs))
    params = asn1_tl(0x30, ms_as + sc_as)
    return _invoke(MAP_ALERT_SC, params)


def build_report_sm_ds_component(msisdn: str, sc_addr: str, delivered: bool = True,
                                  absent_cause: Optional[int] = None) -> bytes:
    """Build reportSM-DeliveryStatus Invoke component (MAP op 47).

    ReportSM-DeliveryStatusArg ::= SEQUENCE {
        msisdn               ISDN-AddressString,
        serviceCentreAddress ISDN-AddressString,
        deliveryOutcome      SMDeliveryOutcome  -- ENUMERATED
            (successfulTransfer(0) | absentSubscriber(1) |
             msPermanentlyUnavailable(2))
        absentSubscriberDiagnosticSM  [0] INTEGER OPTIONAL
    }
    Sent to SMSC/HLR after MT delivery attempt to update message-waiting state.
    delivered=True  -> successfulTransfer(0)
    delivered=False -> absentSubscriber(1) with optional absent_cause
                    -> msPermanentlyUnavailable(2) if absent_cause is None
    """
    ton,    npi,    digs    = parse_ton_npi(msisdn)
    sc_ton, sc_npi, sc_digs = parse_ton_npi(sc_addr)
    ms_as = asn1_tl(0x04, build_address_string(ton,    npi,    digs))
    sc_as = asn1_tl(0x04, build_address_string(sc_ton, sc_npi, sc_digs))
    if delivered:
        outcome_val = 0   # successfulTransfer
    elif absent_cause is not None:
        outcome_val = 1   # absentSubscriber
    else:
        outcome_val = 2   # msPermanentlyUnavailable
    outcome = asn1_tl(0x0A, bytes([outcome_val]))
    body = ms_as + sc_as + outcome
    if not delivered and absent_cause is not None:
        body += asn1_tl(0x80, bytes([absent_cause & 0xFF]))
    params = asn1_tl(0x30, body)
    return _invoke(MAP_REPORT_SM_DS, params)


def _parse_atsi_request(tcap: bytes) -> Tuple[str, str]:
    """Parse anyTimeSubscriberInformation request.

    Returns (subscriber_id, requested_fields) where:
      subscriber_id   = 'MSISDN=xxx' or 'IMSI=xxx' or '?'
      requested_fields = comma-separated list of requested info fields

    AnyTimeSubscriptionInterrogationArg ::= SEQUENCE {
      subscriberIdentity CHOICE {
        imsi   [0] IMSI,                  -- context tag 0x80
        msisdn [1] ISDN-AddressString,    -- context tag 0x81
      }
      requestedSubscriptionInfo SEQUENCE {
        [1] requestedSS-Info              OPTIONAL,
        [2] odb                           OPTIONAL,
        [3] requestedBasicServiceList     OPTIONAL,
        [4] supportedVLR-CAMEL-Phases     OPTIONAL,
        [5] supportedSGSN-CAMEL-Phases    OPTIONAL,
        [7] msisdn-BS-List                OPTIONAL,
        [8] csg-SubscriptionDataRequested OPTIONAL,
        [9] cwData / [10] clipData / ...  OPTIONAL,
      }
      [1] gsmSCF-Address OPTIONAL
    }
    """
    REQUESTED_INFO = {
        0x81: 'SS-Info', 0x82: 'ODB', 0x83: 'BasicServiceList',
        0x84: 'VLR-CAMEL-Phases', 0x85: 'SGSN-CAMEL-Phases',
        0x87: 'MSISDN-BS-List', 0x88: 'CSG-Data',
        0x89: 'CW', 0x8A: 'CLIP', 0x8B: 'CLIR', 0x8C: 'Hold', 0x8D: 'ECT',
    }
    subscriber_id = '?'
    requested     = []
    try:
        cp = extract_component_bytes(tcap)
        if not cp: return subscriber_id, '?'
        top = asn1_read(cp, 0)
        if not top or top[0] != 0x6C: return subscriber_id, '?'
        inv = asn1_read(cp, top[2])
        if not inv or inv[0] != 0xA1: return subscriber_id, '?'

        # Skip invoke-id and op-code, find SEQUENCE params
        off = inv[2]
        while off < inv[3]:
            n = asn1_read(cp, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag != 0x30: continue            # outer SEQUENCE = AnyTimeSubInterrogationArg

            # Walk the SEQUENCE contents
            p = nvs
            while p < nve:
                pn = asn1_read(cp, p)
                if not pn: break
                pt, _, pvs, pve, p = pn

                if pt == 0x80:                  # IMSI (context [0])
                    subscriber_id = f'IMSI={bcd_decode(cp[pvs:pve])}'
                elif pt == 0x81:                # MSISDN (context [1] primitive)
                    subscriber_id = f'MSISDN={bcd_decode(cp[pvs+1:pve])}'  # skip TOA
                elif pt == 0xA1:                # MSISDN (context [1] constructed)
                    inner = asn1_read(cp, pvs)
                    if inner:
                        subscriber_id = f'MSISDN={bcd_decode(cp[inner[2]+1:inner[3]])}'
                elif pt == 0x30:                # requestedSubscriptionInfo SEQUENCE
                    q = pvs
                    while q < pve:
                        qn = asn1_read(cp, q)
                        if not qn: break
                        qt, _, _, _, q = qn
                        name = REQUESTED_INFO.get(qt, f'tag0x{qt:02X}')
                        requested.append(name)
            break
    except Exception:
        pass
    return subscriber_id, ', '.join(requested) if requested else 'none'


def build_atsi_response(iid: int, otid: bytes, acn: str) -> bytes:
    """Build anyTimeSubscriberInformation response (MAP op 62).

    AnyTimeSubscriptionInterrogationRes ::= SEQUENCE {
        -- all fields OPTIONAL — empty SEQUENCE is valid
        -- tells the querier: no special subscription data (no CAMEL, no ODB, etc.)
    }
    Encoded as 0x30 0x00 (empty SEQUENCE) as the result params.
    """
    component = _return_result(iid, MAP_ATSI, b'')
    dtid = asn1_tl(0x49, otid)
    dlg  = build_dialogue_portion(acn, is_request=False)
    return asn1_tl(TCAP_END, dtid + dlg + component)


def build_mo_fsm_component(oa_addr: str, smsc_addr: str, tpdu: bytes) -> bytes:
    oa_ton,  oa_npi,  oa_digs  = parse_ton_npi(oa_addr)
    sc_ton,  sc_npi,  sc_digs  = parse_ton_npi(smsc_addr)
    sm_rp_da = asn1_tl(0x84, build_address_string(sc_ton,  sc_npi,  sc_digs))
    sm_rp_oa = asn1_tl(0x82, build_address_string(oa_ton,  oa_npi,  oa_digs))
    sm_rp_ui = asn1_tl(0x04, tpdu)
    params   = asn1_tl(0x30, sm_rp_da + sm_rp_oa + sm_rp_ui)
    return _invoke(MAP_MO_FSM, params, iid=0)

def parse_sri_sm_result(tcap: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Extract (imsi, nnn_digits) from an SRI-SM ReturnResultLast TCAP PDU."""
    try:
        top = asn1_read(tcap, 0)
        if not top: return None, None
        _, _, vs, ve, _ = top
        off = vs
        while off < ve:
            n = asn1_read(tcap, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag != 0x6C: continue
            comp = asn1_read(tcap, nvs)
            if not comp or comp[0] != 0xA2: break
            # skip invoke ID
            p = comp[2]
            fn = asn1_read(tcap, p)
            if fn and fn[0] == 0x02: p = fn[4]
            # result sequence
            rn = asn1_read(tcap, p)
            if not rn or rn[0] != 0x30: break
            op = asn1_read(tcap, rn[2])
            if not op: break
            prm = asn1_read(tcap, op[4])
            if not prm or prm[0] != 0x30: break
            imsi = nnn = None
            pp = prm[2]
            while pp < prm[3]:
                el = asn1_read(tcap, pp)
                if not el: break
                et, _, evs, eve, pp = el
                if et == 0x04 and imsi is None:
                    imsi = bcd_decode(tcap[evs:eve])
                elif et == 0xA0 and nnn is None:
                    inner = asn1_read(tcap, evs)
                    if inner and inner[0] in (0x80, 0x81):
                        val = tcap[inner[2]:inner[3]]
                        if val and val[0] in (0x91, 0x81, 0xA1) and len(val) > 1:
                            nnn = bcd_decode(val[1:])
                        else:
                            nnn = bcd_decode(val)
            return imsi, nnn
    except Exception:
        pass
    return None, None

def is_final_mt_segment(tcap: bytes, invoke_id: int) -> bool:
    """Return True if this MT-FSM TCAP carries the last concatenated segment
    (or if it is not a multi-part message at all).
    """
    try:
        top = asn1_read(tcap, 0)
        if not top: return True
        _, _, vs, ve, _ = top
        off = vs
        while off < ve:
            n = asn1_read(tcap, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag != 0x6C: continue
            cp_off = nvs
            while cp_off < nve:
                cn = asn1_read(tcap, cp_off)
                if not cn: break
                ctag, _, cvs, cve, cp_off = cn
                if ctag != 0xA1: continue
                fn = asn1_read(tcap, cvs)
                if not fn or fn[0] != 0x02: continue
                if int.from_bytes(tcap[fn[2]:fn[3]], 'big') != invoke_id: continue
                # found our invoke — walk params for SM-RP-UI
                pp = fn[4]
                while pp < cve:
                    pn = asn1_read(tcap, pp)
                    if not pn: break
                    pt, _, pvs, pve, pp = pn
                    if pt in (0x30, 0xA0):
                        return _check_final_in_param(tcap[pvs:pve])
                return True
    except Exception:
        pass
    return True

def _check_final_in_param(param: bytes) -> bool:
    """Walk MAP parameter bytes to locate SM-RP-UI and read concat UDH."""
    def _read(b, o): return asn1_read(b, o)
    sm_rp_ui = None
    off = 0
    while off < len(param):
        n = _read(param, off)
        if not n: break
        tag, _, vs, ve, off = n
        if tag == 0x82:
            sm_rp_ui = param[vs:ve]; break
        elif tag in (0x04,) and (ve-vs) >= 10:
            sm_rp_ui = param[vs:ve]; break

    if not sm_rp_ui: return True
    tpdu = _extract_tpdu_from_blob(sm_rp_ui)
    if not tpdu or len(tpdu) < 2: return True
    fo = tpdu[0]
    if not (fo & 0x40): return True  # no UDHI
    mti = fo & 0x03
    if mti != 0x00: return True

    try:
        idx = 1
        oa_len = tpdu[idx]; idx += 2 + (oa_len+1)//2
        idx += 9  # pid + dcs + scts
        idx += 1  # udl
        ud = tpdu[idx:]
        if not ud: return True
        udhl = ud[0]
        udh = ud[1:1+udhl]
        p = 0
        while p + 2 <= len(udh):
            iei = udh[p]; p += 1
            ielen = udh[p]; p += 1
            if p + ielen > len(udh): break
            ie = udh[p:p+ielen]; p += ielen
            if iei == 0x00 and ielen == 3:
                return ie[2] == ie[1]
            if iei == 0x08 and ielen == 4:
                return ie[3] == ie[2]
    except Exception:
        pass
    return True


# ===========================================================================
# Section 8 — SCCP helpers
# ===========================================================================
def _pack_sccp_gt_addr(gt: str, ssn: int) -> bytes:
    """Build an SCCP called/calling party address using GTI=4 + SSN present.
    Returns length-octet + address bytes.
    """
    ai = (0x04 << 2) | SCCP_SSN_PRESENT  # GTI=4, SSN present
    body = bytes([ai, ssn])
    digs = ''.join(ch for ch in gt if ch.isdigit())
    even = len(digs) % 2 == 0
    np_es = (0x01 << 4) | (0x02 if even else 0x01)
    nai = 0x04
    body += bytes([0x00, np_es, nai])
    s = digs if even else digs + 'F'
    for i in range(0, len(s), 2):
        lo = int(s[i])
        hi = 0xF if s[i + 1] == 'F' else int(s[i + 1])
        body += bytes([(hi << 4) | lo])
    return bytes([len(body)]) + body

def build_sccp_udt(called_gt: str, called_ssn: int,
                   calling_gt: str, calling_ssn: int,
                   user_data: bytes, proto_class: int = 0x80) -> bytes:
    """Build SCCP UDT (0x09) PDU with GTI-4 addresses."""
    called_bytes = _pack_sccp_gt_addr(called_gt, called_ssn)
    calling_bytes = _pack_sccp_gt_addr(calling_gt, calling_ssn)
    assert called_bytes[0] + 1 == len(called_bytes)
    assert calling_bytes[0] + 1 == len(calling_bytes)

    # Pointer bytes are at offsets 2, 3, 4 respectively; each pointer is
    # relative to its own pointer byte (Q.713). Pointer values advance across
    # the parameter content bytes; the length octet itself is not counted.
    ptr_called = 3
    ptr_calling = ptr_called + called_bytes[0]
    ptr_data = ptr_called + called_bytes[0] + calling_bytes[0]

    hdr = struct.pack('!BBBBB',
        SCCP_UDT, proto_class,
        ptr_called,
        ptr_calling,
        ptr_data)
    return hdr + called_bytes + calling_bytes + bytes([len(user_data)]) + user_data

def build_sccp_xudt(called_gt: str, called_ssn: int,
                    calling_gt: str, calling_ssn: int,
                    user_data: bytes, proto_class: int = 0x80,
                    hop_counter: int = 0x0F) -> bytes:
    """Build SCCP XUDT (0x11) PDU with GTI-4 addresses."""
    called_bytes = _pack_sccp_gt_addr(called_gt, called_ssn)
    calling_bytes = _pack_sccp_gt_addr(calling_gt, calling_ssn)
    assert called_bytes[0] + 1 == len(called_bytes)
    assert calling_bytes[0] + 1 == len(calling_bytes)

    # Pointer bytes are at offsets 3, 4, 5, 6 respectively; each pointer is
    # relative to its own pointer byte (Q.713). Pointer values advance across
    # the parameter content bytes; the length octet itself is not counted.
    ptr_called = 4
    ptr_calling = ptr_called + called_bytes[0]
    ptr_data = ptr_called + called_bytes[0] + calling_bytes[0]
    ptr_opt = 0  # no optional part in this script

    hdr = struct.pack('!BBBBBBB',
        SCCP_XUDT, proto_class, hop_counter & 0xFF,
        ptr_called,
        ptr_calling,
        ptr_data,
        ptr_opt)
    return hdr + called_bytes + calling_bytes + bytes([len(user_data)]) + user_data

def build_sccp(called_gt: str, called_ssn: int,
               calling_gt: str, calling_ssn: int,
               user_data: bytes) -> bytes:
    """Build outbound SCCP using the configured message type (UDT/XUDT)."""
    mode = str(CFG.get('sccp_message_type', 'xudt')).strip().lower()
    if mode == 'udt':
        return build_sccp_udt(called_gt, called_ssn, calling_gt, calling_ssn, user_data)
    return build_sccp_xudt(
        called_gt, called_ssn, calling_gt, calling_ssn, user_data,
        hop_counter=int(CFG.get('sccp_hop_counter', 15)))

def parse_sccp_addresses(sccp: bytes) -> Tuple[Dict, Dict, int]:
    """Parse SCCP UDT/XUDT variable part and return
    (called_addr, calling_addr, data_len_field_offset).
    The returned data offset points to the one-byte user-data length field;
    TCAP starts at data_off + 1.
    """
    def _parse_addr(blob: bytes) -> Dict[str, Any]:
        if not blob:
            return {}
        ai = blob[0]
        gti = (ai >> 2) & 0x0F
        ssn_p = bool(ai & SCCP_SSN_PRESENT)
        pc_p = bool(ai & SCCP_PC_PRESENT)
        off = 1
        result: Dict[str, Any] = {}
        if pc_p and off + 2 <= len(blob):
            result['pc'] = struct.unpack('<H', blob[off:off + 2])[0]
            off += 2
        if ssn_p and off < len(blob):
            result['ssn'] = blob[off]
            off += 1
        if gti == 4 and off + 3 <= len(blob):
            result['gt'] = bcd_decode(blob[off + 3:]) or ''
        return result

    if len(sccp) < 5:
        return {}, {}, len(sccp)

    msg_type = sccp[0]
    if msg_type == SCCP_UDT:
        # [0]=type [1]=class [2]=ptr called [3]=ptr calling [4]=ptr data
        base = 2
    elif msg_type == SCCP_XUDT:
        # [0]=type [1]=class [2]=hop [3]=ptr called [4]=ptr calling [5]=ptr data [6]=ptr optional
        if len(sccp) < 7:
            return {}, {}, len(sccp)
        base = 3
    else:
        return {}, {}, len(sccp)

    if base + 3 > len(sccp):
        return {}, {}, len(sccp)

    # Each pointer is relative to its own pointer byte (Q.713).
    cd_start = base + sccp[base]
    cg_start = (base + 1) + sccp[base + 1]
    data_off = (base + 2) + sccp[base + 2]

    cd_len = sccp[cd_start] if cd_start < len(sccp) else 0
    called = _parse_addr(sccp[cd_start + 1:cd_start + 1 + cd_len])
    cg_len = sccp[cg_start] if cg_start < len(sccp) else 0
    calling = _parse_addr(sccp[cg_start + 1:cg_start + 1 + cg_len])

    return called, calling, data_off
# ===========================================================================
# Section 9 — M3UA helpers
# ===========================================================================

def build_m3ua(msg_class: int, msg_type: int, params: bytes) -> bytes:
    length = 8 + len(params)
    return struct.pack('!BBBBI', 1, 0, msg_class, msg_type, length) + params

def build_m3ua_ack(req_class: int, req_type: int) -> Optional[bytes]:
    ack_map = {
        (M3UA_ASPSM, M3UA_ASPUP): M3UA_ASPUP_ACK,
        (M3UA_ASPSM, M3UA_ASPDN): M3UA_ASPDN_ACK,
        (M3UA_ASPSM, M3UA_BEAT):  M3UA_BEAT_ACK,
        (M3UA_ASPTM, M3UA_ASPAC): M3UA_ASPAC_ACK,
        (M3UA_ASPTM, M3UA_ASPIA): M3UA_ASPIA_ACK,
    }
    if (req_class, req_type) not in ack_map:
        return None
    return build_m3ua(req_class, ack_map[(req_class, req_type)], b'')

def _m3ua_param(tag: int, value: bytes) -> bytes:
    L = 4 + len(value)
    pad = b'\x00' * (((L + 3) & ~3) - L)
    return struct.pack('!HH', tag, L) + value + pad

def build_m3ua_data(sccp: bytes, orig_pc: int, dest_pc: int) -> bytes:
    """Wrap SCCP data in M3UA DATA (transfer class)."""
    mtp3 = (struct.pack('!II', orig_pc, dest_pc)
            + bytes([3, int(CFG.get('network_indicator') or 0), 0, 0])  # SI=3 SCCP
            + sccp)
    params = b''
    if CFG.get('route_context') is not None:
        params += _m3ua_param(TAG_ROUTING_CTX, struct.pack('!I', CFG['route_context']))
    params += _m3ua_param(TAG_PROTO_DATA, mtp3)
    return build_m3ua(M3UA_TRANSFER, M3UA_DATA, params)

def parse_m3ua(raw: bytes) -> Optional[Dict]:
    """Parse M3UA header. Returns dict or None."""
    if len(raw) < 8: return None
    ver, _, cls, typ, length = struct.unpack('!BBBBI', raw[:8])
    if ver != 1 or length < 8 or length > len(raw): return None
    body = raw[8:length]
    params = {}
    off = 0
    while off + 4 <= len(body):
        tag, plen = struct.unpack('!HH', body[off:off+4])
        if plen < 4: break          # S4: malformed — plen=0/1/2/3 would loop or underflow
        val = body[off+4:off+plen]
        params[tag] = val
        off += (plen + 3) & ~3      # advance to next 4-byte-aligned parameter
        if off <= 0: break          # safety guard against wrap-around
    return {'class': cls, 'type': typ, 'params': params}


# ===========================================================================
# Section 10 — SRI lookup / IMSI generation helpers
# ===========================================================================

def _validate_gt(gt: str) -> Optional[str]:
    """Validate and normalise a GT string (TON.NPI.digits or bare digits).
    Returns cleaned digit string (max 15 digits), or None if invalid.
    """
    _, _, digits = parse_ton_npi(gt)
    if not digits:
        return None
    if len(digits) > 15:
        digits = digits[:15]    # E.164 max length
    return digits

def _sri_lookup(msisdn: str) -> Dict:
    """Look up SRI response profile for msisdn.
    Supports: exact, prefix (abc*), suffix (*abc), substring (*abc*).
    Longest matching key wins.
    """
    tbl = SRI_TABLE
    if msisdn in tbl and isinstance(tbl[msisdn], dict):
        return tbl[msisdn]
    best, best_len = {}, -1
    for k, v in tbl.items():
        if not isinstance(k, str) or not isinstance(v, dict): continue
        ps, pe = k.startswith('*'), k.endswith('*')
        if ps and pe and len(k) > 2:
            sub = k[1:-1]
            if sub in msisdn and len(sub) > best_len:
                best, best_len = v, len(sub)
        elif pe and not ps:
            pre = k[:-1]
            if msisdn.startswith(pre) and len(pre) > best_len:
                best, best_len = v, len(pre)
        elif ps and not pe:
            suf = k[1:]
            if msisdn.endswith(suf) and len(suf) > best_len:
                best, best_len = v, len(suf)
    return best

def _generate_imsi(msisdn: str) -> str:
    mcc = str(CFG.get('imsi_mcc') or '001')
    mnc = str(CFG.get('imsi_mnc') or '01')
    mcc = ''.join(ch for ch in mcc if ch.isdigit())[:3].ljust(3, '0')
    mnc = ''.join(ch for ch in mnc if ch.isdigit())[:3]
    if len(mnc) not in (2, 3): mnc = mnc[:2].ljust(2, '0')
    msin_len = max(1, 15 - len(mcc) - len(mnc))
    digs = ''.join(ch for ch in msisdn if ch.isdigit())
    msin = (digs[-msin_len:] if len(digs) >= msin_len else digs.zfill(msin_len))
    return (mcc + mnc + msin)[:15]


# ===========================================================================
# Section 11 — Log line builder
# ===========================================================================

_OP_NAMES = {
    MAP_SRI_SM:       'sendRoutingInfoForSM',
    MAP_MT_FSM:       'mt-forwardSM',
    MAP_MO_FSM:       'mo-forwardSM',
    MAP_REPORT_SM_DS: 'reportSM-DeliveryStatus',
    MAP_ALERT_SC:     'alertServiceCentre',
    MAP_ATSI:         'anyTimeSubscriberInformation',
}
_TCAP_NAMES = {
    TCAP_BEGIN:    'TCAP-BEGIN',
    TCAP_CONTINUE: 'TCAP-CONTINUE',
    TCAP_END:      'TCAP-END',
    TCAP_ABORT:    'TCAP-ABORT',
}

def _op_name(op_code) -> str:
    if isinstance(op_code, int):
        return _OP_NAMES.get(op_code, str(op_code))
    if isinstance(op_code, tuple) and op_code[0] == 'oid':
        return op_code[1] or 'oid'
    return '-'

def format_map_log_line(direction: str, opc: int, dpc: int,
                        calling_gt: Optional[str], called_gt: Optional[str],
                        tcap: bytes, op_code=None) -> str:
    """Build a single structured log line for a MAP PDU."""
    # TID
    tid = get_dtid(tcap) or get_otid(tcap)
    tid_str = tid.hex() if tid else '-'

    # Component type suffix
    ct = get_component_tag(tcap)
    ack_sfx = ' returnResultLast' if ct == 0xA2 else ''

    # Operation name — fall back to TCAP primitive name
    op_n = _op_name(op_code)
    if op_n == '-' and tcap:
        op_n = _TCAP_NAMES.get(tcap[0], f'TCAP-0x{tcap[0]:02X}')

    # SCA (for invokes only)
    sca = '-'
    if ct == 0xA1:
        sca = _extract_sca(tcap, op_code) or 'NA'

    # Extra: SMS content preview + OA/DA addresses
    extra = ''
    try:
        if isinstance(op_code, int) and op_code in (MAP_MO_FSM, MAP_MT_FSM):
            cp = extract_component_bytes(tcap)
            if cp:
                # Extract OA/DA from MAP component parameters
                oa_da = _extract_oa_da(cp, op_code)
                for blob in _iter_octet_strings(cp):
                    tpdu = _extract_tpdu_from_blob(blob)
                    pid, dcs, prev = parse_tpdu_preview(tpdu, 160) if tpdu else (None, None, None)
                    if pid is not None and dcs is not None and prev is not None:
                        extra = (f"{oa_da}"
                                 f" PID=0x{pid:02X} DCS=0x{dcs:02X}"
                                 f" LEN={len(prev)} TXT='{prev}'")
                        break
                if not extra and oa_da:
                    extra = oa_da
        elif isinstance(op_code, int) and op_code == MAP_SRI_SM and ct == 0xA2:
            imsi, nnn = parse_sri_sm_result(tcap)
            if imsi or nnn:
                extra = f" IMSI={imsi or '-'} NNN={nnn or '-'}"
    except Exception:
        pass

    return (f"{direction} {opc:<5} -> {dpc:<5} "
            f"TID={tid_str} "
            f"{calling_gt or '-'} -> {called_gt or '-':<18} "
            f"SCA={sca:<14} "
            f"{op_n}{ack_sfx}{extra}")

def _iter_octet_strings(buf: bytes):
    """Yield raw values of all 0x04 OCTET STRING TLVs found anywhere in buf."""
    def walk(b, s, e):
        off = s
        while off < e:
            n = asn1_read(b, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag == 0x04 and nve > nvs:
                yield b[nvs:nve]
            if tag in (0x30, 0xA0, 0xA1, 0xA2, 0xA3, 0x6C, 0x60, 0x61, 0x6B, 0x28):
                yield from walk(b, nvs, nve)
    top = asn1_read(buf, 0)
    if top:
        yield from walk(buf, top[2], top[3])

def _extract_sca(tcap: bytes, op_code) -> Optional[str]:
    """Extract service-centre address from an Invoke component for log display."""
    try:
        cp = extract_component_bytes(tcap)
        if not cp: return None
        tlv = asn1_read(cp, 0)
        if not tlv or tlv[0] != 0x6C: return None
        inv = asn1_read(cp, tlv[2])
        if not inv or inv[0] != 0xA1: return None
        # Walk invoke looking for SEQUENCE (0x30)
        off = inv[2]
        while off < inv[3]:
            n = asn1_read(cp, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag == 0x30:
                prefer = 0x82 if op_code == MAP_SRI_SM else 0x84
                other  = 0x84 if prefer == 0x82 else 0x82
                for want in (prefer, other):
                    p = nvs
                    while p < nve:
                        pn = asn1_read(cp, p)
                        if not pn: break
                        pt, _, pvs, pve, p = pn
                        if pt == want and pve > pvs:
                            return bcd_decode(cp[pvs+1:pve])  # skip TOA byte
                break
    except Exception:
        pass
    return None


def _extract_oa_da(cp: bytes, op_code: int) -> str:
    """Extract OA and DA addresses from a MAP component (MO-FSM or MT-FSM).

    MO-forwardSM (46):
      SM-RP-DA tag=0x84 (serviceCentreAddressDA) — the SMSC/DA
      SM-RP-OA tag=0x82 (msisdn)                 — the originator (OA/MSISDN)

    MT-forwardSM (44):
      SM-RP-DA tag=0x80 (imsi)                   — subscriber IMSI
      SM-RP-OA tag=0x84 (serviceCentreAddressOA) — the SMSC (OA)

    Also tries to extract OA/DA from the SMS-DELIVER/SUBMIT TPDU inside SM-RP-UI.
    Returns a formatted string ' OA=xxx DA=xxx' or '' if not found.
    """
    try:
        tlv = asn1_read(cp, 0)
        if not tlv or tlv[0] != 0x6C: return ''
        inv = asn1_read(cp, tlv[2])
        if not inv or inv[0] != 0xA1: return ''

        oa_digits = da_digits = None
        off = inv[2]
        while off < inv[3]:
            n = asn1_read(cp, off)
            if not n: break
            tag, _, nvs, nve, off = n
            if tag != 0x30: continue
            # Walk MAP parameters inside SEQUENCE
            p = nvs
            while p < nve:
                pn = asn1_read(cp, p)
                if not pn: break
                pt, _, pvs, pve, p = pn
                val = cp[pvs:pve]
                if not val: continue
                if op_code == MAP_MO_FSM:
                    # MO: OA=0x82(msisdn), DA=0x84(SC address)
                    if pt == 0x82 and len(val) > 1:
                        oa_digits = bcd_decode(val[1:])   # skip TOA
                    elif pt == 0x84 and len(val) > 1:
                        da_digits = bcd_decode(val[1:])
                    elif pt == 0x04:
                        # SM-RP-UI: extract DA from SMS-SUBMIT TPDU
                        tpdu = _extract_tpdu_from_blob(val)
                        if tpdu and len(tpdu) >= 4 and (tpdu[0] & 0x03) == 0x01:
                            # SMS-SUBMIT: FO + MR + DA_len + DA_TOA + DA_bcd
                            idx = 2
                            da_len = tpdu[idx]; idx += 1
                            if idx + 1 + (da_len + 1) // 2 <= len(tpdu):
                                da_digits = bcd_decode(tpdu[idx + 1: idx + 1 + (da_len + 1) // 2])
                elif op_code == MAP_MT_FSM:
                    # MT: OA=0x84(SC address), DA=0x80(IMSI of subscriber)
                    if pt == 0x84 and len(val) > 1:
                        oa_digits = bcd_decode(val[1:])
                    elif pt == 0x80:
                        da_digits = bcd_decode(val)       # IMSI, no TOA
                    elif pt == 0x04:
                        # SM-RP-UI: extract OA from SMS-DELIVER TPDU
                        tpdu = _extract_tpdu_from_blob(val)
                        if tpdu and len(tpdu) >= 4 and (tpdu[0] & 0x03) == 0x00:
                            # SMS-DELIVER: FO + OA_len + OA_TOA + OA_bcd
                            idx = 1
                            oa_len = tpdu[idx]; idx += 1
                            if idx + 1 + (oa_len + 1) // 2 <= len(tpdu):
                                oa_digits = bcd_decode(tpdu[idx + 1: idx + 1 + (oa_len + 1) // 2])
            break

        parts = []
        if oa_digits: parts.append(f'OA={oa_digits}')
        if da_digits: parts.append(f'DA={da_digits}')
        return (' ' + '  '.join(parts)) if parts else ''
    except Exception:
        return ''

# ===========================================================================
# Section 12 — Message statistics
# ===========================================================================

class Stats:
    """Thread-safe counters for all MAP traffic.

    Outgoing (we originate):
      mo_sent / mo_acked / mo_aborted / mo_timeout
      mt_sent / mt_acked / mt_aborted / mt_timeout
      sri_sent / sri_acked / sri_aborted / sri_timeout

    Incoming (peer sends to us):
      sri_rx / sri_resp_sent
      mt_rx  / mt_resp_sent  / mt_rejected_absent / mt_rejected_busy
      mo_rx
      alert_sc_rx / alert_sc_resp_sent
      rsmds_rx / rsmds_resp_sent
      atsi_rx  / atsi_resp_sent
    """
    _FIELDS = [
        'mo_sent',  'mo_acked',  'mo_aborted',  'mo_timeout',
        'mt_sent',  'mt_acked',  'mt_aborted',  'mt_timeout',
        'sri_sent', 'sri_acked', 'sri_aborted', 'sri_timeout',
        'alert_sc_sent', 'alert_sc_acked',
        'sri_rx',   'sri_resp_sent',
        'mt_rx',    'mt_resp_sent', 'mt_rejected_absent', 'mt_rejected_busy',
        'mo_rx',
        'alert_sc_rx', 'alert_sc_resp_sent',
        'rsmds_rx', 'rsmds_resp_sent',
        'atsi_rx',  'atsi_resp_sent',
    ]

    def __init__(self):
        self._lock = threading.Lock()
        for f in self._FIELDS:
            setattr(self, f, 0)

    def inc(self, field: str, n: int = 1):
        if field not in self._FIELDS:
            raise ValueError(f"Stats.inc: unknown field {field!r}")
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return {f: getattr(self, f) for f in self._FIELDS}

    def reset(self):
        with self._lock:
            for f in self._FIELDS:
                setattr(self, f, 0)

    def format_display(self) -> str:
        """Return a multi-line stats block for the menu / status command."""
        s = self.snapshot()

        def _row(label, sent, acked, aborted, timeout):
            no_resp = sent - acked - aborted - timeout
            parts = [
                f'sent={sent:<4}',
                f'acked={acked:<4}',
                f'aborted={aborted:<2}',
                f'timeout={timeout:<2}',
                f'no-resp={no_resp:<3}' if no_resp else '',
            ]
            return f'  {label:<8} ' + '  '.join(p for p in parts if p)

        lines = [
            '  ┌─ Outgoing (we send) ' + '─' * 38 + '┐',
            _row('MO-FSM',   s['mo_sent'],       s['mo_acked'],   s['mo_aborted'],   s['mo_timeout']),
            _row('MT-FSM',   s['mt_sent'],       s['mt_acked'],   s['mt_aborted'],   s['mt_timeout']),
            _row('SRI-SM',   s['sri_sent'],      s['sri_acked'],  s['sri_aborted'],  s['sri_timeout']),
            _row('AlertSC',  s['alert_sc_sent'],  s['alert_sc_acked'], 0, 0),
            '  ├─ Incoming (peer sends) ' + '─' * 35 + '┤',
            f'  {"SRI-SM":<8} rx={s["sri_rx"]:<4}  responded={s["sri_resp_sent"]:<4}',
            f'  {"MT-FSM":<8} rx={s["mt_rx"]:<4}  responded={s["mt_resp_sent"]:<4}'
            f'  absent={s["mt_rejected_absent"]:<3}  busy={s["mt_rejected_busy"]:<3}',
            f'  {"MO-FSM":<8} rx={s["mo_rx"]:<4}  (no response required)',
            f'  {"AlertSC":<8} rx={s["alert_sc_rx"]:<4}  responded={s["alert_sc_resp_sent"]:<4}',
            f'  {"ReportDS":<8} rx={s["rsmds_rx"]:<4}  responded={s["rsmds_resp_sent"]:<4}',
            f'  {"ATSI":<8} rx={s["atsi_rx"]:<4}  responded={s["atsi_resp_sent"]:<4}',
            '  └' + '─' * 59 + '┘',
        ]
        return '\n'.join(lines)


# ===========================================================================
# Section 13 — Dialogue state machine (multi-segment handshake)
# ===========================================================================

class DialogueState:
    """Tracks an outgoing multi-segment dialogue (MT long message handshake)."""
    __slots__ = ('our_otid', 'peer_otid', 'called_gt', 'calling_gt',
                 'components', 'next_idx', 'flow', 'acn', 'ts')

    def __init__(self, our_otid: bytes, called_gt: str, calling_gt: str,
                 components: List[bytes], flow: str, acn: str):
        self.our_otid  = our_otid
        self.peer_otid = None
        self.called_gt  = called_gt
        self.calling_gt = calling_gt
        self.components = components
        self.next_idx   = 0
        self.flow       = flow
        self.acn        = acn
        self.ts         = time.time()

    @property
    def key(self) -> str: return self.our_otid.hex()

    @property
    def total(self) -> int: return len(self.components)

    @property
    def pending(self) -> bool: return self.next_idx < self.total

    def peek(self) -> bytes: return self.components[self.next_idx]

    def advance(self): self.next_idx += 1


# ===========================================================================
# Section 13 — Server
# ===========================================================================

class STPServer:
    def __init__(self, host: str, port: int, log_level: str):
        self.host      = host
        self.port      = port
        self.log_level = log_level.upper()
        self.running   = False
        self._sock     = None

        # ASP state: key = "ip:port", value = dict(state, conn, addr)
        self._asps: Dict[str, Dict] = {}
        self._asp_lock = threading.Lock()

        # Outgoing dialogue state: key = our_otid.hex()
        self._dialogues: Dict[str, DialogueState] = {}
        self._dlg_lock = threading.Lock()

        # Pending MT correlations: key = our_otid.hex() (from SRI-SM BEGIN)
        self._pending_mt: Dict[str, Dict] = {}
        self._mt_lock = threading.Lock()

        # Outgoing single-BEGIN transaction tracking for TID correlation.
        # Covers: MO-FSM segments and single MT-FSM sends.
        # Key: otid.hex()  Value: {'type': 'MO'|'MT', 'called_gt': str, 'ts': float}
        self._pending_tx: Dict[str, Dict] = {}
        self._tx_lock = threading.Lock()

        # Message statistics
        self.stats = Stats()

        # Session start time (for uptime display on shutdown)
        self._start_time: float = time.time()

        # Load-test state — at most one active at a time (instance-level flags)
        self._load_active = False
        self._load_stop   = False

        self.log = make_logger(log_level)

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _info(self, msg):  self.log.info(msg)
    def _error(self, msg): self.log.error(msg)
    def _debug(self, msg):
        if self.log_level == 'DEBUG': self.log.debug(msg)

    def _log_pdu(self, direction, opc, dpc, calling_gt, called_gt, tcap, op_code=None):
        self._info(format_map_log_line(direction, opc, dpc, calling_gt, called_gt, tcap, op_code))

    # ------------------------------------------------------------------
    # Socket / transport
    # ------------------------------------------------------------------

    def _create_socket(self) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            for opt in ((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                        (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)):
                try: s.setsockopt(*opt)
                except Exception: pass
            return s
        except Exception as e:
            self._error(f"Socket create failed: {e}")
            return None

    def _pick_conn(self) -> Tuple[Optional[socket.socket], Optional[tuple]]:
        """Return best available (conn, addr) preferring ASP-ACTIVE."""
        with self._asp_lock:
            snap = dict(self._asps)
        for state in ('ASP-ACTIVE', 'ASP-INACTIVE'):
            for info in snap.values():
                if info.get('state') == state and info.get('conn'):
                    return info['conn'], info.get('addr')
        for info in snap.values():
            if info.get('conn'):
                return info['conn'], info.get('addr')
        return None, None

    def _conn_send(self, conn: socket.socket, data: bytes):
        """Send data on conn while holding that connection's send lock.
        Prevents interleaving when the loadtest thread and the recv/response
        thread both write to the same socket simultaneously.
        """
        lock = None
        with self._asp_lock:
            for info in self._asps.values():
                if info.get('conn') is conn:
                    lock = info.get('send_lock')
                    break
        if lock:
            with lock:
                conn.sendall(data)
        else:
            conn.sendall(data)

    # ------------------------------------------------------------------
    # Outbound send
    # ------------------------------------------------------------------

    def _send_tcap(self, tcap: bytes, called_gt: str, calling_gt: str,
                   called_ssn: int = None, calling_ssn: int = None) -> bool:
        conn, addr = self._pick_conn()
        if not conn:
            self._error("No active ASP connection available.")
            return False
        cd_ssn = int(called_ssn  if called_ssn  is not None else CFG.get('called_ssn',  8))
        cg_ssn = int(calling_ssn if calling_ssn is not None else CFG.get('calling_ssn', 8))
        try:
            sccp = build_sccp(called_gt, cd_ssn, calling_gt, cg_ssn, tcap)
            m3ua = build_m3ua_data(sccp, CFG['local_pc'], CFG['remote_pc'])
            self._conn_send(conn, m3ua)
            return True
        except Exception as e:
            self._error(f"Send error to {addr}: {e}")
            return False

    def _send_tcap_logged(self, tcap: bytes, called_gt: str, calling_gt: str,
                          called_ssn: int = None, calling_ssn: int = None,
                          op_code=None) -> bool:
        """Send TCAP and emit a Send log line."""
        ok = self._send_tcap(tcap, called_gt, calling_gt, called_ssn, calling_ssn)
        if ok:
            self._log_pdu('Send', CFG['local_pc'], CFG['remote_pc'],
                          calling_gt, called_gt, tcap, op_code)
        return ok

    def _send_response(self, tcap: bytes, calling_addr: Dict, op_code=None,
                       conn: socket.socket = None):
        """Send a response back to the peer that sent us a request, and log it."""
        called_gt   = calling_addr.get('gt') or CFG.get('remote_gt', '')
        calling_gt  = CFG.get('hlr_gt') or CFG.get('local_gt', '')
        called_ssn  = 8
        calling_ssn = 6
        if not called_gt or not calling_gt:
            self._error("Response GT missing")
            return
        try:
            sccp = build_sccp(called_gt, called_ssn, calling_gt, calling_ssn, tcap)
            m3ua = build_m3ua_data(sccp, CFG['local_pc'], CFG['remote_pc'])
            self._conn_send(conn, m3ua)
            self._log_pdu('Send', CFG['local_pc'], CFG['remote_pc'],
                          calling_gt, called_gt, tcap, op_code)
        except Exception as e:
            self._error(f"Response send error: {e}")

    # ------------------------------------------------------------------
    # M3UA / ASP state machine
    # ------------------------------------------------------------------

    def _handle_m3ua(self, raw: bytes, conn: socket.socket, addr: tuple):
        msg = parse_m3ua(raw)
        if not msg: return
        cls, typ = msg['class'], msg['type']
        key = f"{addr[0]}:{addr[1]}"

        if cls == M3UA_ASPSM:
            if typ == M3UA_ASPUP:
                ack = build_m3ua_ack(cls, typ)
                if ack: self._conn_send(conn, ack)
                with self._asp_lock:
                    self._asps[key].update(state='ASP-INACTIVE', conn=conn, addr=addr)
                self._info(f"M3UA  ASPUP  <- {key}  (ASP Up request)")
                self._info(f"M3UA  ASPUP-ACK -> {key}  state=ASP-INACTIVE")
                self._info(f"  M3UA link: local_pc={CFG['local_pc']}  remote_pc={CFG['remote_pc']}"
                           f"  route_context={CFG.get('route_context','?')}"
                           f"  network_indicator={CFG.get('network_indicator','?')}")
            elif typ == M3UA_ASPDN:
                ack = build_m3ua_ack(cls, typ)
                if ack: self._conn_send(conn, ack)
                with self._asp_lock:
                    if key in self._asps:
                        self._asps[key]['state'] = 'ASP-DOWN'
                self._info(f"M3UA  ASPDN  <- {key}  (ASP Down request)")
                self._info(f"M3UA  ASPDN-ACK -> {key}  state=ASP-DOWN")
            elif typ == M3UA_BEAT:
                t_recv = time.time()
                ack = build_m3ua_ack(cls, typ)
                if ack: self._conn_send(conn, ack)
                # Update per-connection BEAT stats
                with self._asp_lock:
                    if key in self._asps:
                        asp = self._asps[key]
                        asp['beat_rx']  = asp.get('beat_rx', 0) + 1
                        asp['beat_ack'] = asp.get('beat_ack', 0) + 1
                        prev = asp.get('beat_last')
                        asp['beat_prev'] = prev
                        asp['beat_last'] = t_recv
                        if prev is not None:
                            interval = t_recv - prev
                            ivs = asp.get('beat_intervals', [])
                            ivs.append(interval)
                            if len(ivs) > 20:
                                ivs.pop(0)
                            asp['beat_intervals'] = ivs
                self._debug(f"M3UA  BEAT <- {key}  BEAT-ACK sent")

        elif cls == M3UA_ASPTM:
            if typ == M3UA_ASPAC:
                ack = build_m3ua_ack(cls, typ)
                if ack: self._conn_send(conn, ack)
                with self._asp_lock:
                    self._asps[key].update(state='ASP-ACTIVE', conn=conn, addr=addr)
                self._info(f"M3UA  ASPAC  <- {key}  (ASP Active request)")
                self._info(f"M3UA  ASPAC-ACK -> {key}  state=ASP-ACTIVE")
                self._info(f"  ── MAP/SCCP link ESTABLISHED ──────────────────────────────")
                self._info(f"  SCTP peer   : {key}")
                self._info(f"  Local  GT={CFG['local_gt']}  PC={CFG['local_pc']}"
                           f"  SSN={CFG.get('ssn',6)}")
                self._info(f"  Remote GT={CFG['remote_gt']}  PC={CFG['remote_pc']}")
                self._info(f"  HLR GT={CFG['hlr_gt']}  MSC/VLR GT={CFG['msc_gt']}")
                self._info(f"  SMSC GT={CFG['smsc_gt']}  FSMSC GT={CFG['fsmsc_gt']}")
                self._info(f"  M3UA route_context={CFG.get('route_context','?')}"
                           f"  NI={CFG.get('network_indicator','?')}")
                self._info(f"  MAP ACNs handled:")
                self._info(f"    SRI-SM  : {ACN_SRI_SM}  (respond to incoming)")
                self._info(f"    MO-Relay: {ACN_MO_RELAY}  (originate MO-FSM)")
                self._info(f"    MT-Relay: {ACN_MT_RELAY}  (originate MT-FSM via SRI)")
                sri_n = len(SRI_TABLE)
                self._info(f"  SRI table   : {sri_n} entr{'y' if sri_n==1 else 'ies'} configured")
                self._info(f"  ───────────────────────────────────────────────────────────")
            elif typ == M3UA_ASPIA:
                ack = build_m3ua_ack(cls, typ)
                if ack: self._conn_send(conn, ack)
                with self._asp_lock:
                    if key in self._asps:
                        self._asps[key]['state'] = 'ASP-INACTIVE'
                self._info(f"M3UA  ASPIA  <- {key}  (ASP Inactive request)")
                self._info(f"M3UA  ASPIA-ACK -> {key}  state=ASP-INACTIVE")

        elif cls == M3UA_TRANSFER and typ == M3UA_DATA:
            proto = msg['params'].get(TAG_PROTO_DATA, b'')
            if len(proto) < 12: return
            opc = struct.unpack('!I', proto[0:4])[0]
            dpc = struct.unpack('!I', proto[4:8])[0]
            sccp = proto[12:]
            if sccp and sccp[0] in (SCCP_UDT, SCCP_XUDT):
                self._handle_sccp(sccp, opc, dpc, conn)

    # ------------------------------------------------------------------
    # SCCP dispatch
    # ------------------------------------------------------------------

    def _handle_sccp(self, sccp: bytes, opc: int, dpc: int, conn: socket.socket):
        if len(sccp) < 5: return
        msg_type = sccp[0]
        if msg_type not in (SCCP_UDT, SCCP_XUDT): return
        called, calling, data_off = parse_sccp_addresses(sccp)
        if data_off >= len(sccp): return
        # data_off points at the 1-byte user-data length field; TCAP starts +1
        if data_off + 1 >= len(sccp): return
        ud_len = sccp[data_off]
        ud_start = data_off + 1
        ud_end = min(len(sccp), ud_start + ud_len)
        tcap = sccp[ud_start:ud_end]
        if not tcap: return

        # --- Outgoing dialogue continuation hooks ---
        # Only fire for TC-CONTINUE / TC-END / TC-ABORT belonging to OUR dialogues.
        if tcap[0] == TCAP_CONTINUE:
            dtid = get_dtid(tcap)
            if dtid:
                with self._dlg_lock:
                    is_ours = dtid.hex() in self._dialogues
                if is_ours:
                    self._on_continue(tcap)
                    p = parse_tcap(tcap)
                    self._log_pdu('Recv', opc, dpc, calling.get('gt'), called.get('gt'),
                                  tcap, p['op_code'])
                    return

        elif tcap[0] == TCAP_END:
            dtid = get_dtid(tcap)
            if dtid:
                key = dtid.hex()

                # Check multi-segment dialogue (MT long message)
                with self._dlg_lock:
                    is_ours_dlg = key in self._dialogues
                if is_ours_dlg:
                    self._on_end(tcap)
                    p = parse_tcap(tcap)
                    self._log_pdu('Recv', opc, dpc, calling.get('gt'), called.get('gt'),
                                  tcap, p['op_code'])
                    return

                # Check single-BEGIN transaction (MO segment or single MT)
                with self._tx_lock:
                    tx = self._pending_tx.pop(key, None)
                if tx:
                    p = parse_tcap(tcap)
                    ct = get_component_tag(tcap)
                    flow = tx['type']
                    seg_info = (f" seg {tx['seg']}/{tx['total']}"
                                if 'seg' in tx else '')
                    if ct == 0xA2:
                        # TC-END with ReturnResultLast — normal ack
                        self._log_pdu('Recv', opc, dpc, calling.get('gt'), called.get('gt'),
                                      tcap, p['op_code'])
                        self._debug(f"TID matched: {flow}{seg_info} ack (RRL) "
                                    f"(DTID={key}) from {calling.get('gt','?')}")
                        if flow == 'MO':
                            self.stats.inc('mo_acked')
                        elif flow == 'MT':
                            self.stats.inc('mt_acked')
                        elif flow == 'ALERT_SC':
                            self.stats.inc('alert_sc_acked')
                            self._info(f"[alertSC] Acked by SMSC — subscriber retry should follow")
                    elif ct == -1:
                        # TC-END with no component — also a valid ack
                        self._log_pdu('Recv', opc, dpc, calling.get('gt'), called.get('gt'),
                                      tcap, p['op_code'])
                        self._debug(f"TID matched: {flow}{seg_info} ack (empty TC-END) "
                                    f"(DTID={key}) from {calling.get('gt','?')}")
                        if flow == 'MO':
                            self.stats.inc('mo_acked')
                        elif flow == 'MT':
                            self.stats.inc('mt_acked')
                        elif flow == 'ALERT_SC':
                            self.stats.inc('alert_sc_acked')
                            self._info(f"[alertSC] Acked by SMSC — subscriber retry should follow")
                    else:
                        # TC-END with error component (ReturnError/Reject)
                        err_desc = parse_tcap_error(tcap)
                        self._log_pdu('Recv', opc, dpc, calling.get('gt'), called.get('gt'),
                                      tcap, p['op_code'])
                        self._error(f"[{flow}{seg_info}] TID={key}  {err_desc}")
                    return

        elif tcap[0] == TCAP_ABORT:
            dtid = get_dtid(tcap)
            if dtid:
                key = dtid.hex()
                with self._dlg_lock:
                    removed_dlg = self._dialogues.pop(key, None)
                with self._tx_lock:
                    removed_tx = self._pending_tx.pop(key, None)
                with self._mt_lock:
                    removed_sri = self._pending_mt.pop(key, None)
                if removed_dlg or removed_tx or removed_sri:
                    if removed_sri:
                        flow = 'SRI'
                        self.stats.inc('sri_aborted')
                    elif removed_tx:
                        flow = removed_tx.get('type', '?')
                        self.stats.inc('mo_aborted' if flow == 'MO' else 'mt_aborted')
                    else:
                        flow = removed_dlg.flow
                        self.stats.inc('mo_aborted' if flow == 'MO' else 'mt_aborted')
                    # Parse TCAP-ABORT cause for detailed error info
                    abort_detail = _parse_abort_cause(tcap)
                    self._error(f"TC-ABORT [{flow}] TID={key}  {abort_detail}")
                    # If SMSC offered a different ACN, suggest updating config
                    if flow == 'ALERT_SC' and 'offered-ACN=' in abort_detail:
                        offered = abort_detail.split('offered-ACN=')[-1].split()[0]
                        if offered != CFG.get('alert_sc_acn', ''):
                            self._info(f"  Hint: SMSC wants ACN {offered} — "
                                       f"set alert_sc_acn={offered} in config or retry with that ACN")
                    self._log_pdu('Recv', opc, dpc, calling.get('gt'), called.get('gt'),
                                  tcap, None)
                    return

        # --- Full parse for incoming requests ---
        p = parse_tcap(tcap)
        self._log_pdu('Recv', opc, dpc, calling.get('gt'), called.get('gt'), tcap, p['op_code'])

        op = p['op_code']
        ct = get_component_tag(tcap)

        # SRI-SM ReturnResultLast (peer answered our outgoing SRI-SM)
        if ct == 0xA2 and op == MAP_SRI_SM:
            self._on_sri_sm_result(tcap)
            return

        # Incoming requests from SMSC/peer
        resp_tcap = None

        if isinstance(op, int) and p['invoke_id'] is not None:
            if op == MAP_SRI_SM and p['msisdn']:
                self.stats.inc('sri_rx')
                resp_tcap = build_sri_sm_response(p['invoke_id'], p['msisdn'],
                                                  p['otid'] or p['dtid'])

            elif op == MAP_MT_FSM:
                self.stats.inc('mt_rx')
                if tcap[0] == TCAP_END:
                    self._debug("MT-FSM TCAP END received — no response needed")
                else:
                    resp_tcap = self._build_mt_fsm_response(p['invoke_id'], tcap)

            elif op == MAP_MO_FSM:
                self.stats.inc('mo_rx')
                self._debug("mo-forwardSM received — no response required")

            elif op == MAP_REPORT_SM_DS:
                # reportSM-DeliveryStatus from SMSC — update our HLR delivery state
                self.stats.inc('rsmds_rx')
                outcome_str = self._parse_rsmds_outcome(tcap)
                msisdn_r = p.get('msisdn', '?')
                self._info(f"[reportSM-DS] MSISDN={msisdn_r}  {outcome_str}"
                           f"  (from {calling.get('gt','?')})")
                # Respond with empty ReturnResultLast in TC-END
                iid = p['invoke_id'] if p['invoke_id'] is not None else 0
                ack = _return_result_ack(iid)
                peer_otid = p.get('otid') or p.get('dtid')
                if peer_otid:
                    resp_tcap = build_tcap_end(peer_otid, ack,
                                               include_dialogue=(tcap[0] == TCAP_BEGIN),
                                               acn=ACN_MT_RELAY)

            elif op == MAP_ATSI:
                # anyTimeSubscriberInformation — querier (SMSC/gsmSCF) asks for
                # subscriber profile. We respond as HLR with empty result (no
                # special subscription: no CAMEL, no ODB, teleservices unrestricted).
                self.stats.inc('atsi_rx')
                sub_id, req_fields = _parse_atsi_request(tcap)
                self._info(f"[ATSI] {sub_id}  requested={req_fields}"
                           f"  (from {calling.get('gt','?')})")
                iid = p['invoke_id'] if p['invoke_id'] is not None else 0
                peer_otid = p.get('otid') or p.get('dtid')
                if peer_otid:
                    # Use the ACN from the incoming dialogue so we mirror what the
                    # querier sent (v2 or v3 — both get a correct response)
                    acn = _infer_acn_from_tcap(tcap) or ACN_ATSI_V3
                    resp_tcap = build_atsi_response(iid, peer_otid, acn)

            elif op == MAP_ALERT_SC:
                # Incoming alertServiceCentre — SMSC notifying us a subscriber is reachable
                self.stats.inc('alert_sc_rx')
                msisdn = p.get('msisdn', '?')
                self._info(f"[alertSC] Subscriber reachable: MSISDN={msisdn}  (from {calling.get('gt','?')})")
                # Respond with empty ReturnResultLast in TC-END
                iid = p['invoke_id'] if p['invoke_id'] is not None else 0
                ack = _return_result_ack(iid)
                peer_otid = p.get('otid') or p.get('dtid')
                if peer_otid:
                    resp_tcap = build_tcap_end(peer_otid, ack, include_dialogue=True, acn=ACN_ALERT_SC)

        elif p.get('otid') and tcap[0] == TCAP_BEGIN:
            # Unknown BEGIN — infer ACN from the incoming dialogue portion if present,
            # fall back to MT relay ACN which is most common for unexpected BEGINs.
            acn = _infer_acn_from_tcap(tcap) or ACN_MT_RELAY
            resp_tcap = build_tcap_continue_response(p['otid'], acn)

        if resp_tcap:
            self._send_response(resp_tcap, calling, op, conn)
            if op == MAP_SRI_SM:
                self.stats.inc('sri_resp_sent')
            elif op == MAP_MT_FSM:
                self.stats.inc('mt_resp_sent')
            elif op == MAP_ALERT_SC:
                self.stats.inc('alert_sc_resp_sent')
            elif op == MAP_REPORT_SM_DS:
                self.stats.inc('rsmds_resp_sent')
            elif op == MAP_ATSI:
                self.stats.inc('atsi_resp_sent')

    def _parse_rsmds_outcome(self, tcap: bytes) -> str:
        """Parse reportSM-DeliveryStatus and return human-readable outcome string.

        SMDeliveryOutcome ENUMERATED:
          0 = successfulTransfer
          1 = absentSubscriber
          2 = msPermanentlyUnavailable
        """
        OUTCOMES = {0: 'successfulTransfer', 1: 'absentSubscriber', 2: 'msPermanentlyUnavailable'}
        try:
            cp = extract_component_bytes(tcap)
            if not cp: return 'outcome=unknown'
            top = asn1_read(cp, 0)
            if not top or top[0] != 0x6C: return 'outcome=unknown'
            inv = asn1_read(cp, top[2])
            if not inv or inv[0] != 0xA1: return 'outcome=unknown'
            off = inv[2]
            while off < inv[3]:
                n = asn1_read(cp, off)
                if not n: break
                tag, _, nvs, nve, off = n
                if tag == 0x30:
                    # Walk SEQUENCE params for outcome ENUMERATED (0x0A) and absentDiag (0x80)
                    p = nvs
                    outcome_val = None
                    absent_diag = None
                    while p < nve:
                        pn = asn1_read(cp, p)
                        if not pn: break
                        pt, _, pvs, pve, p = pn
                        if pt == 0x0A and pve > pvs:
                            outcome_val = cp[pvs]
                        elif pt == 0x80 and pve > pvs:
                            absent_diag = cp[pvs]
                    if outcome_val is not None:
                        name = OUTCOMES.get(outcome_val, f'outcome#{outcome_val}')
                        result = f'outcome={outcome_val} ({name})'
                        if absent_diag is not None:
                            result += f'  absentDiag={absent_diag}'
                        return result
                    break
        except Exception:
            pass
        return 'outcome=unknown'

    def _build_mt_fsm_response(self, invoke_id: int, req_tcap: bytes) -> bytes:
        """Build MT-FSM response based on current mt_response_mode.

        Modes (set via 'mtmode' command or CFG['mt_response_mode']):
          'success' — ReturnResultLast (normal delivery ack)
          'absent'  — ReturnError absentSubscriberSM (code 27)
                      SMSC will buffer message and send alertServiceCentre later
          'busy'    — ReturnError subscriberBusyForMT-SMS (code 26)
        """
        mode = CFG.get('mt_response_mode', 'success').lower()
        peer_otid = get_otid(req_tcap)
        if not peer_otid: return b''

        if mode == 'absent':
            self.stats.inc('mt_rejected_absent')
            err = _return_error(invoke_id, 27)   # absentSubscriberSM
            self._info(f"[MT-FSM] Responding ReturnError absentSubscriberSM "
                       f"(mode=absent) — SMSC should buffer and retry via alertSC")
            return build_tcap_end(peer_otid, err,
                                  include_dialogue=(req_tcap[0] == TCAP_BEGIN),
                                  acn=ACN_MT_RELAY)

        if mode == 'busy':
            self.stats.inc('mt_rejected_busy')
            err = _return_error(invoke_id, 26)   # subscriberBusyForMT-SMS
            self._info(f"[MT-FSM] Responding ReturnError subscriberBusyForMT-SMS (mode=busy)")
            return build_tcap_end(peer_otid, err,
                                  include_dialogue=(req_tcap[0] == TCAP_BEGIN),
                                  acn=ACN_MT_RELAY)

        # Default: success
        final = is_final_mt_segment(req_tcap, invoke_id)
        ack   = _return_result_ack(invoke_id)
        if req_tcap[0] == TCAP_CONTINUE and not final:
            our = get_dtid(req_tcap) or new_otid()
            return build_tcap_continue(our, peer_otid, ack)
        else:
            return build_tcap_end(peer_otid, ack,
                                  include_dialogue=(req_tcap[0] == TCAP_BEGIN),
                                  acn=ACN_MT_RELAY)

    # ------------------------------------------------------------------
    # Outgoing dialogue continuation handlers
    # ------------------------------------------------------------------

    def _on_continue(self, tcap: bytes):
        """Peer sent TC-CONTINUE on one of our outgoing dialogues."""
        try:
            dtid = get_dtid(tcap)
            otid = get_otid(tcap)
            if not dtid: return
            key = dtid.hex()
            with self._dlg_lock:
                dlg = self._dialogues.get(key)
                if not dlg: return
                if otid and not dlg.peer_otid:
                    dlg.peer_otid = otid
            self._deliver_next(key)
        except Exception as e:
            self._error(f"_on_continue error: {e}\n{traceback.format_exc()}")

    def _on_end(self, tcap: bytes):
        """Peer sent TC-END on one of our outgoing MT dialogues."""
        try:
            dtid = get_dtid(tcap)
            if not dtid: return
            key = dtid.hex()
            with self._dlg_lock:
                dlg = self._dialogues.get(key)
                if not dlg: return
                if not dlg.pending:
                    del self._dialogues[key]
                    self._debug("Dialogue ended; queue empty.")
                    return
                comp       = dlg.peek()
                tail       = dlg.components[dlg.next_idx + 1:]
                called_gt  = dlg.called_gt
                calling_gt = dlg.calling_gt
                acn        = dlg.acn
                flow       = dlg.flow
                del self._dialogues[key]

            otid  = new_otid()
            begin = build_tcap_begin(otid, acn, comp)

            if tail:
                new_dlg = DialogueState(otid, called_gt, calling_gt, tail, flow, acn)
                with self._dlg_lock:
                    self._dialogues[otid.hex()] = new_dlg

            op = MAP_MT_FSM if flow == 'MT' else MAP_MO_FSM
            self._send_tcap_logged(begin, called_gt, calling_gt, op_code=op)
            self._debug(f"{flow}: peer TC-END — reopened BEGIN "
                        f"({len(tail)} more after this, new_otid={otid.hex()})")
        except Exception as e:
            self._error(f"_on_end error: {e}\n{traceback.format_exc()}")

    def _deliver_next(self, key: str):
        """Send the next queued component for dialogue `key`."""
        try:
            with self._dlg_lock:
                dlg = self._dialogues.get(key)
                if not dlg or not dlg.pending: return
                comp       = dlg.peek()
                last       = dlg.next_idx == dlg.total - 1
                our_otid   = dlg.our_otid
                peer_otid  = dlg.peer_otid
                called_gt  = dlg.called_gt
                calling_gt = dlg.calling_gt
                flow       = dlg.flow

            if peer_otid is None:
                self._debug(f"_deliver_next: peer_otid not yet known for key={key}, waiting")
                return

            if last:
                tcap = build_tcap_end(peer_otid, comp)
            else:
                tcap = build_tcap_continue(our_otid, peer_otid, comp)

            op = MAP_MT_FSM if flow == 'MT' else MAP_MO_FSM
            ok = self._send_tcap_logged(tcap, called_gt, calling_gt, op_code=op)
            if ok:
                with self._dlg_lock:
                    dlg = self._dialogues.get(key)
                    if dlg:
                        dlg.advance()
                        if not dlg.pending:
                            del self._dialogues[key]
            else:
                self._error(f"_deliver_next: send failed for dialogue key={key}")
        except Exception as e:
            self._error(f"_deliver_next error: {e}\n{traceback.format_exc()}")

    # ------------------------------------------------------------------
    # SRI-SM → MT-FSM flow
    # ------------------------------------------------------------------

    def send_sri_sm(self, msisdn_addr: str, originator: str, text: str,
                    sc_addr: Optional[str] = None) -> bool:
        """Originate SRI-SM for msisdn, then deliver MT-FSM after the response."""
        sc = sc_addr or CFG.get('fsmsc_gt', '')
        if not sc:
            self._error("SRI-SM: no SMSC address (fsmsc_gt)")
            return False
        _, _, digits = parse_ton_npi(msisdn_addr)
        if not digits:
            self._error("SRI-SM: MSISDN contains no digits — aborting")
            return False
        if len(digits) > 15:
            self._error(f"SRI-SM: MSISDN too long ({len(digits)} digits, max 15) — aborting")
            return False

        comp  = build_sri_sm_component(msisdn_addr, sc)
        otid  = new_otid()
        begin = build_tcap_begin(otid, ACN_SRI_SM, comp)

        key = otid.hex()
        with self._mt_lock:
            self._pending_mt[key] = {
                'originator': originator,
                'msisdn':     msisdn_addr,
                'text':       text,
                'sc_addr':    sc,
                'ts':         time.time(),
            }

        # SRI-SM SCCP routing:
        #   called_gt  = MSISDN digits, SSN=6 — routed by STP toward the HLR
        #   calling_gt = fsmsc_gt (our foreign SMSC identity), SSN=8
        #   This is correct: we are acting AS a foreign SMSC querying the HLR
        #   for routing info. The calling party must be the SMSC GT, not the
        #   local MSC/HLR GT.
        _, _, sc_digits = parse_ton_npi(sc)
        calling_gt_sri = sc_digits or sc   # strip TON.NPI prefix if present
        ok = self._send_tcap_logged(begin, digits, calling_gt_sri,
                                    called_ssn=6, calling_ssn=8,
                                    op_code=MAP_SRI_SM)
        if ok:
            self.stats.inc('sri_sent')
            self._debug(f"SRI-SM BEGIN sent for {msisdn_addr} (otid={key})")
        else:
            with self._mt_lock:
                self._pending_mt.pop(key, None)
        return ok

    def send_alert_sc(self, msisdn: str, smsc_gt: Optional[str] = None) -> bool:
        """Originate alertServiceCentre toward the SMSC (MAP op 64).

        We act as the MSC/VLR notifying the SMSC that a previously absent
        subscriber is now reachable so the SMSC can retry buffered MT messages.

        AlertServiceCentreArg:
          msisdn             = subscriber MSISDN (who is now reachable)
          serviceCentreAddr  = SMSC address (the one to notify / that buffered the MT)

        SCCP routing:
          called_gt  = SMSC GT, SSN=8
          calling_gt = msc_gt (we are the MSC/VLR), SSN=6
        """
        sc = smsc_gt or CFG.get('smsc_gt') or CFG.get('remote_gt', '')
        _, _, sc_digs = parse_ton_npi(sc)
        if not sc_digs:
            self._error("alertSC: no SMSC GT — set smsc_gt in config or use --smsc")
            return False
        _, _, ms_digs = parse_ton_npi(msisdn)
        if not ms_digs:
            self._error(f"alertSC: invalid MSISDN: {msisdn!r}")
            return False

        # sc_addr in the MAP component = the SMSC address that holds the buffered message.
        # This should be the fsmsc_gt we used as calling GT in the original SRI-SM,
        # because that's the address the SMSC will recognise.
        sc_addr_in_comp = CFG.get('fsmsc_gt') or sc_digs
        calling_gt = CFG.get('msc_gt') or CFG.get('local_gt', '')

        # Use ACN from config if set, otherwise try v3 (most common modern SMSCs)
        acn = CFG.get('alert_sc_acn', ACN_ALERT_SC)

        comp  = build_alert_sc_component(msisdn, sc_addr_in_comp)
        otid  = new_otid()
        begin = build_tcap_begin(otid, acn, comp)

        with self._tx_lock:
            self._pending_tx[otid.hex()] = {
                'type': 'ALERT_SC', 'called_gt': sc_digs, 'ts': time.time()
            }

        ok = self._send_tcap_logged(begin, sc_digs, calling_gt,
                                    called_ssn=8, calling_ssn=6,
                                    op_code=MAP_ALERT_SC)
        if ok:
            self.stats.inc('alert_sc_sent')
            self._info(f"[alertSC] Sent MSISDN={ms_digs} sc_addr={sc_addr_in_comp}"
                       f" -> SMSC={sc_digs}  ACN={acn}")
        else:
            with self._tx_lock:
                self._pending_tx.pop(otid.hex(), None)
        return ok

    def _on_sri_sm_result(self, tcap: bytes):
        """Handle SRI-SM ReturnResultLast — extract IMSI/NNN and send MT-FSM."""
        try:
            self._on_sri_sm_result_inner(tcap)
        except Exception as e:
            self._error(f"_on_sri_sm_result error: {e}\n{traceback.format_exc()}")

    def _on_sri_sm_result_inner(self, tcap: bytes):
        dtid = get_dtid(tcap)
        if not dtid:
            self._error("SRI-SM result: no DTID")
            return
        key = dtid.hex()
        with self._mt_lock:
            ctx = self._pending_mt.get(key)
        if not ctx:
            self._debug(f"SRI-SM result: no pending MT for key {key}")
            return

        imsi, nnn = parse_sri_sm_result(tcap)
        if not imsi or not nnn:
            self._error("SRI-SM result: IMSI/NNN missing — aborting MT")
            with self._mt_lock: self._pending_mt.pop(key, None)
            return

        self.stats.inc('sri_acked')
        self._debug(f"SRI-SM result: IMSI={imsi} NNN={nnn}")
        text    = ctx['text']
        sc_addr = ctx['sc_addr'] or CFG.get('fsmsc_gt', '')
        orig    = ctx['originator']

        oa_ton, oa_npi, oa_digs = parse_ton_npi(orig)
        segs = split_for_concat(text)
        ref  = random.randint(0, 255)

        if len(segs) == 1:
            tpdu  = build_sms_deliver(oa_ton, oa_npi, oa_digs, segs[0]['text'])
            comp  = build_mt_fsm_component(imsi, sc_addr, tpdu)
            otid  = new_otid()
            begin = build_tcap_begin(otid, ACN_MT_RELAY, comp)
            with self._tx_lock:
                self._pending_tx[otid.hex()] = {
                    'type': 'MT', 'called_gt': nnn, 'ts': time.time()}
            ok = self._send_tcap_logged(begin, nnn, sc_addr, op_code=MAP_MT_FSM)
            if not ok:
                with self._tx_lock:
                    self._pending_tx.pop(otid.hex(), None)
            else:
                self.stats.inc('mt_sent')
            self._debug(f"MT-FSM BEGIN (single) -> NNN={nnn} ok={ok}")
        else:
            # Long message — handshake: BEGIN (dialogue only) then components via CONTINUE/END
            components = []
            for idx, seg in enumerate(segs, 1):
                udh  = make_concat_udh(ref, len(segs), idx)
                tpdu = build_sms_deliver(oa_ton, oa_npi, oa_digs, seg['text'], udh)
                components.append(build_mt_fsm_component(imsi, sc_addr, tpdu))

            otid = new_otid()
            dlg  = DialogueState(otid, nnn, sc_addr, components, 'MT', ACN_MT_RELAY)
            with self._dlg_lock:
                self._dialogues[otid.hex()] = dlg

            begin = build_tcap_begin_dialogue_only(otid, ACN_MT_RELAY)
            ok = self._send_tcap_logged(begin, nnn, sc_addr, op_code=None)
            self._debug(f"MT handshake BEGIN (dialogue-only) sent (otid={otid.hex()}) ok={ok}")

        with self._mt_lock:
            self._pending_mt.pop(key, None)

    # ------------------------------------------------------------------
    # MO-FSM origination
    # ------------------------------------------------------------------

    def send_mo(self, oa: str, da: str, text: str,
                smsc: Optional[str] = None) -> bool:
        """Originate MO-FSM (mo-forwardSM) for the given addresses and text.

        Each MO segment — whether single or part of a long message — is sent
        as its own standalone TC-BEGIN with the component embedded.  The SMSC
        acks each BEGIN independently with TC-END (ReturnResultLast).  This
        matches the standard MO delivery pattern: there is no dialogue-only
        handshake for MO.
        """
        smsc = smsc or CFG.get('smsc_gt') or CFG.get('remote_gt', '')
        if not smsc:
            self._error("MO: no SMSC address")
            return False
        called_gt  = smsc
        calling_gt = CFG.get('msc_gt') or CFG.get('hlr_gt') or CFG.get('local_gt', '')
        if not calling_gt:
            self._error("MO: no calling GT")
            return False

        # S1/T8: validate OA and DA contain digits and are not oversized
        _, _, oa_digs_check = parse_ton_npi(oa)
        _, _, da_digs_check = parse_ton_npi(da)
        if not oa_digs_check:
            self._error(f"MO: originator address has no digits: {oa!r}")
            return False
        if not da_digs_check:
            self._error(f"MO: destination address has no digits: {da!r}")
            return False

        da_ton, da_npi, da_digs = parse_ton_npi(da)
        segs = split_for_concat(text)
        ref  = random.randint(0, 255)

        if len(segs) == 1:
            tpdu = build_sms_submit(da_ton, da_npi, da_digs, segs[0]['text'])
            comp = build_mo_fsm_component(oa, smsc, tpdu)
            otid_bytes = new_otid()
            tcap = build_tcap_begin(otid_bytes, ACN_MO_RELAY, comp)
            with self._tx_lock:
                self._pending_tx[otid_bytes.hex()] = {
                    'type': 'MO', 'called_gt': called_gt, 'ts': time.time()}
            ok = self._send_tcap_logged(tcap, called_gt, calling_gt, op_code=MAP_MO_FSM)
            if not ok:
                with self._tx_lock:
                    self._pending_tx.pop(otid_bytes.hex(), None)
            else:
                self.stats.inc('mo_sent')
            self._debug(f"MO-FSM BEGIN (single) ok={ok}")
            return ok

        # Long message: each segment is an independent TC-BEGIN.
        # The SMSC acks each one separately with TC-END; no shared dialogue state needed.
        ok_all = True
        for idx, seg in enumerate(segs, 1):
            udh  = make_concat_udh(ref, len(segs), idx)
            tpdu = build_sms_submit(da_ton, da_npi, da_digs, seg['text'], udh)
            comp = build_mo_fsm_component(oa, smsc, tpdu)
            otid_bytes = new_otid()
            tcap = build_tcap_begin(otid_bytes, ACN_MO_RELAY, comp)
            with self._tx_lock:
                self._pending_tx[otid_bytes.hex()] = {
                    'type': 'MO', 'seg': idx, 'total': len(segs),
                    'called_gt': called_gt, 'ts': time.time()}
            ok = self._send_tcap_logged(tcap, called_gt, calling_gt, op_code=MAP_MO_FSM)
            if not ok:
                with self._tx_lock:
                    self._pending_tx.pop(otid_bytes.hex(), None)
                self._error(f"MO: failed to send segment {idx}/{len(segs)}")
                ok_all = False
                break
            self.stats.inc('mo_sent')
            self._debug(f"MO-FSM BEGIN seg {idx}/{len(segs)} ok={ok}")
        return ok_all

    # ------------------------------------------------------------------
    # Stale entry cleanup
    # ------------------------------------------------------------------

    def _cleanup_stale(self):
        ttl = int(CFG.get('dialogue_ttl', 120))
        now = time.time()
        with self._dlg_lock:
            stale_dlg = [k for k, v in self._dialogues.items() if now - v.ts > ttl]
            for k in stale_dlg: del self._dialogues[k]
        with self._mt_lock:
            stale_mt = [k for k, v in self._pending_mt.items()
                        if now - v.get('ts', now) > ttl]
            for k in stale_mt: del self._pending_mt[k]
        with self._tx_lock:
            stale_tx = [(k, v) for k, v in self._pending_tx.items()
                        if now - v.get('ts', now) > ttl]
            for k, _ in stale_tx: del self._pending_tx[k]
        # Count timeouts per type and log details
        for _, v in stale_tx:
            flow = v.get('type', '')
            if flow == 'MO':   self.stats.inc('mo_timeout')
            elif flow == 'MT': self.stats.inc('mt_timeout')
        if stale_mt:
            self.stats.inc('sri_timeout', len(stale_mt))
        total = len(stale_dlg) + len(stale_mt) + len(stale_tx)
        if total:
            parts = []
            if stale_dlg: parts.append(f'dialogues={len(stale_dlg)}')
            if stale_mt:  parts.append(f'sri_pending={len(stale_mt)}')
            if stale_tx:
                mo_n = sum(1 for _,v in stale_tx if v.get('type')=='MO')
                mt_n = sum(1 for _,v in stale_tx if v.get('type')=='MT')
                parts.append(f'tx_mo={mo_n} tx_mt={mt_n}')
            self._debug(f"[cleanup] purged {total} stale entries: {', '.join(parts)}")

    def _cleanup_loop(self):
        interval = int(CFG.get('cleanup_interval', 30))
        while self.running:
            time.sleep(interval)
            try: self._cleanup_stale()
            except Exception as e: self._error(f"Cleanup error: {e}")

    # ------------------------------------------------------------------
    # Interactive menu helpers
    # ------------------------------------------------------------------

    # Lock so concurrent network log lines don't interleave with menu prompts
    _print_lock = threading.Lock()

    def _puts(self, text: str = ''):
        """Write directly to stdout (bypasses logger, used for menu UI)."""
        with self._print_lock:
            sys.stdout.write(text + '\n')
            sys.stdout.flush()

    def _prompt(self, label: str, default: str = '') -> str:
        """Print a labelled prompt with an editable default value.
        Uses readline pre-fill when available so the user can backspace/edit.
        Falls back to plain input() otherwise.
        """
        with self._print_lock:
            sys.stdout.flush()

        # Try readline pre-fill (works on Linux/macOS with a real TTY)
        filled = False
        if sys.stdin.isatty():
            try:
                import readline
                def _hook():
                    readline.insert_text(default)
                    readline.redisplay()
                readline.set_pre_input_hook(_hook)
                filled = True
            except Exception:
                pass

        hint = f'  [{default}]' if default and not filled else ''
        try:
            val = input(f'  {label}{hint}: ')
        except (EOFError, KeyboardInterrupt):
            return default
        finally:
            if filled:
                try:
                    import readline
                    readline.set_pre_input_hook(None)
                except Exception:
                    pass

        return val.strip() if val.strip() else default

    def _print_menu(self):
        """Print the interactive menu to stdout."""
        ex_oa = CFG.get('example_oa', '')
        ex_da = CFG.get('example_da', '')
        w = 64
        b = '║'
        sep_top = '╔' + '═' * (w - 2) + '╗'
        sep_mid = '╠' + '═' * (w - 2) + '╣'
        sep_bot = '╚' + '═' * (w - 2) + '╝'

        def row(left, right=''):
            content = f'  {left:<22}{right}'
            # Hard-clip to inner width, then pad to exact width
            inner = w - 2
            if len(content) > inner:
                content = content[:inner]
            pad = inner - len(content)
            return f'{b}{content}{" " * pad}{b}'

        with self._print_lock:
            print(sep_top)
            title = 'MAP SMS Gateway'
            print(f'{b}  {title:<{w-4}}{b}')
            lgt  = f'Local  GT={CFG["local_gt"]}  PC={CFG["local_pc"]}'
            rgt  = f'Remote GT={CFG["remote_gt"]}  PC={CFG["remote_pc"]}'
            print(f'{b}  {lgt:<{w-4}}{b}')
            print(f'{b}  {rgt:<{w-4}}{b}')
            print(sep_mid)
            print(row('1', 'Send MO  GSM-7 short  [load test]'))
            print(row('2', 'Send MT  GSM-7 short  [load test]'))
            print(row('3', 'Send MO  GSM-7 long  (multi-segment)'))
            print(row('4', 'Send MT  GSM-7 long  (multi-segment)'))
            print(row('5', 'Send MO  UCS-2 short (Chinese)'))
            print(row('6', 'Send MT  UCS-2 short (Chinese)'))
            print(row('7', 'Send MO  UCS-2 long  (Chinese concat)'))
            print(row('8', 'Send MT  UCS-2 long  (Chinese concat)'))
            print(sep_mid)
            print(row('9', 'Status'))
            print(row('10', 'Reload config'))
            print(row('11', 'Log level  toggle'))
            print(row('12  /  s', 'Show statistics'))
            print(row('13', 'Send alertServiceCentre -> SMSC'))
            mt_mode = CFG.get('mt_response_mode', 'success').upper()
            print(row('14', f'MT-FSM response mode  [{mt_mode}]'))
            print(sep_mid)
            print(row('0  /  exit', 'Exit'))
            print(row('m  /  menu', 'Show this menu'))
            print(row('or type any command directly'))
            # Live summary line — clipped to box inner width to prevent overflow
            s = self.stats.snapshot()
            summary = (f"MO tx={s['mo_sent']} rx={s['mo_acked']}  "
                       f"MT tx={s['mt_sent']} rx={s['mt_acked']}  "
                       f"SRI tx={s['sri_sent']} rx={s['sri_acked']}")
            inner = w - 4
            if len(summary) > inner:
                summary = summary[:inner-3] + '...'
            print(f'{b}  {summary:<{inner}}{b}')
            print(sep_bot)
            sys.stdout.flush()

    def _menu_alert_sc(self):
        """Guided alertServiceCentre prompt."""
        self._puts()
        self._puts('  ── Send alertServiceCentre ──')
        self._puts('  Notifies SMSC that a subscriber is now reachable.')
        self._puts('  SMSC should retry any buffered MT messages for this MSISDN.')
        msisdn = self._prompt('Subscriber MSISDN (ton.npi.digits)',
                              CFG.get('example_da', ''))
        smsc   = self._prompt('SMSC GT (blank = smsc_gt from config)',
                              CFG.get('smsc_gt', ''))
        self._puts()
        smsc_arg = smsc if smsc else None
        _, _, ms_digs = parse_ton_npi(msisdn)
        cmd = f'alert {msisdn}' + (f' --smsc {smsc}' if smsc else '')
        self._info(f'MAP SMS Gateway > {cmd}')
        self.send_alert_sc(msisdn, smsc_arg)

    def _menu_mtmode(self):
        """Toggle MT-FSM response mode: success → absent → busy → success."""
        cur = CFG.get('mt_response_mode', 'success')
        cycle = {'success': 'absent', 'absent': 'busy', 'busy': 'success'}
        new_mode = cycle.get(cur, 'success')
        CFG['mt_response_mode'] = new_mode
        msg = {
            'success': 'Normal delivery — ReturnResultLast (ack)',
            'absent':  'Absent subscriber — SMSC will buffer; send alertSC (13) to trigger retry',
            'busy':    'Subscriber busy — SMSC will retry after short delay',
        }
        self._info(f"MT-FSM response mode: {cur} → {new_mode}  ({msg[new_mode]})")

    def _menu_mo(self, preset_text: str = ''):
        """Guided MO prompt — single send or load test."""
        self._puts()
        self._puts('  ── Send MO (mo-forwardSM) ──')
        self._puts('  Counter syntax:  {n} = plain  {n:02d} = 2-digit pad  {n:03d} = 3-digit pad')
        oa      = self._prompt('Originator  (OA ton.npi.digits)',
                               CFG.get('example_oa', ''))
        da      = self._prompt('Destination (DA ton.npi.digits, e.g. 1.1.8170858114{n:02d})',
                               CFG.get('example_da', ''))
        text    = self._prompt('Message text  (e.g. mo test {n:04d})', preset_text or 'mo test')
        smsc    = self._prompt('SMSC GT (blank = default)', '')
        count_s = self._prompt('Number of messages  (1 = single)', '1')
        tps_s   = self._prompt('TPS  (messages per second, ignored if count=1)', '10')
        self._puts()
        try:
            count = max(1, int(count_s))
            tps   = max(0.1, float(tps_s))
        except ValueError:
            count, tps = 1, 10.0

        if count == 1:
            import re as _re
            def _sub1(tmpl):
                m = _re.search(r'\{n:0?(\d+)d\}', tmpl)
                if m: return tmpl.replace(m.group(0), '1'.zfill(int(m.group(1))))
                return tmpl.replace('{n}', '1')
            msg = _sub1(text)
            oa1 = _sub1(oa)
            da1 = _sub1(da)
            cmd = f'mo {oa1} {da1} {msg}' + (f' --smsc {smsc}' if smsc else '')
            self._info(f'MAP SMS Gateway > {cmd}')
            self._handle_cmd(cmd)
        else:
            self._puts(f'  Starting load test: {count} msgs @ {tps} TPS')
            has_n_da = '{n}' in da or '{n:' in da
            if has_n_da:
                da1 = self._run_loadtest.__func__  # placeholder
                # Show example first and last
                import re as _re
                def _preview(tmpl, val):
                    m = _re.search(r'\{n:0?(\d+)d\}', tmpl)
                    if m: return tmpl.replace(m.group(0), str(val).zfill(int(m.group(1))))
                    return tmpl.replace('{n}', str(val).zfill(len(str(count))))
                self._puts(f'  DA range: {_preview(da,1)} .. {_preview(da,count)}')
            elif '{n}' not in oa and '{n:' not in oa and not has_n_da:
                self._puts('  Note: OA and DA are fixed — consider using {n:02d} in the '
                           'address to vary destinations across messages')
            threading.Thread(
                target=self._run_loadtest,
                args=('MO', oa, da, text, count, tps, smsc),
                daemon=True, name='loadtest'
            ).start()

    def _menu_mt(self, preset_text: str = ''):
        """Guided MT prompt — single send or load test."""
        self._puts()
        self._puts('  ── Send MT (mt-forwardSM via SRI-SM) ──')
        self._puts('  Counter syntax:  {n} = plain  {n:02d} = 2-digit pad  {n:03d} = 3-digit pad')
        orig    = self._prompt('Originator  (OA ton.npi.digits)',
                               CFG.get('example_oa', ''))
        msisdn  = self._prompt('Destination MSISDN (DA ton.npi.digits, e.g. 1.1.8170858114{n:02d})',
                               CFG.get('example_da', ''))
        text    = self._prompt('Message text  (e.g. mt test {n:04d})', preset_text or 'mt test')
        smsc    = self._prompt('SMSC GT (blank = default)', '')
        count_s = self._prompt('Number of messages  (1 = single)', '1')
        tps_s   = self._prompt('TPS  (messages per second, ignored if count=1)', '10')
        self._puts()
        try:
            count = max(1, int(count_s))
            tps   = max(0.1, float(tps_s))
        except ValueError:
            count, tps = 1, 10.0

        if count == 1:
            import re as _re
            def _sub1(tmpl):
                m = _re.search(r'\{n:0?(\d+)d\}', tmpl)
                if m: return tmpl.replace(m.group(0), '1'.zfill(int(m.group(1))))
                return tmpl.replace('{n}', '1')
            msg  = _sub1(text)
            oa1  = _sub1(orig)
            da1  = _sub1(msisdn)
            cmd = f'mt {oa1} {da1} {msg}' + (f' --smsc {smsc}' if smsc else '')
            self._info(f'MAP SMS Gateway > {cmd}')
            self._handle_cmd(cmd)
        else:
            self._puts(f'  Starting load test: {count} msgs @ {tps} TPS')
            import re as _re
            def _preview(tmpl, val):
                m = _re.search(r'\{n:0?(\d+)d\}', tmpl)
                if m: return tmpl.replace(m.group(0), str(val).zfill(int(m.group(1))))
                return tmpl.replace('{n}', str(val).zfill(len(str(count))))
            has_n_msisdn = '{n}' in msisdn or '{n:' in msisdn
            if has_n_msisdn:
                self._puts(f'  MSISDN range: {_preview(msisdn,1)} .. {_preview(msisdn,count)}')
            elif '{n}' not in orig and '{n:' not in orig and not has_n_msisdn:
                self._puts('  Note: OA and DA are fixed — consider using {n:02d} in the '
                           'address to vary destinations across messages')
            threading.Thread(
                target=self._run_loadtest,
                args=('MT', orig, msisdn, text, count, tps, smsc),
                daemon=True, name='loadtest'
            ).start()

    @staticmethod
    def _subst_n(tmpl: str, n: int) -> str:
        """Replace {n} in tmpl with counter n, auto-zero-padded for address fields.

        Rules (in order):
          {n:Xd}   explicit width, e.g. {n:02d} -> '01','02',...
          {n}      auto-pad: counts existing digits in tmpl and pads so the
                   total digit count stays constant across all values of n.
                   e.g. '1.1.8170858114{n}' with 11 existing digits targets 12
                   -> n=1 becomes '01', n=10 becomes '10', n=100 becomes '100'
        """
        import re as _re
        # Explicit format spec: {n:Xd}
        fmt_m = _re.search(r'\{n:0?(\d+)d\}', tmpl)
        if fmt_m:
            width = int(fmt_m.group(1))
            return tmpl.replace(fmt_m.group(0), str(n).zfill(width))
        if '{n}' not in tmpl:
            return tmpl
        # Auto-pad: count existing digit characters in the template (excluding {n})
        existing_digits = sum(1 for c in tmpl.replace('{n}', '') if c.isdigit())
        if existing_digits > 0:
            # Target a round total digit count (next multiple of common lengths)
            # e.g. 11 existing -> target 12 so {n} fills 1+ chars
            target = existing_digits + len(str(n))
            # If the template clearly wants a fixed-length number, use 1 digit per {n}
            # unless n has grown past that — use at least len(str(n)) width
            pad = max(len(str(n)), target - existing_digits)
            # Actually: pad so total digits = existing + pad = round number
            # Heuristic: pad width = digits needed to reach next multiple of 2 or 3
            # Simplest: always pad to len(str(count)) so all values same width
            # We don't have count here, so pad to len(str(n)) minimum, zfill to 2 if n<10
            pad_width = max(2, len(str(n))) if n < 100 else len(str(n))
            return tmpl.replace('{n}', str(n).zfill(pad_width))
        return tmpl.replace('{n}', str(n))

    def _run_loadtest(self, flow: str, oa_tmpl: str, da_tmpl: str,
                      text_tmpl: str, count: int, tps: float,
                      smsc: str):
        """Send `count` messages at `tps` rate in a background thread.

        {n} is substituted in oa_tmpl, da_tmpl AND text_tmpl so each message
        can have a unique originator, destination and/or text.
        If {n} is absent from the text, [n/count] is appended automatically.
        Address fields without {n} are sent as-is (fixed address).
        """
        if self._load_active:
            self._info('[Load] Another load test is already running. '
                       'Type "stopload" to stop it first.')
            return

        self._load_active = True
        self._load_stop   = False
        interval  = 1.0 / tps
        sent      = 0
        errors    = 0
        t_start   = time.time()
        last_progress = t_start

        # Pre-compute pad width for {n} based on total count so all values same width
        n_width = len(str(count))  # e.g. count=100 -> width=3, count=10 -> width=2

        # Log what will vary per message
        varies = []
        if '{n}' in oa_tmpl or '{n:' in oa_tmpl:   varies.append('OA')
        if '{n}' in da_tmpl or '{n:' in da_tmpl:   varies.append('DA')
        if '{n}' in text_tmpl or '{n:' in text_tmpl: varies.append('text')
        vary_str = f'  varying: {", ".join(varies)}' if varies else '  fixed OA+DA (use {n} to vary)'

        self._info(f'[Load {flow}] Starting: {count} msgs @ {tps} TPS{vary_str}  '
                   f'(type "stopload" to abort)')
        try:
            for n in range(1, count + 1):
                if self._load_stop or not self.running:
                    self._info(f'[Load {flow}] Stopped by user at {sent}/{count}')
                    break

                # Substitute {n} with zero-padded counter (width = len(str(count)))
                def sub(tmpl):
                    import re as _re
                    fmt_m = _re.search(r'\{n:0?(\d+)d\}', tmpl)
                    if fmt_m:
                        w = int(fmt_m.group(1))
                        return tmpl.replace(fmt_m.group(0), str(n).zfill(w))
                    return tmpl.replace('{n}', str(n).zfill(n_width))

                oa  = sub(oa_tmpl)
                da  = sub(da_tmpl)
                msg = (sub(text_tmpl)
                       if ('{n}' in text_tmpl or '{n:' in text_tmpl)
                       else f'{text_tmpl} [{n}/{count}]')

                try:
                    if flow == 'MO':
                        ok = self.send_mo(oa, da, msg, smsc or None)
                    else:
                        ok = self.send_sri_sm(da, oa, msg, smsc or None)
                except Exception as e:
                    self._error(f'[Load {flow}] send exception at msg {n}: {e}')
                    ok = False

                if ok:
                    sent += 1
                else:
                    errors += 1

                now = time.time()
                if now - last_progress >= 1.0:
                    elapsed = now - t_start
                    actual  = sent / elapsed if elapsed > 0 else 0
                    pct     = int(sent * 100 / count)
                    self._info(f'[Load {flow}]  {sent:>5}/{count}  '
                               f'{pct:>3}%  actual={actual:.1f} tps  '
                               f'errors={errors}  elapsed={elapsed:.1f}s')
                    last_progress = now

                send_time = time.time() - t_start - (n - 1) * interval
                sleep_for = interval - send_time
                if sleep_for > 0:
                    time.sleep(sleep_for)

        except Exception as e:
            self._error(f'[Load {flow}] Unexpected error: {e}\n{traceback.format_exc()}')
        finally:
            elapsed = time.time() - t_start
            actual  = sent / elapsed if elapsed > 0 else 0
            self._info(f'[Load {flow}] Done. sent={sent}  errors={errors}  '
                       f'total={count}  elapsed={elapsed:.1f}s  '
                       f'actual_tps={actual:.1f}')
            self._load_active = False

    # ------------------------------------------------------------------
    # Console command dispatcher  (unchanged interface)
    # ------------------------------------------------------------------

    def _handle_cmd(self, line: str):
        parts = line.strip().split()
        if not parts: return
        cmd = parts[0].lower()

        # ---- numeric menu shortcuts (loaded from INI [menu_presets]) ----
        if cmd == '1':  self._menu_mo(MENU_PRESETS.get('short_gsm7_mo', '')); return
        if cmd == '2':  self._menu_mt(MENU_PRESETS.get('short_gsm7_mt', '')); return
        if cmd == '3':  self._menu_mo(MENU_PRESETS.get('long_gsm7', ''));     return
        if cmd == '4':  self._menu_mt(MENU_PRESETS.get('long_gsm7', ''));     return
        if cmd == '5':  self._menu_mo(MENU_PRESETS.get('short_ucs2', ''));    return
        if cmd == '6':  self._menu_mt(MENU_PRESETS.get('short_ucs2', ''));    return
        if cmd == '7':  self._menu_mo(MENU_PRESETS.get('long_ucs2', ''));     return
        if cmd == '8':  self._menu_mt(MENU_PRESETS.get('long_ucs2', ''));     return
        if cmd == '9':
            self._handle_cmd('status'); return
        if cmd == '10':
            self._handle_cmd('reload'); return
        if cmd == '11':
            new_lv = 'DEBUG' if self.log_level == 'INFO' else 'INFO'
            self.log_level = new_lv
            self.log = make_logger(new_lv)
            self._info(f"Log level toggled -> {new_lv}")
            return
        if cmd in ('12', 's'):
            self._handle_cmd('stats'); return
        if cmd == '13': self._menu_alert_sc(); return
        if cmd == '14': self._menu_mtmode();   return
        if cmd in ('m', 'menu'):
            self._print_menu(); return

        # ---- named commands ----
        if cmd in ('0', 'exit', 'quit'):
            self.stop()
            return

        elif cmd in ('help', '?'):
            self._puts()
            self._puts('  Direct commands:')
            self._puts('    mo <oa> <da> <text> [--smsc GT]')
            self._puts('    mt <oa> <da-msisdn> <text> [--smsc GT]')
            self._puts('    alert <msisdn> [--smsc GT]     — send alertServiceCentre to SMSC')
            self._puts('    mtmode [success|absent|busy]   — set MT-FSM response mode')
            self._puts('    status | stats | reset | reload | stopload | menu | exit')
            self._puts('  Menu shortcuts:')
            self._puts('    1=MO short (load test)   2=MT short (load test)')
            self._puts('    3=MO GSM-7 long          4=MT GSM-7 long')
            self._puts('    5=MO UCS-2 short         6=MT UCS-2 short')
            self._puts('    7=MO UCS-2 long          8=MT UCS-2 long')
            self._puts('    9=status  10=reload  11=log-level  12/s=stats')
            self._puts('    13=alertSC  14=MT-FSM mode toggle  0=exit')
            self._puts('  Load test counter: {n}=plain  {n:02d}=2-digit  {n:03d}=3-digit')
            self._puts('  MWI flow: set mode absent (14) → SMSC sends MT → buffered')
            self._puts('            then send alertSC (13) → SMSC retries MT')
            self._puts()

        elif cmd == 'status':
            with self._asp_lock:  snap = dict(self._asps)
            with self._dlg_lock:  dlg_n = len(self._dialogues)
            with self._mt_lock:   mt_n  = len(self._pending_mt)
            with self._tx_lock:   tx_n  = len(self._pending_tx)
            elapsed = time.time() - self._start_time
            h, rem = divmod(int(elapsed), 3600); m, s = divmod(rem, 60)
            uptime = f'{h}h {m}m {s}s' if h else (f'{m}m {s}s' if m else f'{s}s')
            self._info(f"--- Status  uptime={uptime} ---")
            if snap:
                for k, v in snap.items():
                    self._info(f"  ASP {k}: {v.get('state','?')}")
                    self._info(f"    {self._format_beat_stats(v)}")
            else:
                self._info("  No ASP associations")
            self._info(f"  Pending MT (SRI correlations):    {mt_n}")
            self._info(f"  Pending TX (MO/MT ack wait):      {tx_n}")
            self._info(f"  Active outgoing dialogues:        {dlg_n}")
            self._info(f"  Local  GT={CFG.get('local_gt')}  PC={CFG.get('local_pc')}")
            self._info(f"  Remote GT={CFG.get('remote_gt')}  PC={CFG.get('remote_pc')}")
            self._info("--------------")

        elif cmd == 'stats':
            # subcommand: 'stats reset' clears counters
            if len(parts) > 1 and parts[1].lower() == 'reset':
                self.stats.reset()
                self._info("Statistics counters reset.")
                return
            self._puts()
            self._puts(self.stats.format_display())
            self._puts()

        elif cmd == 'stopload':
            if self._load_active:
                self._load_stop = True
                self._info('[Load] Stop signal sent.')
            else:
                self._info('[Load] No load test is running.')

        elif cmd == 'reset':
            self.stats.reset()
            self._info("Statistics counters reset.")

        elif cmd == 'reload':
            if not _CFG_FILE:
                self._info("No --config file specified; nothing to reload.")
                return
            if load_config(_CFG_FILE):
                new_lv = CFG.get('log_level', self.log_level).upper()
                if new_lv != self.log_level:
                    self.log_level = new_lv
                    self.log = make_logger(new_lv)
                    self._info(f"Log level changed to {new_lv}")
                self._info(f"Config reloaded from {_CFG_FILE}")
            else:
                self._error(f"Config reload failed: {_CFG_FILE}")

        elif cmd == 'alert':
            # alert <msisdn> [--smsc GT]
            if len(parts) < 2:
                self._error("Usage: alert <msisdn> [--smsc GT]")
                return
            msisdn = parts[1]
            tokens, smsc = list(parts[2:]), None
            i = 0
            while i < len(tokens):
                if tokens[i] == '--smsc' and i+1 < len(tokens):
                    smsc = tokens[i+1]; del tokens[i:i+2]
                elif tokens[i].startswith('--smsc='):
                    smsc = tokens[i].split('=',1)[1]; del tokens[i]
                else: i += 1
            self.send_alert_sc(msisdn, smsc)

        elif cmd == 'mtmode':
            # mtmode [success|absent|busy]
            if len(parts) < 2:
                cur = CFG.get('mt_response_mode', 'success')
                self._info(f"MT-FSM response mode: {cur}  (options: success | absent | busy)")
                return
            mode = parts[1].lower()
            if mode not in ('success', 'absent', 'busy'):
                self._error(f"mtmode: invalid mode {mode!r} — use: success | absent | busy")
                return
            CFG['mt_response_mode'] = mode
            self._info(f"MT-FSM response mode set to: {mode}"
                       + (' — SMSC will buffer MT messages; use alertSC to trigger retry' if mode == 'absent' else '')
                       + (' — SMSC will retry after short delay' if mode == 'busy' else ''))
            return

        elif cmd == 'mo':
            if len(parts) < 4:
                self._error("Usage: mo <oa> <da> <text> [--smsc TON.NPI.DIGITS]")
                return
            oa, da = parts[1], parts[2]
            tokens, smsc = list(parts[3:]), None
            i = 0
            while i < len(tokens):
                if tokens[i] == '--smsc' and i+1 < len(tokens):
                    smsc = tokens[i+1]; del tokens[i:i+2]
                elif tokens[i].startswith('--smsc='):
                    smsc = tokens[i].split('=',1)[1]; del tokens[i]
                else: i += 1
            try:
                ok = self.send_mo(oa, da, ' '.join(tokens), smsc)
                if not ok: self._error("MO send failed.")
            except Exception as e:
                self._error(f"MO error: {e}\n{traceback.format_exc()}")

        elif cmd == 'mt':
            if len(parts) < 4:
                self._error("Usage: mt <oa> <da-msisdn> <text> [--smsc TON.NPI.DIGITS]")
                return
            orig, msisdn = parts[1], parts[2]
            tokens, smsc = list(parts[3:]), None
            i = 0
            while i < len(tokens):
                if tokens[i] == '--smsc' and i+1 < len(tokens):
                    smsc = tokens[i+1]; del tokens[i:i+2]
                elif tokens[i].startswith('--smsc='):
                    smsc = tokens[i].split('=',1)[1]; del tokens[i]
                else: i += 1
            try:
                ok = self.send_sri_sm(msisdn, orig, ' '.join(tokens), smsc)
                if not ok: self._error("MT send failed.")
            except Exception as e:
                self._error(f"MT error: {e}\n{traceback.format_exc()}")

        else:
            self._error(f"Unknown command '{cmd}'. Type 'menu' or 'help'.")

    # ------------------------------------------------------------------
    # Client thread
    # ------------------------------------------------------------------

    def _client_loop(self, conn: socket.socket, addr: tuple):
        key = f"{addr[0]}:{addr[1]}"
        self._info(f"SCTP association from {key}")
        buf = b''
        try:
            while self.running:
                try:
                    chunk = conn.recv(65536)
                    if not chunk:
                        if self.running:
                            self._info(f"M3UA  peer {key} disconnected (TCP closed by remote)")
                        else:
                            self._info(f"M3UA  connection to {key} closed (local shutdown)")
                        break
                    buf += chunk
                    while len(buf) >= 8:
                        msg_len = struct.unpack('!I', buf[4:8])[0]
                        if msg_len < 8 or msg_len > 65535:
                            self._error(f"Invalid M3UA length {msg_len} from {key}, dropping buffer")
                            buf = b''
                            break
                        if len(buf) < msg_len:
                            break
                        raw = buf[:msg_len]
                        buf = buf[msg_len:]
                        try:
                            self._handle_m3ua(raw, conn, addr)
                        except Exception as e:
                            self._error(f"PDU handling error from {key}: {e}\n{traceback.format_exc()}")
                            # Continue — one bad PDU must not kill the connection
                except socket.timeout:
                    continue
                except OSError as e:
                    import errno
                    # T9: retry on transient signals; break on real errors
                    if e.errno in (errno.EINTR, errno.EAGAIN):
                        continue
                    self._error(f"Socket error {key}: {e}")
                    break
                except Exception as e:
                    self._error(f"Recv loop error {key}: {e}\n{traceback.format_exc()}")
                    break
        finally:
            with self._asp_lock:
                self._asps.pop(key, None)
            try: conn.close()
            except: pass
            self._info(f"Connection closed: {key}")

    # ------------------------------------------------------------------
    # Main server loop
    # ------------------------------------------------------------------

    def start(self):
        self._sock = self._create_socket()
        if not self._sock: return
        try:
            self._sock.bind((self.host, self.port))
            self._sock.listen(5)
            self._sock.settimeout(1.0)
        except Exception as e:
            self._error(f"Bind/listen failed: {e}"); return

        self._print_banner()
        self.running = True

        threading.Thread(target=self._cleanup_loop, daemon=True, name='cleanup').start()

        def _console():
            # Show the interactive menu once on startup (TTY only)
            if sys.stdin.isatty() and self.log_level in ('INFO', 'DEBUG'):
                time.sleep(0.15)   # let banner finish printing first
                self._print_menu()

            while self.running:
                try:
                    # Show a compact prompt on TTY; silent on pipes
                    if sys.stdin.isatty():
                        with self._print_lock:
                            sys.stdout.write('\nMAP SMS Gateway > ')
                            sys.stdout.flush()
                    line = sys.stdin.readline()
                    if not line:
                        time.sleep(0.05)
                        continue
                    self._handle_cmd(line)
                except EOFError:
                    break
                except Exception as e:
                    self._error(f"Console error: {e}"); time.sleep(0.2)

        threading.Thread(target=_console, daemon=True, name='console').start()

        try:
            while self.running:
                try:
                    conn, addr = self._sock.accept()
                    key = f"{addr[0]}:{addr[1]}"
                    with self._asp_lock:
                        self._asps[key] = {
                            'state':      'ASP-DOWN',
                            'conn':       conn,
                            'addr':       addr,
                            'send_lock':  threading.Lock(),
                            'connected_at': time.time(),
                            # BEAT / heartbeat tracking
                            'beat_rx':    0,       # total BEATs received
                            'beat_ack':   0,       # total BEAT-ACKs sent
                            'beat_last':  None,    # timestamp of last BEAT received
                            'beat_prev':  None,    # timestamp of second-to-last BEAT (for interval)
                            'beat_intervals': [],  # rolling list of inter-beat intervals (last 20)
                        }
                    threading.Thread(target=self._client_loop, args=(conn, addr),
                                     daemon=True).start()
                except socket.timeout:
                    continue
                except socket.error as e:
                    if self.running: self._error(f"Accept error: {e}")
                    break
        finally:
            try: self._sock.close()
            except: pass
            self._info("Server stopped.")

    def stop(self):
        self._info("Stopping server...")
        self.running = False
        # Send ASPDN to every active/inactive ASP so the peer knows we are going down
        # gracefully rather than experiencing a sudden TCP RST.
        with self._asp_lock:
            snap = dict(self._asps)
        aspdn_msg = build_m3ua(M3UA_ASPSM, M3UA_ASPDN, b'')
        for key, info in snap.items():
            state = info.get('state', 'ASP-DOWN')
            conn  = info.get('conn')
            if conn and state in ('ASP-ACTIVE', 'ASP-INACTIVE'):
                try:
                    self._conn_send(conn, aspdn_msg)
                    self._info(f"M3UA  ASPDN -> {key}  (graceful shutdown notification)")
                except Exception as e:
                    self._debug(f"ASPDN send to {key} failed: {e}")
        # Give peers a moment to send ASPDN-ACK before the socket closes
        if snap:
            time.sleep(0.3)
        # Print full session summary before closing
        self._print_shutdown_summary()
        try: self._sock.close()
        except: pass
        self._info("Server stopped.")

    def _format_beat_stats(self, asp: Dict) -> str:
        """Return a one-line BEAT/heartbeat summary for a connection."""
        rx  = asp.get('beat_rx', 0)
        ivs = asp.get('beat_intervals', [])
        if rx == 0:
            return 'BEAT: none received yet'
        last_ts = asp.get('beat_last')
        since   = f'{time.time()-last_ts:.1f}s ago' if last_ts else '?'
        if ivs:
            avg_iv  = sum(ivs) / len(ivs)
            min_iv  = min(ivs)
            max_iv  = max(ivs)
            last_iv = ivs[-1]
            return (f'BEAT: rx={rx}  ack={asp.get("beat_ack",0)}'
                    f'  interval last={last_iv:.2f}s  avg={avg_iv:.2f}s'
                    f'  min={min_iv:.2f}s  max={max_iv:.2f}s'
                    f'  last_seen={since}')
        return f'BEAT: rx={rx}  ack={asp.get("beat_ack",0)}  last_seen={since}'

    def _print_banner(self):
        """Print startup config summary (log, not stdout — goes to file + console)."""
        if self.log_level not in ('INFO', 'DEBUG'): return
        sep = '=' * 60
        self._info(sep)
        self._info(f"MAP SMS Gateway listening on {self.host}:{self.port}")
        self._info(f"  Protocol stack : SCTP -> M3UA -> MTP3 -> SCCP(XUDT) -> TCAP -> MAP")
        self._info(f"  Local  GT={CFG['local_gt']}  PC={CFG['local_pc']}"
                   f"  SSN={CFG.get('ssn',6)}")
        self._info(f"  Remote GT={CFG['remote_gt']}  PC={CFG['remote_pc']}")
        self._info(f"  HLR GT={CFG['hlr_gt']}  MSC/VLR GT={CFG['msc_gt']}")
        self._info(f"  SMSC GT={CFG['smsc_gt']}  FSMSC GT={CFG['fsmsc_gt']}")
        self._info(f"  M3UA route_context={CFG.get('route_context','?')}"
                   f"  network_indicator={CFG.get('network_indicator','?')}")
        self._info(f"  Called SSN={CFG.get('called_ssn',8)}"
                   f"  Calling SSN={CFG.get('calling_ssn',8)}")
        sri_n = len(SRI_TABLE)
        self._info(f"  SRI table: {sri_n} entr{'y' if sri_n==1 else 'ies'}"
                   + (f"  [{', '.join(list(SRI_TABLE.keys())[:3])}{'...' if sri_n>3 else ''}]"
                      if sri_n else '  [empty — all MSISDNs will get generated IMSI]'))
        self._info(f"  Log level: {self.log_level}  |  Log file: {CFG.get('log_file') or 'map_sms_gateway.log'}")
        self._info(f"  Waiting for M3UA ASPUP from remote peer...")
        self._info(sep)

    def _print_shutdown_summary(self):
        """Print a full session summary to the log before stopping."""
        elapsed = time.time() - self._start_time
        h, rem  = divmod(int(elapsed), 3600)
        m, s    = divmod(rem, 60)
        uptime  = f'{h}h {m}m {s}s' if h else (f'{m}m {s}s' if m else f'{s}s')

        sep = '─' * 60
        self._info(sep)
        self._info(f'SESSION SUMMARY  uptime={uptime}')
        self._info(sep)

        # MAP traffic stats
        self._info(self.stats.format_display())

        # Per-connection BEAT / heartbeat info
        with self._asp_lock:
            snap = dict(self._asps)
        self._info('')
        if snap:
            self._info('M3UA connections:')
            for key, asp in snap.items():
                state = asp.get('state', '?')
                connected_at = asp.get('connected_at')
                conn_dur = f'  connected {time.time()-connected_at:.0f}s' if connected_at else ''
                self._info(f'  {key}  state={state}{conn_dur}')
                self._info(f'    {self._format_beat_stats(asp)}')
        else:
            self._info('M3UA connections: none')

        # Pending state
        with self._dlg_lock: dlg_n = len(self._dialogues)
        with self._mt_lock:  mt_n  = len(self._pending_mt)
        with self._tx_lock:  tx_n  = len(self._pending_tx)
        if dlg_n or mt_n or tx_n:
            self._info('')
            self._info(f'Pending at shutdown:  dialogues={dlg_n}  '
                       f'sri_correlations={mt_n}  tx_ack_wait={tx_n}')
        self._info(sep)

# ===========================================================================
# Entry point
# ===========================================================================

def main():
    import argparse
    ap = argparse.ArgumentParser(description='MAP SMS Gateway server — lab use only')
    ap.add_argument('--port',      type=int, default=None,
                    help='Listen port override (defaults to [transport] sctp_port in INI)')
    ap.add_argument('--log-level', choices=['ERROR','INFO','DEBUG'], default=None,
                    help='Logging verbosity override (defaults to [transport] log_level in INI)')
    ap.add_argument('--config',    type=str, default='map_sms_gateway.ini',
                    help='INI config file path (default: map_sms_gateway.ini)')
    args = ap.parse_args()

    global _CFG_FILE
    _CFG_FILE = args.config
    if args.config:
        if load_config(args.config):
            print(f"Config loaded from {args.config}")
        else:
            print(f"Warning: could not read {args.config}")

    if args.port is not None:
        CFG['sctp_port'] = args.port
    if args.log_level is not None:
        CFG['log_level'] = args.log_level

    host = CFG.get('sctp_host') or '0.0.0.0'
    port = int(CFG.get('sctp_port') or 2905)
    log_level = str(CFG.get('log_level') or 'INFO').upper()

    server = STPServer(host, port, log_level)
    try:
        server.start()
    except KeyboardInterrupt:
        print("Shutdown requested.")
        server.stop()
    except Exception as e:
        print(f"Fatal: {e}")
        server.stop()

if __name__ == '__main__':
    main()

