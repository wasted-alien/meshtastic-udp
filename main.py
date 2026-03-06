import socket
import struct
import mesh_pb2
import json
import time
import os
import logging
import base64
import hashlib
import re
import sys
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'meshtastic'))

try:
    import telemetry_pb2
except ImportError:
    telemetry_pb2 = None

# ─── Configuration ────────────────────────────────────────────────────────────
MCAST_GRP  = '224.0.0.69'
MCAST_PORT = 4403
IFACE_IP   = '0.0.0.0'

BASE_DIR          = 'packet_logs'
LOG_DIR           = 'logs'
PRIVATE_KEYS_FILE = 'private_keys.json'
NODES_DB_FILE     = 'nodes.json'

DEFAULT_CHANNEL_KEY = bytes([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
])

CHANNEL_KEYS = {
    0:  1,   # Primary channel – default key
    31: 1,   # Adjust based on your setup
}

# ─── In-memory state ──────────────────────────────────────────────────────────
PRIVATE_KEYS_BY_NODE   = {}   # node_num (int) → private_key bytes
PUBLIC_KEYS_BY_NODE    = {}   # node_num (int) → public_key bytes (derived)
PRIVATE_KEYS_BY_PUB    = {}   # pubkey hex / base64 → private_key bytes
PRIVATE_KEYS_BY_CLIENT = {}   # client URL → private_key bytes
NODE_DB                = {}   # node_num (int) → dict

# ─── Logging setup ────────────────────────────────────────────────────────────
os.makedirs(LOG_DIR, exist_ok=True)
_ts_str       = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
_log_file     = os.path.join(LOG_DIR, f'session_{_ts_str}.txt')
_jsonl_file   = os.path.join(LOG_DIR, f'session_{_ts_str}.jsonl')
_jsonl_fh     = open(_jsonl_file, 'a', encoding='utf-8')

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(_log_file), logging.StreamHandler()],
)
logging.info(f"Listening for multicast UDP on {MCAST_GRP}:{MCAST_PORT} on interface {IFACE_IP}...")
logging.info(f"JSONL log: {_jsonl_file}")


def write_jsonl(record: dict) -> None:
    """Append one JSON line to the session JSONL log."""
    record.setdefault('_ts', datetime.now().isoformat(timespec='milliseconds'))
    _jsonl_fh.write(json.dumps(record, ensure_ascii=False) + '\n')
    _jsonl_fh.flush()

# ─── Node DB ──────────────────────────────────────────────────────────────────

def load_node_db():
    global NODE_DB
    if os.path.exists(NODES_DB_FILE):
        try:
            with open(NODES_DB_FILE, 'r') as f:
                NODE_DB = {int(k): v for k, v in json.load(f).items()}
            logging.info(f"Node DB: loaded {len(NODE_DB)} nodes from {NODES_DB_FILE}")
        except Exception as e:
            logging.warning(f"Failed to load {NODES_DB_FILE}: {e}")
            NODE_DB = {}
    else:
        NODE_DB = {}


def save_node_db():
    try:
        with open(NODES_DB_FILE, 'w') as f:
            json.dump({str(k): v for k, v in NODE_DB.items()}, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.warning(f"Failed to save {NODES_DB_FILE}: {e}")


def update_node_db(node_num, **fields):
    """Merge *fields* into NODE_DB[node_num] and persist."""
    entry = NODE_DB.get(node_num, {})
    entry['hex'] = f'!{node_num:x}'
    entry['last_seen'] = datetime.now().isoformat(timespec='seconds')
    for k, v in fields.items():
        if v is not None and v != '' and v != 0:
            entry[k] = v
    NODE_DB[node_num] = entry
    save_node_db()
    logging.debug(f"Node DB updated: !{node_num:x} → {entry}")


def node_label(node_id):
    """Return 'Long Name (!hex)' if known, else just '!hex'."""
    if isinstance(node_id, int):
        node_num = node_id
        hex_str = f"!{node_id:x}"
    else:
        hex_str = str(node_id)
        try:
            node_num = int(hex_str.lstrip('!'), 16)
        except Exception:
            return hex_str
    info = NODE_DB.get(node_num)
    if info:
        name = info.get('long_name') or info.get('short_name')
        if name:
            return f"{name} ({hex_str})"
    return hex_str

# ─── Key parsing ──────────────────────────────────────────────────────────────

def parse_meshtastic_key(key):
    """Parse key from int (0-10), bytes, hex string, or base64. Returns bytes."""
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        s = key.strip()
        try:
            return bytes.fromhex(s[2:] if s.lower().startswith('0x') else s)
        except Exception:
            try:
                return base64.b64decode(s)
            except Exception:
                logging.warning(f"Could not parse key string: {key}")
                return b''
    if isinstance(key, int):
        if key == 0:
            return b''
        if key == 1:
            return DEFAULT_CHANNEL_KEY
        if 2 <= key <= 10:
            k = bytearray(DEFAULT_CHANNEL_KEY)
            k[-1] = (k[-1] + (key - 1)) & 0xFF
            return bytes(k)
        logging.warning(f"Invalid meshtastic key shorthand: {key}")
        return b''
    return b''


def _try_base64_urlsafe_decode(s: str):
    s2 = s.replace('-', '+').replace('_', '/')
    s2 += '=' * ((-len(s2)) % 4)
    try:
        return base64.b64decode(s2)
    except Exception:
        return None


def parse_pubkey_from_client_id(client_url: str):
    """Extract the 32-byte X25519 public key from a Meshtastic client URL fragment.

    The URL fragment is a url-safe-base64-encoded protobuf. We scan it for the
    first 32-byte length-delimited field (the pubkey).
    """
    if not client_url:
        return None
    m = re.search(r'/v/#([A-Za-z0-9_\-]+)', client_url)
    if not m:
        return None
    blob = _try_base64_urlsafe_decode(m.group(1))
    if not blob:
        return None
    i = 0
    while i < len(blob) - 1:
        wire_type = blob[i] & 0x07
        i += 1
        if wire_type == 2:  # length-delimited
            length = blob[i]; i += 1
            if length == 32 and i + 32 <= len(blob):
                return bytes(blob[i:i + 32])
            i += length
        elif wire_type == 0:  # varint
            while i < len(blob) and (blob[i] & 0x80):
                i += 1
            i += 1
        elif wire_type == 5:
            i += 4
        elif wire_type == 1:
            i += 8
        else:
            break
    return None


def load_private_keys():
    """Populate PRIVATE_KEYS_BY_NODE / PUBLIC_KEYS_BY_NODE / PRIVATE_KEYS_BY_PUB / PRIVATE_KEYS_BY_CLIENT."""
    global PRIVATE_KEYS_BY_NODE, PUBLIC_KEYS_BY_NODE, PRIVATE_KEYS_BY_PUB, PRIVATE_KEYS_BY_CLIENT
    PRIVATE_KEYS_BY_NODE = {}
    PUBLIC_KEYS_BY_NODE  = {}
    PRIVATE_KEYS_BY_PUB  = {}
    PRIVATE_KEYS_BY_CLIENT = {}

    data = None
    if os.path.exists(PRIVATE_KEYS_FILE):
        try:
            with open(PRIVATE_KEYS_FILE, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logging.warning(f"Failed to load {PRIVATE_KEYS_FILE}: {e}")
    if not data:
        env = os.environ.get('MESHTASTIC_PRIVATE_KEYS')
        if env:
            try:
                data = json.loads(env)
            except Exception as e:
                logging.warning(f"Failed to parse MESHTASTIC_PRIVATE_KEYS env: {e}")
    if not data:
        logging.debug("No private keys found")
        return

    def _register_pubkey(pub_bytes, priv):
        PRIVATE_KEYS_BY_PUB[pub_bytes.hex()] = priv
        PRIVATE_KEYS_BY_PUB[base64.b64encode(pub_bytes).decode()] = priv

    # nodes
    for k, v in (data.get('nodes') or {}).items():
        try:
            node_num = int(k)
            priv = parse_meshtastic_key(v)
            if not priv:
                logging.warning(f"Failed to parse key for node {node_num}")
                continue
            PRIVATE_KEYS_BY_NODE[node_num] = priv
            try:
                pub = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()
                PUBLIC_KEYS_BY_NODE[node_num] = pub
                logging.debug(f"Loaded node {node_num}: pubkey {base64.b64encode(pub).decode()[:20]}...")
            except Exception as e:
                logging.debug(f"Could not derive pubkey for node {node_num}: {e}")
        except Exception as e:
            logging.warning(f"Error loading node key {k}: {e}")

    # pubkeys
    for pub_str, priv_str in (data.get('pubkeys') or {}).items():
        priv = parse_meshtastic_key(priv_str)
        if not priv:
            continue
        pub_bytes = parse_meshtastic_key(pub_str)
        if pub_bytes:
            _register_pubkey(pub_bytes, priv)

    # clients
    for url, priv_str in (data.get('clients') or {}).items():
        priv = parse_meshtastic_key(priv_str)
        if not priv:
            continue
        PRIVATE_KEYS_BY_CLIENT[url] = priv
        extracted = parse_pubkey_from_client_id(url)
        if extracted:
            _register_pubkey(extracted, priv)

    logging.info(
        f"Private Keys: {len(PRIVATE_KEYS_BY_NODE)} nodes, "
        f"{len(PRIVATE_KEYS_BY_PUB)} pubkey mappings, "
        f"{len(PRIVATE_KEYS_BY_CLIENT)} clients"
    )


load_private_keys()
load_node_db()

# ─── Decryption ───────────────────────────────────────────────────────────────

def build_nonce(packet_id, from_node, extra_nonce=0):
    """16-byte AES-CTR nonce for PSK decryption."""
    nonce = bytearray(16)
    nonce[0:4]   = struct.pack('<I', packet_id  & 0xFFFFFFFF)
    nonce[8:12]  = struct.pack('<I', from_node  & 0xFFFFFFFF)
    nonce[12:16] = struct.pack('<I', extra_nonce & 0xFFFFFFFF)
    return bytes(nonce)


def try_decrypt_with_psk(encrypted_payload, psk, from_node_id, packet_id):
    """AES-CTR decryption with a pre-shared key (16 or 32 bytes)."""
    try:
        if not psk or len(psk) not in (16, 32):
            return None
        nonce = build_nonce(packet_id, from_node_id)
        cipher = Cipher(algorithms.AES(psk), modes.CTR(nonce), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(encrypted_payload) + dec.finalize()
    except Exception:
        return None


def aes_ccm_decrypt(key, nonce, ciphertext, mac_tag):
    """AES-CCM authenticated decryption.  Returns plaintext or None on tag failure."""
    try:
        return AESCCM(key, tag_length=len(mac_tag)).decrypt(nonce, ciphertext + mac_tag, None)
    except Exception:
        return None


def try_decrypt_pki(encrypted_payload, sender_pub_bytes, recip_priv_bytes, from_node_id, packet_id):
    """Decrypt a PKI message (X25519 + SHA256 + AES-CCM-8, per Meshtastic firmware).

    Wire format: [ciphertext | 8-byte auth tag | 4-byte extraNonce]
    Returns plaintext bytes or None.
    """
    try:
        if not sender_pub_bytes or not recip_priv_bytes:
            return None
        if len(sender_pub_bytes) != 32 or len(recip_priv_bytes) != 32:
            return None

        shared = X25519PrivateKey.from_private_bytes(recip_priv_bytes).exchange(
            X25519PublicKey.from_public_bytes(sender_pub_bytes)
        )
        key = hashlib.sha256(shared).digest()

        if len(encrypted_payload) < 13:  # minimum: 1 byte ct + 8 tag + 4 extraNonce
            return None

        ct          = encrypted_payload[:-12]
        tag         = encrypted_payload[-12:-4]
        extra_nonce = encrypted_payload[-4:]

        nonce = (struct.pack('<I', packet_id & 0xFFFFFFFF)
                 + extra_nonce
                 + struct.pack('<I', from_node_id & 0xFFFFFFFF)
                 + b'\x00')[:13]

        plaintext = aes_ccm_decrypt(key, nonce, ct, tag)
        if plaintext is None:
            logging.debug("PKI: AES-CCM tag verification failed")
        else:
            logging.debug(f"PKI: decrypted {len(plaintext)} bytes")
        return plaintext
    except Exception as e:
        logging.debug(f"PKI decryption error: {e}")
        return None

# ─── Network setup ────────────────────────────────────────────────────────────

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MCAST_PORT))
mreq = struct.pack('4s4s', socket.inet_aton(MCAST_GRP), socket.inet_aton(IFACE_IP))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# ─── File I/O helpers ─────────────────────────────────────────────────────────

def ensure_directories(ip):
    ip_dir = os.path.join(BASE_DIR, ip.replace('.', '_'))
    os.makedirs(ip_dir, exist_ok=True)
    return ip_dir


def save_to_json(packet_info, ip_dir):
    json_file = os.path.join(ip_dir, 'packets.json')
    try:
        data = json.load(open(json_file)) if os.path.exists(json_file) else []
    except Exception:
        data = []
    data.append(packet_info)
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=4)


def save_to_pcap(raw_data, ip_dir):
    pcap_file = os.path.join(ip_dir, 'packets.pcap')
    if not os.path.exists(pcap_file):
        with open(pcap_file, 'wb') as f:
            f.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    ts = time.time()
    hdr = struct.pack('@ I I I I', int(ts), int((ts % 1) * 1_000_000), len(raw_data), len(raw_data))
    with open(pcap_file, 'ab') as f:
        f.write(hdr + raw_data)

# ─── Payload decoders ─────────────────────────────────────────────────────────

def decode_portnum_payload(portnum, payload_bytes):
    """Decode payload based on PortNum type.  Returns a dict."""
    if not payload_bytes:
        return {"type": "empty"}
    try:
        if portnum == 1:                                         # TEXT_MESSAGE
            return {"type": "TEXT_MESSAGE", "text": payload_bytes.decode('utf-8', errors='replace')}

        elif portnum == 3:                                       # POSITION
            pos = mesh_pb2.Position()
            pos.ParseFromString(payload_bytes)
            r = {"type": "POSITION"}
            if pos.latitude_i:   r["lat"] = pos.latitude_i * 1e-7
            if pos.longitude_i:  r["lon"] = pos.longitude_i * 1e-7
            if pos.altitude:     r["alt_m"] = pos.altitude
            if pos.time:         r["time"] = datetime.fromtimestamp(pos.time).isoformat()
            if pos.HasField('ground_speed'):  r["ground_speed_ms"] = pos.ground_speed
            if pos.HasField('ground_track'):  r["ground_track_deg"] = pos.ground_track
            if pos.PDOP:           r["PDOP"] = round(pos.PDOP / 100.0, 2)
            if pos.HDOP:           r["HDOP"] = round(pos.HDOP / 100.0, 2)
            if pos.VDOP:           r["VDOP"] = round(pos.VDOP / 100.0, 2)
            if pos.gps_accuracy:   r["gps_accuracy_mm"] = pos.gps_accuracy
            if pos.sats_in_view:   r["sats_in_view"] = pos.sats_in_view
            if pos.fix_quality:    r["fix_quality"] = pos.fix_quality
            if pos.fix_type:       r["fix_type"] = pos.fix_type
            if pos.precision_bits: r["precision_bits"] = pos.precision_bits
            loc_src = {0: "UNSET", 1: "MANUAL", 2: "INTERNAL", 3: "EXTERNAL"}
            if pos.location_source:
                r["location_source"] = loc_src.get(pos.location_source, str(pos.location_source))
            return r

        elif portnum == 4:                                       # NODEINFO
            user = mesh_pb2.User()
            user.ParseFromString(payload_bytes)
            return {
                "type": "NODEINFO", "id": user.id,
                "long_name": user.long_name, "short_name": user.short_name,
                "hw_model": user.hw_model, "is_licensed": user.is_licensed,
            }

        elif portnum == 5:                                       # ROUTING
            routing = mesh_pb2.Routing()
            routing.ParseFromString(payload_bytes)
            r = {"type": "ROUTING"}
            variant = routing.WhichOneof('variant')
            if variant in ('route_request', 'route_reply'):
                route = getattr(routing, variant)
                r["subtype"] = variant
                r["route"] = [f"!{nid:x}" for nid in route.route]
                if route.snr_towards:
                    r["snr_towards"] = list(route.snr_towards)
                if variant == 'route_reply' and route.route_back:
                    r["route_back"] = [f"!{nid:x}" for nid in route.route_back]
                    if route.snr_back:
                        r["snr_back"] = list(route.snr_back)
            elif variant == 'error_reason':
                r["subtype"] = "error"
                _err_names = {
                    0: "NONE", 1: "NO_ROUTE", 2: "GOT_NAK", 3: "TIMEOUT",
                    4: "NO_INTERFACE", 5: "MAX_RETRANSMIT", 6: "NO_CHANNEL",
                    7: "TOO_LARGE", 8: "NO_RESPONSE", 9: "DUTY_CYCLE_LIMIT",
                    32: "BAD_REQUEST", 33: "NOT_AUTHORIZED",
                    34: "PKI_FAILED", 35: "PKI_UNKNOWN_PUBKEY",
                }
                r["error"] = _err_names.get(routing.error_reason, f"UNKNOWN_{routing.error_reason}")
            return r

        elif portnum == 6:                                       # ADMIN
            return {"type": "ADMIN", "raw_hex": payload_bytes.hex()}

        elif portnum == 7:                                       # TEXT_COMPRESSED
            try:
                import unishox2
                return {"type": "TEXT_MESSAGE_COMPRESSED",
                        "text": unishox2.decompress(payload_bytes).decode('utf-8', errors='replace')}
            except ImportError:
                return {"type": "TEXT_MESSAGE_COMPRESSED", "raw_hex": payload_bytes.hex()}

        elif portnum == 67 and telemetry_pb2:                    # TELEMETRY
            try:
                telem = telemetry_pb2.Telemetry()
                telem.ParseFromString(payload_bytes)
                r = {"type": "TELEMETRY"}
                if telem.time:
                    r["time"] = datetime.fromtimestamp(telem.time).isoformat()
                variant = telem.WhichOneof('variant')
                r["variant"] = variant
                if variant == 'device_metrics':
                    dm = telem.device_metrics
                    for src, dst, rnd in [
                        ('battery_level', 'battery_level', None),
                        ('voltage', 'voltage_v', 3),
                        ('channel_utilization', 'channel_util_pct', 2),
                        ('air_util_tx', 'air_util_tx_pct', 2),
                        ('uptime_seconds', 'uptime_s', None),
                    ]:
                        if dm.HasField(src):
                            val = getattr(dm, src)
                            r[dst] = round(val, rnd) if rnd else val
                elif variant == 'environment_metrics':
                    em = telem.environment_metrics
                    for src, dst, rnd in [
                        ('temperature', 'temperature_c', 2),
                        ('relative_humidity', 'humidity_pct', 1),
                        ('barometric_pressure', 'pressure_hpa', 2),
                        ('gas_resistance', 'gas_resistance_mohm', 3),
                        ('iaq', 'iaq', None),
                        ('wind_speed', 'wind_speed_ms', 2),
                        ('wind_direction', 'wind_direction_deg', None),
                        ('distance', 'distance_mm', 1),
                        ('lux', 'lux', 2),
                        ('uv_lux', 'uv_lux', 2),
                        ('rainfall_1h', 'rainfall_1h_mm', 2),
                    ]:
                        if em.HasField(src):
                            val = getattr(em, src)
                            r[dst] = round(val, rnd) if rnd else val
                elif variant == 'power_metrics':
                    pm = telem.power_metrics
                    for ch in range(1, 9):
                        if pm.HasField(f'ch{ch}_voltage'):
                            r[f'ch{ch}_v'] = round(getattr(pm, f'ch{ch}_voltage'), 3)
                        if pm.HasField(f'ch{ch}_current'):
                            r[f'ch{ch}_ma'] = round(getattr(pm, f'ch{ch}_current') * 1000, 1)
                elif variant == 'air_quality_metrics':
                    aq = telem.air_quality_metrics
                    for field in ['pm10_standard', 'pm25_standard', 'pm100_standard',
                                  'pm10_environmental', 'pm25_environmental', 'pm100_environmental',
                                  'particles_03um', 'particles_05um', 'particles_10um']:
                        val = getattr(aq, field, None)
                        if val:
                            r[field] = val
                elif variant == 'local_stats':
                    ls = telem.local_stats
                    r.update(uptime_s=ls.uptime_seconds,
                             channel_util_pct=round(ls.channel_utilization, 2),
                             air_util_tx_pct=round(ls.air_util_tx, 2),
                             num_online_nodes=ls.num_online_nodes,
                             num_total_nodes=ls.num_total_nodes)
                return r
            except Exception as e:
                logging.debug(f"Telemetry parse error: {e}")
                return {"type": "TELEMETRY", "raw_hex": payload_bytes.hex()}

        elif portnum == 67:
            return {"type": "TELEMETRY", "raw_hex": payload_bytes.hex()}

        elif portnum == 70:                                      # TRACEROUTE
            rd = mesh_pb2.RouteDiscovery()
            rd.ParseFromString(payload_bytes)
            r = {"type": "TRACEROUTE", "route": [], "snr_towards": [], "route_back": [], "snr_back": []}
            for i, nid in enumerate(rd.route):
                r["route"].append(f"!{nid:x}")
                if i < len(rd.snr_towards):
                    r["snr_towards"].append(rd.snr_towards[i] / 4.0)
            for i, nid in enumerate(rd.route_back):
                r["route_back"].append(f"!{nid:x}")
                if i < len(rd.snr_back):
                    r["snr_back"].append(rd.snr_back[i] / 4.0)
            return r

        else:
            return {"type": f"UNKNOWN_APP_{portnum}", "raw_hex": payload_bytes.hex()}
    except Exception as e:
        logging.debug(f"Payload decode error (portnum {portnum}): {e}")
        return {"type": f"APP_{portnum}", "raw_hex": payload_bytes.hex()}

# ─── Pretty-print ─────────────────────────────────────────────────────────────

def log_decoded_message(from_node, to_node, portnum, status, info, rssi=None, snr=None):
    from_s = f"!{from_node:x}" if isinstance(from_node, int) else str(from_node)
    to_s   = f"!{to_node:x}"   if isinstance(to_node, int)   else str(to_node)
    div = "=" * 80

    sig = f"Decryption: {status}"
    if rssi is not None:
        sig += f" | RSSI: {rssi} dBm"
    if snr is not None:
        sig += f" | SNR: {snr:.2f} dB"

    logging.info(f"\n{div}")
    logging.info(f"📦 MESSAGE: {from_s} → {to_s} | PortNum: {portnum} ({info.get('type', '?')})")
    logging.info(f"   {sig}")

    t = info.get('type')
    if t == 'TEXT_MESSAGE':
        logging.info(f"   TEXT: {info.get('text', '')}")
    elif t == 'TEXT_MESSAGE_COMPRESSED':
        logging.info(f"   TEXT (COMPRESSED): {info.get('text', '')}")
    elif t == 'POSITION':
        if 'lat' in info and 'lon' in info:
            logging.info(f"   POSITION: {info['lat']:.6f}, {info['lon']:.6f}")
        if 'alt_m' in info:
            logging.info(f"   ALTITUDE: {info['alt_m']}m")
        if 'time' in info:
            logging.info(f"   TIME: {info['time']}")
        acc = []
        for k, fmt in [('sats_in_view', 'sats={}'), ('PDOP', 'PDOP={}'), ('HDOP', 'HDOP={}'),
                        ('gps_accuracy_mm', 'acc={}mm'), ('precision_bits', 'prec={}b')]:
            if k in info:
                acc.append(fmt.format(info[k]))
        if 'fix_type' in info:
            ft = info['fix_type']
            acc.append(f"fix={({2:'2D',3:'3D',4:'3D-DGPS',5:'RTK'}).get(ft, str(ft))}")
        if acc:
            logging.info(f"   ACCURACY: {' | '.join(acc)}")
        if 'ground_speed_ms' in info:
            logging.info(f"   SPEED: {info['ground_speed_ms']} m/s @ {info.get('ground_track_deg', '?')}°")
    elif t == 'NODEINFO':
        logging.info(f"   ID: {info.get('id')}  Name: {info.get('long_name', '')} [{info.get('short_name', '')}]")
        if info.get('hw_model'):
            logging.info(f"   HW Model: {info['hw_model']}")
    elif t == 'ROUTING':
        sub = info.get('subtype', '?')
        logging.info(f"   ROUTING ({sub})")
        if sub in ('route_request', 'route_reply'):
            logging.info(f"   Route: {' → '.join(info.get('route', [])) or '(empty)'}")
        if sub == 'error':
            logging.info(f"   Error: {info.get('error', '?')}")
    elif t == 'TELEMETRY':
        logging.info(f"   Variant: {info.get('variant', '?')}")
        for k, label in [('time', 'Time'), ('battery_level', 'Battery'), ('voltage_v', 'Voltage'),
                          ('channel_util_pct', 'Ch util'), ('air_util_tx_pct', 'Air TX'),
                          ('temperature_c', 'Temp'), ('humidity_pct', 'Humidity'),
                          ('pressure_hpa', 'Pressure'), ('iaq', 'IAQ')]:
            if k in info:
                val = info[k]
                if k == 'battery_level':
                    bar = '█' * (val // 10) + '░' * (10 - val // 10)
                    val = f"{val}% [{bar}]"
                logging.info(f"   {label}: {val}")
        if 'uptime_s' in info:
            u = info['uptime_s']
            logging.info(f"   Uptime: {u//3600}h {(u%3600)//60}m {u%60}s")
        if 'num_online_nodes' in info:
            logging.info(f"   Nodes: {info['num_online_nodes']} online / {info.get('num_total_nodes', '?')} total")
    elif t == 'TRACEROUTE':
        def _chain(nodes, snrs):
            if not nodes:
                return "(direct)"
            return " ".join(
                f"──[{snrs[i]:+.2f}dB]──▶ {node_label(n)}" if i < len(snrs) else f"──▶ {node_label(n)}"
                for i, n in enumerate(nodes)
            )
        if info.get('route_back'):
            logging.info(f"   Fwd: {node_label(to_node)} {_chain(info['route'] + [from_s], info.get('snr_towards', []))}")
            logging.info(f"   Bck: {node_label(from_node)} {_chain(info['route_back'] + [to_s], info.get('snr_back', []))}")
        else:
            logging.info(f"   Req: {node_label(from_node)} {_chain(info['route'] + [to_s], info.get('snr_towards', []))}")
    elif t == 'ADMIN':
        logging.info("   ADMIN MESSAGE")
    logging.info(f"{div}\n")

# ─── Shared helpers for main loop ─────────────────────────────────────────────

def _extract_signal(msg):
    """Return (rssi, snr) from a MeshPacket, or None for each if absent/zero."""
    rssi = msg.rx_rssi if msg.rx_rssi != 0 else None
    snr  = msg.rx_snr  if msg.rx_snr  != 0.0 else None
    return rssi, snr


def _extract_hops(msg):
    """Return (hop_start, hop_limit, hops_taken)."""
    hs = msg.hop_start if msg.hop_start is not None else None
    hl = msg.hop_limit
    taken = (hs - hl) if (hs is not None and hl is not None) else None
    return hs, hl, taken


def _build_jsonl_base(msg, from_id, src_ip, *, encryption=None, pki=False):
    """Build the common fields dict for every JSONL record."""
    rssi, snr = _extract_signal(msg)
    hs, hl, ht = _extract_hops(msg)
    return {
        'rx_time':    msg.rx_time or None,
        'from_id':    from_id,
        'from_hex':   f'!{from_id:x}',
        'from_name':  NODE_DB.get(from_id, {}).get('long_name'),
        'to_id':      msg.to,
        'to_hex':     f'!{msg.to:x}',
        'to_name':    NODE_DB.get(msg.to, {}).get('long_name'),
        'packet_id':  msg.id,
        'channel':    msg.channel,
        'pki':        pki,
        'encryption': encryption,
        'rssi':       rssi,
        'snr':        snr,
        'hop_start':  hs,
        'hop_limit':  hl,
        'hops_taken': ht,
        'relay_node': getattr(msg, 'relay_node', None) or None,
        'src_ip':     src_ip,
    }

# ─── Main loop ────────────────────────────────────────────────────────────────

while True:
    try:
        data, addr = sock.recvfrom(1024)
        src_ip, src_port = addr
        logging.info(f"\nRaw UDP Packet from {addr}: {data}")

        ip_dir = ensure_directories(src_ip)
        save_to_pcap(data, ip_dir)

        msg = mesh_pb2.MeshPacket()
        msg.ParseFromString(data)
        from_id = getattr(msg, 'from')

        # ── Encrypted payload ─────────────────────────────────────────────
        if msg.HasField('encrypted'):
            logging.info(f"Encrypted payload ({len(msg.encrypted)}B) ch={msg.channel}")

            decrypted      = None
            successful_key = None
            is_pki         = getattr(msg, 'pki_encrypted', False)

            if is_pki:
                to_id      = msg.to
                sender_pub = bytes(msg.public_key) if msg.public_key else None
                priv_bytes = None

                logging.info(f"🔐 PKI: !{from_id:x} → !{to_id:x}")

                # Resolve sender public key
                if not sender_pub:
                    sender_pub = PUBLIC_KEYS_BY_NODE.get(from_id)
                    if sender_pub:
                        logging.info(f"   Sender pubkey: derived from key store")
                    else:
                        logging.info(f"   Sender pubkey: MISSING")
                else:
                    logging.info(f"   Sender pubkey: {sender_pub.hex()[:32]}... ({len(sender_pub)}B)")

                # Resolve recipient private key
                priv_bytes = PRIVATE_KEYS_BY_NODE.get(to_id)
                if not priv_bytes and sender_pub:
                    priv_bytes = PRIVATE_KEYS_BY_PUB.get(sender_pub.hex())
                    if priv_bytes:
                        logging.debug("   Private key found via PRIVATE_KEYS_BY_PUB")

                # Attempt decryption
                if priv_bytes and sender_pub:
                    decrypted = try_decrypt_pki(msg.encrypted, sender_pub, priv_bytes, from_id, msg.id)
                    if not decrypted:
                        # Relay nodes can overwrite msg.public_key with stale data
                        trusted_pub = PUBLIC_KEYS_BY_NODE.get(from_id)
                        if trusted_pub and trusted_pub != sender_pub:
                            logging.debug(f"   Retrying with trusted sender pubkey")
                            decrypted = try_decrypt_pki(msg.encrypted, trusted_pub, priv_bytes, from_id, msg.id)
                            if decrypted:
                                logging.info("   ✓ Decrypted (stale relay pubkey bypassed)")
                    if decrypted:
                        successful_key = 'pki'
                        logging.info("   ✓ PKI decrypted")
                    else:
                        logging.warning(f"   ✗ PKI decryption failed")
                else:
                    logging.warning(f"   ⚠️  No key pair available for !{from_id:x} → !{to_id:x}")
                    if not priv_bytes:
                        logging.warning(f"       Add node {to_id} to private_keys.json")

            else:
                # PSK decryption – try channel-specific key first, then defaults
                keys_to_try = []
                if msg.channel in CHANNEL_KEYS:
                    keys_to_try.append(CHANNEL_KEYS[msg.channel])
                keys_to_try.extend(range(1, 11))

                for key_num in keys_to_try:
                    psk = parse_meshtastic_key(key_num)
                    if not psk:
                        continue
                    plaintext = try_decrypt_with_psk(msg.encrypted, psk, from_id, msg.id)
                    if plaintext:
                        decrypted = plaintext
                        successful_key = key_num
                        logging.info(f"✓ PSK decrypted (key {key_num})")
                        break

            # ── Process result ────────────────────────────────────────────
            if decrypted:
                rec = _build_jsonl_base(msg, from_id, src_ip, encryption=str(successful_key), pki=is_pki)
                rec['raw_encrypted_hex'] = msg.encrypted.hex()
                try:
                    data_msg = mesh_pb2.Data()
                    data_msg.ParseFromString(decrypted)
                    portnum = data_msg.portnum
                    payload = data_msg.payload or b''
                    decoded_info = decode_portnum_payload(portnum, payload)

                    # Update node DB
                    if decoded_info.get('type') == 'NODEINFO':
                        update_node_db(from_id,
                                       long_name=decoded_info.get('long_name'),
                                       short_name=decoded_info.get('short_name'),
                                       hw_model=decoded_info.get('hw_model'),
                                       is_licensed=decoded_info.get('is_licensed'))
                    elif decoded_info.get('type') == 'POSITION':
                        update_node_db(from_id,
                                       lat=decoded_info.get('lat'),
                                       lon=decoded_info.get('lon'),
                                       alt_m=decoded_info.get('alt_m'))

                    rssi, snr = _extract_signal(msg)
                    log_decoded_message(from_id, msg.to, portnum, f"✓ {successful_key}", decoded_info, rssi, snr)
                    rec.update(portnum=portnum, type=decoded_info.get('type'), payload=decoded_info)

                except Exception as parse_err:
                    logging.warning(f"Protobuf parse failed: {parse_err}")
                    logging.info(f"Raw decrypted hex: {decrypted.hex()}")
                    rec.update(parse_error=str(parse_err), raw_decrypted_hex=decrypted.hex())

                write_jsonl(rec)
            else:
                logging.warning("✗ Decryption failed with all available keys")
                rec = _build_jsonl_base(msg, from_id, src_ip, pki=is_pki)
                rec['raw_encrypted_hex'] = msg.encrypted.hex()
                write_jsonl(rec)

        # ── Already-decoded (plaintext) payload ───────────────────────────
        elif msg.HasField('decoded'):
            d = msg.decoded
            portnum = d.portnum
            payload_bytes = d.payload or b''
            decoded_info = decode_portnum_payload(portnum, payload_bytes)
            rssi, snr = _extract_signal(msg)
            log_decoded_message(from_id, msg.to, portnum, 'plaintext', decoded_info, rssi, snr)

            rec = _build_jsonl_base(msg, from_id, src_ip, encryption='plaintext')
            rec.update(portnum=portnum, type=decoded_info.get('type'), payload=decoded_info)
            write_jsonl(rec)

        # ── Raw packet JSON + debug ───────────────────────────────────────
        save_to_json({"from": src_ip, "port": src_port, "decoded": str(msg)}, ip_dir)
        logging.info(f"Decoded MeshPacket:\n{msg}")

    except Exception as e:
        logging.error(f"Error decoding packet: {e}")
