#!/usr/bin/env python3
import json
import requests
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from collections import defaultdict
import time
import os

app = Flask(__name__)

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
BLOCK_SIZE = 16

def decrypt_aes_cbc(data):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted = cipher.decrypt(data)
        try:
            return unpad(decrypted, BLOCK_SIZE)
        except ValueError:
            return decrypted
    except Exception:
        return None

def encrypt_aes_cbc(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data, BLOCK_SIZE)
    return cipher.encrypt(padded)

def encode_varint(value):
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            result.append(byte)
            break
        result.append(byte | 0x80)
    return bytes(result)

def decode_varint(data, offset):
    value = 0
    shift = 0
    while True:
        b = data[offset]
        value |= (b & 0x7F) << shift
        offset += 1
        if not (b & 0x80):
            break
        shift += 7
    return value, offset

def parse_single_message(data):
    fields = {}
    idx = 0
    while idx < len(data):
        key, idx = decode_varint(data, idx)
        field_num = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, idx = decode_varint(data, idx)
            fields[field_num] = ('varint', value)
        elif wire_type == 2:
            length, idx = decode_varint(data, idx)
            raw = data[idx:idx+length]
            idx += length
            fields[field_num] = ('bytes', raw)
    return fields

def serialize_fields(fields_dict):
    result = bytearray()
    for num, (typ, val) in sorted(fields_dict.items()):
        if typ == 'varint':
            key = (num << 3) | 0
            result.extend(encode_varint(key))
            result.extend(encode_varint(val))
        elif typ == 'bytes':
            key = (num << 3) | 2
            result.extend(encode_varint(key))
            result.extend(encode_varint(len(val)))
            result.extend(val)
    return bytes(result)

def encode_packed_varint(values):
    result = bytearray()
    for v in values:
        result.extend(encode_varint(v))
    return bytes(result)

def decode_packed_varint(data):
    values = []
    idx = 0
    while idx < len(data):
        val, idx = decode_varint(data, idx)
        values.append(val)
    return values

BACKPACK_BODY_HEX = "1a725b2c56ec52ba7d09623454c0a003"
BACKPACK_BODY = bytes.fromhex(BACKPACK_BODY_HEX)

def parse_one_message(data, start):
    fields = []
    idx = start
    while idx < len(data):
        key, idx = decode_varint(data, idx)
        field_num = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, idx = decode_varint(data, idx)
            fields.append((field_num, 'varint', value, None))
        elif wire_type == 2:
            length, idx = decode_varint(data, idx)
            raw = data[idx:idx+length]
            idx += length
            nested = None
            try:
                nested, _ = parse_one_message(raw, 0)
            except:
                pass
            fields.append((field_num, 'bytes', raw, nested))
    return fields, idx

def collect_ids_from_fields(fields):
    ids = []
    for f in fields:
        if f[1] == 'varint' and f[0] == 1:
            ids.append(f[2])
        elif f[3] is not None:
            ids.extend(collect_ids_from_fields(f[3]))
    return ids

def fetch_vault_items(jwt_token, retries=2):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/GetBackpack"
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1"
    }
    for attempt in range(retries):
        try:
            resp = requests.post(url, headers=headers, data=BACKPACK_BODY, timeout=15)
            if resp.status_code != 200:
                raise Exception(f"GetBackpack HTTP {resp.status_code}")
            raw = resp.content
            plain = decrypt_aes_cbc(raw)
            if plain is None:
                data = raw
            else:
                data = plain
            fields, _ = parse_one_message(data, 0)
            item_ids = collect_ids_from_fields(fields)
            if item_ids:
                return item_ids
        except Exception as e:
            if attempt == retries-1:
                raise
            time.sleep(1)
    return []

GET_OUTFIT_TEMPLATE_HEX = "6868f708913820034b74f88c5e59558c"

def build_get_outfit_payload(account_id):
    template = bytes.fromhex(GET_OUTFIT_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template)
    if plain is None:
        plain = template
    fields = parse_single_message(plain)
    if 1 in fields and fields[1][0] == 'varint':
        fields[1] = ('varint', account_id)
    else:
        raise ValueError("Field 1 not found")
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def fetch_current_outfit(jwt_token, account_id):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/GetAccountOutfit"
    payload = build_get_outfit_payload(account_id)
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB54",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=payload, timeout=15)
    if resp.status_code != 200:
        raise Exception(f"GetAccountOutfit HTTP {resp.status_code}")
    data = resp.content
    fields = parse_single_message(data)
    outfit_values = []
    if 2 in fields and fields[2][0] == 'bytes':
        raw = fields[2][1]
        idx = 0
        while idx < len(raw):
            try:
                val, idx = decode_varint(raw, idx)
                outfit_values.append(val)
            except:
                break
    return outfit_values

def build_change_request_plain(character_id, outfit_ids):
    fields_dict = {
        1: ('varint', character_id),
        3: ('varint', 50)
    }
    repeated_raw = encode_packed_varint(outfit_ids)
    fields_dict[2] = ('bytes', repeated_raw)
    return serialize_fields(fields_dict)

def build_change_request(character_id, outfit_ids):
    plain = build_change_request_plain(character_id, outfit_ids)
    return encrypt_aes_cbc(plain)

def send_change_request(jwt_token, character_id, outfit_ids):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChangeClothes"
    encrypted = build_change_request(character_id, outfit_ids)
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB54",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=encrypted, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

REGION_SERVER_MAP = {
    "BD": "https://clientbp.ggpolarbear.com",
    "IND": "https://client.ind.freefiremobile.com",
    "PK": "https://clientbp.ggpolarbear.com",
    "ME": "https://clientbp.ggpolarbear.com",
    "VN": "https://clientbp.ggpolarbear.com",
    "SG": "https://clientbp.ggpolarbear.com",
    "ID": "https://clientbp.ggpolarbear.com",
    "TH": "https://clientbp.ggpolarbear.com",
    "BR": "https://client.us.freefiremobile.com",
    "NA": "https://client.us.freefiremobile.com",
    "US": "https://client.us.freefiremobile.com",
    "RU": "https://clientbp.ggpolarbear.com",
}

EMOTE_HEADERS = {
    "Accept-Encoding": "gzip",
    "Connection": "Keep-Alive",
    "Content-Type": "application/x-www-form-urlencoded",
    "Expect": "100-continue",
    "ReleaseVersion": "OB54",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
    "X-GA": "v1 1",
    "X-Unity-Version": "2018.4.11f1",
}

EMOTE_TEMPLATE_HEX = "CAF683222A25C7BEFEB51F59544DB313"

def build_emote_payload(emote_id):
    template_bytes = bytes.fromhex(EMOTE_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_bytes)
    if plain is None:
        raise ValueError("Failed to decrypt emote template")
    fields = parse_single_message(plain)
    if 6 not in fields or fields[6][0] != 'bytes':
        raise ValueError("Field 6 missing or not bytes in emote template")
    raw_field6 = fields[6][1]
    ids = decode_packed_varint(raw_field6)
    if len(ids) < 4:
        raise ValueError("Unexpected emote payload structure")
    ids[-1] = emote_id
    new_raw = encode_packed_varint(ids)
    fields[6] = ('bytes', new_raw)
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def get_region(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64)
        data = json.loads(payload_json)
        return data.get("noti_region") or data.get("lock_region")
    except Exception:
        return None

def get_base_url(jwt_token):
    region = get_region(jwt_token)
    if region == "IND":
        return "https://client.ind.freefiremobile.com"
    return "https://clientbp.ggpolarbear.com"

def send_emote_request(jwt_token, base_url, encrypted_payload):
    url = f"{base_url}/ChooseEmote"
    headers = EMOTE_HEADERS.copy()
    headers["Authorization"] = f"Bearer {jwt_token}"
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

WEAPON_TEMPLATE_HEX = "90D63D8BFD093219919DB87E0136ED8865B197FF37F1D324A370C36C9D7717A7339A91F6A679A1B588690CC48C7C568E20D6ECA6DEAF0AF16A12565F4C72059EDD2CC0AE8F762331C6936B3CE45AB9CAABD76B12ED6D979DB4896F4B23FB6CDA53037EC6F290BF14E8EA124E7484DA7C"

def build_weapon_payload(weapon_id):
    template_bytes = bytes.fromhex(WEAPON_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_bytes)
    if plain is None:
        raise ValueError("Failed to decrypt weapon template")
    fields = parse_single_message(plain)
    if 1 not in fields or fields[1][0] != 'bytes':
        raise ValueError("Field 1 missing or not bytes")
    list1 = decode_packed_varint(fields[1][1])
    idx = next((i for i, v in enumerate(list1) if v != 0), None)
    if idx is None:
        raise ValueError("No non-zero placeholder found in field 1")
    list1[idx] = weapon_id
    fields[1] = ('bytes', encode_packed_varint(list1))
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def send_weapon_request(jwt_token, encrypted_payload):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChooseSlotsAndShow"
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB54",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

AVATAR_TEMPLATE_HEX = "2C540F37C1CDE1F16C9BA687ABBDD316"

def build_avatar_payload(avatar_id):
    template_bytes = bytes.fromhex(AVATAR_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_bytes)
    if plain is None:
        raise ValueError("Failed to decrypt avatar template")
    fields = parse_single_message(plain)
    if 1 not in fields or fields[1][0] != 'varint':
        raise ValueError("Field 1 missing or not varint in avatar template")
    fields[1] = ('varint', avatar_id)
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def send_avatar_request(jwt_token, encrypted_payload):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChooseHeadPic"
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB54",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

def send_backpack_request(jwt_token, encrypted_payload):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChooseGameBagShow"
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB54",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

SELECT_PRESET_TEMPLATE_HEX = (
    "7aa34f4d48a78f45a70aa7acda90d4725589618bac35555d8ee85bb158907cadc35d53e485302b2c196303061be9b887b41285b4025c459b4761fb4122f38c3cf2611df67295bf52697ae68ffdc8d048703f822088829130cd445f747033a5821347af4c85419f96072da6b9d9c956e8"
)

def replace_varint_in_plaintext(plain_data, old_value, new_value):
    result = bytearray()
    idx = 0
    while idx < len(plain_data):
        try:
            val, idx = decode_varint(plain_data, idx)
            if val == old_value:
                result.extend(encode_varint(new_value))
                continue
            else:
                result.extend(encode_varint(val))
        except:
            result.extend(plain_data[idx:])
            break
    return bytes(result), True

def build_select_preset_payload(character_id, pet_id):
    template_encrypted = bytes.fromhex(SELECT_PRESET_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_encrypted)
    if plain is None:
        raise ValueError("Failed to decrypt SelectPresetLoadout template")
    old_char_id = 102000007
    old_pet_id1 = 1315000012
    old_pet_id2 = 1300000113
    plain, _ = replace_varint_in_plaintext(plain, old_char_id, character_id)
    plain, _ = replace_varint_in_plaintext(plain, old_pet_id1, pet_id)
    plain, _ = replace_varint_in_plaintext(plain, old_pet_id2, pet_id)
    encrypted = encrypt_aes_cbc(plain)
    return encrypted

def send_select_preset_request(jwt_token, character_id, pet_id):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/SelectPresetLoadout"
    encrypted_payload = build_select_preset_payload(character_id, pet_id)
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB54",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    payload_b64 = parts[1]
    payload_b64 += '=' * (4 - len(payload_b64) % 4)
    payload_json = base64.b64decode(payload_b64)
    data = json.loads(payload_json)
    account_id = data.get('account_id')
    if not account_id:
        raise ValueError("account_id not found")
    return int(account_id)

def load_item_db():
    try:
        with open("data.json", "r", encoding="utf-8") as f:
            items = json.load(f)
        db = {}
        for it in items:
            iid = it.get('itemID')
            if iid is not None:
                db[iid] = it
        print(f"Loaded {len(db)} items")
        return db
    except Exception as e:
        print(f"Could not load data.json: {e}")
        return {}

ITEM_DB = load_item_db()

def get_item_info(item_id):
    info = ITEM_DB.get(item_id, {})
    name = info.get('name', f'ID {item_id}')
    typ = info.get('type', 'Unknown')
    rare = info.get('Rare', '')
    return name, typ, rare

def extract_slots(outfit_values):
    slots = {}
    character_id = None
    for val in outfit_values:
        if 102000000 <= val < 103000000:
            character_id = val
            break
    if character_id is None and outfit_values:
        character_id = outfit_values[0]
    slots['character'] = character_id

    for val in outfit_values:
        name, typ, _ = get_item_info(val)
        if typ == 'Mask' and 'head' not in slots:
            slots['head'] = val
        elif typ == 'Shoe' and 'shoe' not in slots:
            slots['shoe'] = val
        elif typ == 'Bottom' and 'bottom' not in slots:
            slots['bottom'] = val
        elif typ == 'Top' and 'top' not in slots:
            slots['top'] = val
        elif typ == 'Facepaint' and 'facepaint' not in slots:
            slots['facepaint'] = val
        elif typ == 'Head' and 'head' not in slots:
            slots['head'] = val
    if len(slots) < 5 and outfit_values:
        try:
            idx = outfit_values.index(character_id) if character_id in outfit_values else 0
            order = ['head', 'shoe', 'bottom', 'top', 'facepaint']
            for i, s in enumerate(order):
                if idx+1+i < len(outfit_values) and s not in slots:
                    slots[s] = outfit_values[idx+1+i]
        except:
            pass
    return slots

# Backend conversion helper for Access Token -> JWT to avoid CORS
@app.route('/convert-access', methods=['GET'])
def convert_access():
    access_token = request.args.get('access_token', '').strip()
    if not access_token:
        return jsonify({'success': False, 'error': 'Access Token is required'}), 400
    try:
        api_url = f"https://access-to-jwt-five-beta.vercel.app/token?access_token={access_token}"
        resp = requests.get(api_url, timeout=15)
        
        try:
            data = resp.json()
            token = data.get('token') or data.get('jwt') or data.get('jwt_token')
            if not token:
                if isinstance(data, str):
                    token = data
                elif isinstance(data, dict) and 'jwt' in data:
                    token = data['jwt']
        except:
            token = resp.text.strip()
            
        if token and len(token.split('.')) == 3:
            return jsonify({'success': True, 'jwt': token})
        else:
            return jsonify({'success': False, 'error': 'Invalid token signature received from remote converter'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

UI_COMMON_HEADER = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --p:#00ffe7;--p2:#00c9b1;--p3:#7fffd4;
  --g1:#ff6ec7;--g2:#c026d3;
  --acc:#ffd700;--acc2:#ffe066;
  --dark:#030d0b;--card:rgba(12, 5, 45, 0.7);
  --brd:rgba(0,255,231,.18);--txt:#d6fff9;--dim:#65a197;
  --success:#00ff88;--err:#ff4466;
}
body{font-family:'Exo 2',sans-serif;background:var(--dark);min-height:100vh;overflow-x:hidden;
  background-image:radial-gradient(ellipse 70% 50% at 10% 0%,rgba(0,255,231,.12),transparent),radial-gradient(ellipse 60% 40% at 90% 100%,rgba(255,110,199,.1),transparent),radial-gradient(ellipse 40% 40% at 50% 50%,rgba(255,215,0,.04),transparent);}
#vanta-bg { position: fixed; width: 100%; height: 100%; top: 0; left: 0; z-index: -1; pointer-events: none; }
body::after{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.07)2px,rgba(0,0,0,.07)4px);}

.shell{position:relative;z-index:2;max-width:1200px;margin:0 auto;padding:1.2rem 1rem 3rem}
.music-bar{display:flex;align-items:center;gap:.8rem;background:rgba(0,255,231,.05);border:1px solid rgba(0,255,231,.18);border-radius:1rem;padding:.7rem 1.2rem;margin-bottom:1.5rem;box-shadow:0 0 24px rgba(0,255,231,.05),inset 0 1px 0 rgba(0,255,231,.08);position:relative;overflow:hidden;}
.music-bar::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--p),var(--g1),var(--p),transparent);opacity:.45}
.mdisc{font-size:1.1rem;color:var(--p);flex-shrink:0;animation:discSpin 4s linear infinite}
.mdisc.paused{animation-play-state:paused}
@keyframes discSpin{to{transform:rotate(360deg)}}
.meq{display:flex;align-items:flex-end;gap:2px;height:18px;flex-shrink:0}
.meq span{display:inline-block;width:3px;background:linear-gradient(0deg,var(--g2),var(--p),var(--p3));border-radius:2px;animation:eq .7s ease-in-out infinite alternate}
.meq span:nth-child(1){height:5px;animation-delay:0s}
.meq span:nth-child(2){height:13px;animation-delay:.1s}
.meq span:nth-child(3){height:8px;animation-delay:.2s}
.meq span:nth-child(4){height:15px;animation-delay:.05s}
.meq span:nth-child(5){height:6px;animation-delay:.15s}
.meq.paused span{animation-play-state:paused;opacity:.3}
@keyframes eq{from{transform:scaleY(.2)}to{transform:scaleY(1)}}
.minfo{flex:1;overflow:hidden}
.mtitle{font-family:'Orbitron',sans-serif;font-size:.7rem;letter-spacing:1.5px;color:var(--p);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.msub{font-size:.63rem;color:var(--dim);letter-spacing:1px;margin-top:.15rem}
.mbtn{background:linear-gradient(135deg,rgba(0,255,231,.12),rgba(255,110,199,.08));border:1px solid rgba(0,255,231,.3);border-radius:.6rem;color:var(--p);padding:.4rem .9rem;cursor:pointer;transition:all .2s;flex-shrink:0;font-family:'Orbitron',sans-serif;font-weight:700;font-size:.68rem;letter-spacing:1px;display:flex;align-items:center;gap:.4rem;}
.mbtn:hover{background:rgba(0,255,231,.2);box-shadow:0 0 15px rgba(0,255,231,.3)}

/* Profile Frame of Owner Ayan */
.profile-wrap{width:160px;height:160px;margin:0 auto 1.5rem;position:relative;display:flex;align-items:center;justify-content:center}
.profile-inner{width:118px;height:118px;border-radius:50%;overflow:hidden;position:relative;z-index:3;background:linear-gradient(135deg,rgba(0,255,231,.15),rgba(255,110,199,.15));display:flex;align-items:center;justify-content:center;box-shadow:0 0 22px rgba(0,255,231,.65),0 0 0 3px rgba(0,255,231,.38)}
.profile-inner img{width:100%;height:100%;object-fit:cover;border-radius:50%;}
.pico-owner { font-size: 3rem; background: linear-gradient(135deg, var(--p), var(--g1)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.profile-wrap::before{content:"";position:absolute;inset:-10px;border-radius:50%;z-index:1;border:2px solid transparent;background:linear-gradient(var(--dark),var(--dark))padding-box,conic-gradient(var(--p),var(--g1),var(--acc),transparent,transparent,var(--p))border-box;animation:spinR1 3s linear infinite;}
.profile-wrap::after{content:"";position:absolute;inset:-19px;border-radius:50%;z-index:1;border:1.5px solid transparent;background:linear-gradient(var(--dark),var(--dark))padding-box,conic-gradient(transparent,transparent,var(--g1),var(--p3),transparent,transparent)border-box;animation:spinR2 6s linear infinite;}
@keyframes spinR1{to{transform:rotate(360deg)}}
@keyframes spinR2{to{transform:rotate(-360deg)}}

.banner{text-align:center;padding:2rem 1rem 1.8rem;margin-bottom:1.5rem;position:relative}
.banner::after{content:"";display:block;width:80%;height:1px;margin:1.5rem auto 0;background:linear-gradient(90deg,transparent,var(--p),var(--g1),var(--acc),var(--p),transparent)}
.banner h1{font-family:'Orbitron',sans-serif;font-size:2.5rem;font-weight:900;letter-spacing:5px;text-transform:uppercase;background:linear-gradient(90deg,var(--p)0%,var(--g1)35%,var(--acc)70%,var(--p)100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:hGlow 3s ease-in-out infinite alternate;margin-bottom:.5rem}
@keyframes hGlow{from{filter:drop-shadow(0 0 10px rgba(0,255,231,.5))}to{filter:drop-shadow(0 0 30px rgba(255,110,199,.7))}}
.banner .sub{color:var(--dim);font-size:.82rem;letter-spacing:2px;display:flex;align-items:center;justify-content:center;gap:.7rem;flex-wrap:wrap;margin-top:.5rem}

.badge{background:linear-gradient(135deg,rgba(0,255,231,.08),rgba(255,110,199,.06));border:1px solid rgba(0,255,231,.25);border-radius:20px;padding:.2rem .9rem;font-size:.7rem;color:var(--p);letter-spacing:1px}
.badge.gold{border-color:rgba(255,215,0,.3);color:var(--acc2)}
.badge.pink{border-color:rgba(255,110,199,.3);color:var(--g1)}

.ticker{display:flex;align-items:center;gap:1rem;background:rgba(0,255,231,.04);border:1px solid rgba(0,255,231,.1);border-radius:.7rem;padding:.55rem 1.2rem;margin-bottom:2rem}
.tdot{width:8px;height:8px;border-radius:50%;background:var(--success);flex-shrink:0;animation:blink 1.2s ease-in-out infinite alternate}
@keyframes blink{from{opacity:.3}to{opacity:1;box-shadow:0 0 8px var(--success)}}
.ttxt{font-size:.72rem;color:var(--dim);letter-spacing:1px;font-family:'Orbitron',sans-serif}
.ttxt span{color:var(--p)}

.card{background:var(--card);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--brd);border-radius:1.6rem;padding:2rem;position:relative;overflow:hidden;transition:transform .3s,border-color .3s,box-shadow .3s;box-shadow:0 8px 40px rgba(0,0,0,.7),inset 0 1px 0 rgba(0,255,231,.06);margin-bottom:1.8rem}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--p),var(--g1),var(--acc),var(--p),transparent);opacity:.55}
.card:hover{border-color:rgba(0,255,231,.42);box-shadow:0 20px 60px rgba(0,255,231,.1)}

.card-head{display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem}
.card-ico{width:52px;height:52px;border-radius:.9rem;flex-shrink:0;background:linear-gradient(135deg,rgba(0,255,231,.12),rgba(255,110,199,.1));border:1px solid rgba(0,255,231,.25);display:flex;align-items:center;justify-content:center;font-size:1.4rem;color:var(--p)}
.card-ttl{font-family:'Orbitron',sans-serif;font-size:1.05rem;font-weight:700;color:var(--txt);letter-spacing:2px;text-transform:uppercase}
.card-ep{font-size:.7rem;color:var(--dim);letter-spacing:1px;margin-top:.15rem}

.tab-btn-row { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; border-bottom: 1px solid rgba(0,255,231,.1); padding-bottom: 0.5rem; flex-wrap: wrap;}
.auth-tab { background: transparent; border: none; color: var(--dim); font-family: 'Orbitron', sans-serif; font-size: 0.75rem; letter-spacing: 1px; padding: 0.5rem 1rem; cursor: pointer; transition: 0.2s; }
.auth-tab.active { color: var(--p); border-bottom: 2px solid var(--p); }

.inp-wrap{position:relative;margin-bottom:1rem}
.inp-lbl{font-size:.68rem;color:var(--dim);letter-spacing:1.5px;font-family:'Orbitron',sans-serif;text-transform:uppercase;margin-bottom:.4rem}
.inp{width:100%;background:rgba(0,255,231,.03);border:1px solid rgba(0,255,231,.13);border-radius:.75rem;padding:.88rem 2.5rem .88rem 1.2rem;font-size:.9rem;color:var(--txt);font-family:'Exo 2',sans-serif;outline:none;transition:all .25s}
.inp:focus{border-color:var(--p);background:rgba(0,255,231,.07);box-shadow:0 0 22px rgba(0,255,231,.14)}
.inp::placeholder{color:rgba(101, 161, 151, 0.4)}
.iico{position:absolute;right:1rem;top:50%;transform:translateY(-50%);color:var(--dim);font-size:.85rem;pointer-events:none}

.btn-row{display:flex;flex-wrap:wrap;gap:.8rem;margin-top:.5rem}
.btn{padding:.85rem 2rem;border-radius:.75rem;border:none;cursor:pointer;font-family:'Orbitron',sans-serif;font-size:.75rem;letter-spacing:1.5px;text-transform:uppercase;display:inline-flex;align-items:center;gap:.6rem;position:relative;overflow:hidden;transition:all .25s;font-weight:700}
.btn::before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.12),transparent);opacity:0;transition:opacity .2s}
.btn:hover::before{opacity:1}
.btn-main{background:linear-gradient(135deg,#006655,var(--p2));color:var(--dark);box-shadow:0 4px 24px rgba(0,255,231,.4)}
.btn-main:hover{background:linear-gradient(135deg,var(--p),var(--p3));box-shadow:0 6px 32px rgba(0,255,231,.65);transform:translateY(-2px) scale(1.02)}

.btn-danger{background:linear-gradient(135deg,#660011,#b10022);color:#fff;box-shadow:0 4px 20px rgba(255,68,102,.3)}
.btn-danger:hover{background:linear-gradient(135deg,#ff4466,#ff7788);box-shadow:0 6px 28px rgba(255,68,102,.5);transform:translateY(-2px)}

.msg-box{border-radius:.9rem;padding:1rem 1.2rem;margin-top:1rem;display:flex;align-items:center;gap:.8rem;font-size:.85rem}
.msg-box.err{background:rgba(255,68,102,.07);border:1px solid rgba(255,68,102,.25);color:var(--err)}

.sec-title{font-family:'Orbitron',sans-serif;font-size:.75rem;letter-spacing:2.5px;color:var(--p);text-transform:uppercase;margin-bottom:1rem;display:flex;align-items:center;gap:.6rem}
.sec-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,rgba(0,255,231,.3),transparent)}

.slot-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(188px,1fr));gap:1rem;margin-bottom:.5rem}
.slot-card{background:rgba(0,255,231,.04);border:1px solid rgba(0,255,231,.13);border-radius:1.1rem;padding:1.2rem;text-align:center;transition:all .25s;position:relative;overflow:hidden}
.slot-card::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--p),transparent);opacity:.4}
.slot-card:hover{border-color:rgba(0,255,231,.45);transform:translateY(-4px);box-shadow:0 12px 30px rgba(0,255,231,.12)}
.slot-img{width:88px;height:88px;margin:0 auto .8rem;border-radius:.8rem;overflow:hidden;background:rgba(0,255,231,.06);border:1px solid rgba(0,255,231,.18);display:flex;align-items:center;justify-content:center}
.slot-img img{width:100%;height:100%;object-fit:contain;padding:6px}
.slot-type{font-family:'Orbitron',sans-serif;font-size:.68rem;letter-spacing:1.5px;color:var(--p);margin-bottom:.3rem;text-transform:uppercase}
.slot-name{font-size:.82rem;color:var(--txt);font-weight:600;margin-bottom:.25rem}
.slot-iid{font-size:.67rem;color:var(--dim);font-family:monospace;margin-bottom:.3rem}
.slot-rare{font-size:.64rem;color:var(--acc2);letter-spacing:.5px;margin-bottom:.6rem}
.slot-row{display:flex;gap:.4rem;align-items:center}
.sinp{flex:1;background:rgba(0,255,231,.06);border:1px solid rgba(0,255,231,.18);border-radius:.45rem;padding:.38rem .55rem;font-size:.76rem;color:var(--txt);font-family:'Exo 2',sans-serif;outline:none;min-width:0}
.sinp:focus{border-color:var(--p)}
.sbtn{background:linear-gradient(135deg,#006655,var(--p2));border:none;border-radius:.45rem;color:var(--dark);padding:.38rem .65rem;cursor:pointer;font-family:'Orbitron',sans-serif;font-size:.58rem;letter-spacing:.5px;transition:all .2s;white-space:nowrap;font-weight:700}
.sbtn:hover{background:linear-gradient(135deg,var(--p),var(--p3));box-shadow:0 0 12px rgba(0,255,231,.4)}

.char-row{display:flex;gap:1rem;align-items:center;flex-wrap:wrap;margin-bottom:.5rem}
.char-sel{background:rgba(0,255,231,.06);border:1px solid rgba(0,255,231,.22);border-radius:.6rem;padding:.65rem 1rem;color:var(--txt);font-family:'Exo 2',sans-serif;font-size:.88rem;outline:none;cursor:pointer;min-width:200px}
.char-sel option{background:#030d0b}
.char-note{font-size:.76rem;color:var(--dim);margin-top:.5rem;display:flex;align-items:center;gap:.4rem}

.vcat{margin-bottom:2rem}
.vcat-title{font-family:'Orbitron',sans-serif;font-size:.76rem;letter-spacing:2px;color:var(--acc2);display:flex;align-items:center;gap:.6rem;margin-bottom:.9rem}
.vcat-title::before{content:"";width:4px;height:16px;background:linear-gradient(to bottom,var(--p),var(--g1));border-radius:2px;flex-shrink:0}
.vcat-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,rgba(0,255,231,.18),transparent)}

.vault-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(152px,1fr));gap:.85rem}
.item-card{background:rgba(0,255,231,.03);border:1px solid rgba(0,255,231,.1);border-radius:1rem;padding:.95rem;text-align:center;cursor:pointer;transition:all .25s;position:relative;overflow:hidden}
.item-card::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--p),transparent);opacity:0;transition:opacity .3s}
.item-card:hover{border-color:rgba(0,255,231,.42);transform:translateY(-4px);box-shadow:0 10px 25px rgba(0,255,231,.12)}
.item-card:hover::before{opacity:1}

.item-img{width:78px;height:78px;margin:0 auto .7rem;border-radius:.6rem;overflow:hidden;background:rgba(0,255,231,.06);border:1px solid rgba(0,255,231,.13);display:flex;align-items:center;justify-content:center}
.item-img img{width:100%;height:100%;object-fit:contain;padding:5px}
.item-name{font-size:.76rem;color:var(--txt);font-weight:600;margin-bottom:.2rem;line-height:1.3}
.item-iid{font-size:.63rem;color:var(--dim);font-family:monospace;margin-bottom:.2rem}
.item-rare{font-size:.6rem;color:var(--acc2)}

.flash-ok{background:rgba(0,255,136,.12)!important;border-color:rgba(0,255,136,.5)!important;transition:all .15s!important}
.flash-er{background:rgba(255,68,102,.12)!important;border-color:rgba(255,68,102,.5)!important;transition:all .15s!important}

.toast{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;background:rgba(3,13,11,.96);border-radius:.8rem;padding:.85rem 1.2rem;font-family:'Orbitron',sans-serif;font-size:.7rem;letter-spacing:1px;display:flex;align-items:center;gap:.7rem;max-width:320px;box-shadow:0 8px 30px rgba(0,0,0,.6);animation:toastIn .3s ease;border:1px solid rgba(0,255,231,.15)}
.toast.ok{border-left:3px solid var(--success);color:var(--success)}
.toast.er{border-left:3px solid var(--err);color:var(--err)}
@keyframes toastIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}

.overlay{position:fixed;inset:0;background:rgba(3,13,11,.88);backdrop-filter:blur(10px);z-index:9000;display:none;flex-direction:column;align-items:center;justify-content:center;gap:1.2rem}
.overlay.show{display:flex}
.ov-ring{width:72px;height:72px;border-radius:50%;border:3px solid rgba(0,255,231,.12);border-top-color:var(--p);animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.ov-txt{font-family:'Orbitron',sans-serif;font-size:.78rem;letter-spacing:2px;color:var(--p)}
.ov-sub{font-size:.65rem;color:var(--dim);letter-spacing:1px}

.divider{border:none;border-top:1px solid rgba(0,255,231,.08);margin:2rem 0}
.foot{text-align:center;color:var(--dim);font-size:.76rem;letter-spacing:1.5px;font-family:'Orbitron',sans-serif;padding:.5rem}
.foot span{background:linear-gradient(90deg,var(--p),var(--g1));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.foot a{color:var(--p);text-decoration:none;transition:color .2s}
.foot a:hover{color:var(--p)}

.slot-sel-bar{background:rgba(0,255,231,.04);border:1px solid rgba(0,255,231,.12);border-radius:.9rem;padding:.85rem 1.1rem;margin-bottom:1.3rem;display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.ssl{font-family:'Orbitron',sans-serif;font-size:.68rem;letter-spacing:1.5px;color:var(--p);flex-shrink:0}
.sselect{background:rgba(0,255,231,.07);border:1px solid rgba(0,255,231,.22);border-radius:.5rem;padding:.5rem 1rem;color:var(--p);font-family:'Orbitron',sans-serif;font-size:.68rem;letter-spacing:1px;outline:none;cursor:pointer}
.sselect option{background:#030d0b}

@media(max-width:640px){.banner h1{font-size:1.7rem;letter-spacing:2px}.card{padding:1.3rem}.slot-grid{grid-template-columns:1fr 1fr}.vault-grid{grid-template-columns:repeat(auto-fill,minmax(128px,1fr))}.btn{padding:.75rem 1.2rem;font-size:.68rem}}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-thumb{background:rgba(0,255,231,.22);border-radius:3px}
</style>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    {{ UI_COMMON_HEADER | safe }}
</head>
<body>
<div id="vanta-bg"></div>
<audio id="bgAudio" loop><source src="/static/music.mp3" type="audio/mpeg"></audio>
<div class="overlay" id="loadOverlay"><div class="ov-ring"></div><div class="ov-txt">PROCESSING</div><div class="ov-sub">Please wait...</div></div>
<div class="shell">

<div class="music-bar"><i class="fas fa-compact-disc mdisc paused" id="mDisc"></i><div class="meq paused" id="mEq"><span></span><span></span><span></span><span></span><span></span></div><div class="minfo"><div class="mtitle" id="mTitle">♪ AYAN OUTFIT HUB — BGM</div><div class="msub">Tap PLAY to enable music</div></div><button class="mbtn" id="mBtn"><i class="fas fa-play" id="mIcon"></i><span id="mLbl">PLAY</span></button></div>

<div class="banner">
  <div class="profile-wrap">
    <div class="profile-inner">
      <img id="owner_avatar" src="/static/pic.jpg" alt="Ayan Bro" onerror="this.style.display='none'; document.getElementById('fallback_pico').style.display='inline-block'">
      <i class="fas fa-fire pico-owner" id="fallback_pico" style="display:none;"></i>
    </div>
  </div>
  <h1>Ayan Outfit Hub</h1>
  <div class="sub">
    <i class="fas fa-crown" style="color:var(--acc)"></i><span>Owner: Ayan Bro</span>
    <span class="badge"><i class="fas fa-id-badge"></i> UID: 2279016714</span>
    <span class="badge gold"><i class="fas fa-crown"></i> VIP PRO Developer</span>
  </div>
</div>

<div class="ticker"><div class="tdot"></div><div class="ttxt">SYSTEM ONLINE &nbsp;•&nbsp; <span>OB54 ENGINE</span> &nbsp;•&nbsp; LOGIN PORTAL ACTIVE</div></div>

<!-- JWT and Converter Login Container -->
<div class="card" id="auth-panel">
  <div class="card-head">
    <div class="card-ico"><i class="fas fa-shield-alt"></i></div>
    <div>
      <div class="card-ttl">Garena Authentication</div>
      <div class="card-ep">/ auth • Convert Access Token or paste JWT directly</div>
    </div>
  </div>
  
  <div class="tab-btn-row">
    <button class="auth-tab active" onclick="switchAuthTab('direct-jwt')"><i class="fas fa-key"></i> Direct JWT</button>
    <button class="auth-tab" onclick="switchAuthTab('access-conv')"><i class="fas fa-exchange-alt"></i> Access Token to JWT</button>
  </div>

  <div id="direct-jwt-panel">
    <form action="/dashboard" method="GET" id="jwtForm">
      <div class="inp-wrap">
        <div class="inp-lbl">Bearer JWT Token</div>
        <input class="inp" type="text" id="main_jwt_input" name="jwt" placeholder="eyJhbGciOiJIUzI1NiIs..." required>
        <i class="fas fa-lock iico"></i>
      </div>
      <div class="btn-row">
        <button class="btn btn-main" type="submit"><i class="fas fa-bolt"></i> Load Dashboard</button>
      </div>
    </form>
  </div>

  <div id="access-conv-panel" style="display:none;">
    <div class="inp-wrap">
      <div class="inp-lbl">Garena Access Token</div>
      <input class="inp" type="text" id="access_token_input" placeholder="Enter Access Token...">
      <i class="fas fa-key iico"></i>
    </div>
    <div class="btn-row">
      <button class="btn btn-main" type="button" onclick="convertAccessToken()"><i class="fas fa-sync-alt"></i> Convert &amp; Load</button>
    </div>
  </div>

  {% if load_error %}
    <div class="msg-box err" id="loadErrorBox"><i class="fas fa-exclamation-triangle"></i> {{ load_error }}</div>
  {% endif %}
</div>

</div>
<hr class="divider">
<div class="foot">Crafted with <span>♥</span> by <span>AYAN</span> &nbsp;•&nbsp; UID: 2279016714</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.waves.min.js"></script>
<script>
function switchAuthTab(tabId) {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    if (tabId === 'direct-jwt') {
        document.getElementById('direct-jwt-panel').style.display = 'block';
        document.getElementById('access-conv-panel').style.display = 'none';
    } else {
        document.getElementById('direct-jwt-panel').style.display = 'none';
        document.getElementById('access-conv-panel').style.display = 'block';
    }
}

async function convertAccessToken() {
    const token = document.getElementById('access_token_input').value.trim();
    if (!token) {
        toast('Please enter Garena Access Token', false);
        return;
    }
    showOverlay(true);
    try {
        const res = await fetch('/convert-access?access_token=' + encodeURIComponent(token));
        const data = await res.json();
        showOverlay(false);
        if (data.success && data.jwt) {
            toast('Access token converted to JWT successfully!', true);
            window.location.href = '/dashboard?jwt=' + encodeURIComponent(data.jwt);
        } else {
            toast(data.error || 'Conversion failed. Invalid response.', false);
        }
    } catch(e) {
        showOverlay(false);
        toast('Connection failed: ' + e.message, false);
    }
}

const audio=document.getElementById('bgAudio');let playing=false;const mDisc=document.getElementById('mDisc'),mEq=document.getElementById('mEq'),mIcon=document.getElementById('mIcon'),mLbl=document.getElementById('mLbl'),mTitle=document.getElementById('mTitle');
function setMusic(on){playing=on;mDisc.classList.toggle('paused',!on);mEq.classList.toggle('paused',!on);mIcon.className=on?'fas fa-pause':'fas fa-play';mLbl.textContent=on?'PAUSE':'PLAY';mTitle.textContent=on?'♪ Now Playing — BGM':'♪ Music Paused';}
document.getElementById('mBtn').onclick=()=>{if(playing){audio.pause();setMusic(false);}else audio.play().then(()=>setMusic(true)).catch(()=>{});};
let autoTried=false;['click','touchstart'].forEach(ev=>document.addEventListener(ev,()=>{if(!autoTried&&!playing){autoTried=true;audio.play().then(()=>setMusic(true)).catch(()=>{});}},{once:true}));

function toast(msg,ok=true){const t=document.createElement('div');t.className='toast '+(ok?'ok':'er');t.innerHTML='<i class="fas fa-'+(ok?'check-circle':'times-circle')+'"></i>'+msg;document.body.appendChild(t);setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity .4s';setTimeout(()=>t.remove(),400);},3000);}
const overlay=document.getElementById('loadOverlay');function showOverlay(on){overlay.classList.toggle('show',on);}

document.addEventListener('DOMContentLoaded', () => {
    VANTA.WAVES({
        el: "#vanta-bg",
        mouseControls: true, touchControls: true, gyroControls: false,
        minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
        color: 0x0a0523, shininess: 35.00, waveHeight: 12.00, waveSpeed: 0.7, zoom: 0.90
    });
});
</script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    {{ UI_COMMON_HEADER | safe }}
    <style>
      .vault-tab-row { display: flex; gap: 0.5rem; margin-bottom: 2rem; overflow-x: auto; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(0,255,231,.15); }
      .v-tab { background: rgba(0,255,231,.05); border: 1px solid rgba(0,255,231,.15); border-radius: 0.5rem; color: var(--dim); font-family: 'Orbitron', sans-serif; font-size: 0.68rem; padding: 0.6rem 1.2rem; cursor: pointer; transition: 0.2s; white-space: nowrap; }
      .v-tab.active, .v-tab:hover { background: rgba(0,255,231,.15); border-color: var(--p); color: var(--p); }
    </style>
</head>
<body>
<div id="vanta-bg"></div>
<audio id="bgAudio" loop><source src="/static/music.mp3" type="audio/mpeg"></audio>
<div class="overlay" id="loadOverlay"><div class="ov-ring"></div><div class="ov-txt">PROCESSING</div><div class="ov-sub">Please wait...</div></div>
<div class="shell">

<div class="music-bar"><i class="fas fa-compact-disc mdisc paused" id="mDisc"></i><div class="meq paused" id="mEq"><span></span><span></span><span></span><span></span><span></span></div><div class="minfo"><div class="mtitle" id="mTitle">♪ AYAN OUTFIT HUB — BGM</div><div class="msub">Tap PLAY to enable music</div></div><button class="mbtn" id="mBtn"><i class="fas fa-play" id="mIcon"></i><span id="mLbl">PLAY</span></button></div>

<div class="banner">
  <h1 style="font-size: 2rem;">Outfit Customizer</h1>
  <div class="sub">
    <span class="badge gold"><i class="fas fa-user-circle"></i> Player ID: {{ account_id }}</span>
    <span class="badge pink"><i class="fas fa-globe"></i> Region: {{ region }}</span>
    <button onclick="logout()" class="badge" style="background: rgba(255,68,102,.12); border-color: rgba(255,68,102,.3); color: var(--err); cursor: pointer;"><i class="fas fa-sign-out-alt"></i> Logout</button>
  </div>
</div>

<!-- Equipped Items Section -->
{% if slots %}
<div class="card" id="outfit-panel">
  <div class="card-head">
    <div class="card-ico"><i class="fas fa-tshirt"></i></div>
    <div>
      <div class="card-ttl">Current Outfit</div>
      <div class="card-ep">/ GetAccountOutfit &nbsp;•&nbsp; Edit ID &amp; press SET to change</div>
    </div>
  </div>
  <div class="slot-sel-bar">
    <span class="ssl"><i class="fas fa-crosshairs"></i> Target Slot:</span>
    <select class="sselect" id="targetSlot">
      {% for slot, data in slots.items() %}
        <option value="{{ slot }}">{{ slot|capitalize }} — ID: {{ data.id }}</option>
      {% endfor %}
    </select>
  </div>
  <div class="sec-title"><i class="fas fa-layer-group"></i> Equipped Items</div>
  <div class="slot-grid">
    {% for slot, data in slots.items() %}
      <div class="slot-card">
        <div class="slot-img">
          <img src="https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{{ data.id }}.png" onerror="this.src='data:image/svg+xml,%3Csvg xmlns=\\'http://www.w3.org/2000/svg\\' viewBox=\\'0 0 80 80\\'%3E%3Crect width=\\'80\\' height=\\'80\\' fill=\\'%23031a18\\'/%3E%3Ctext x=\\'40\\' y=\\'45\\' font-size=\\'8\\' text-anchor=\\'middle\\' fill=\\'%2300ffe7\\'%3E{{ data.id }}%3C/text%3E%3C/svg%3E'">
        </div>
        <div class="slot-type">{{ slot }}</div>
        <div class="slot-name">{{ data.name }}</div>
        <div class="slot-iid">ID: {{ data.id }}</div>
        <div class="slot-rare">{{ data.rarity }}</div>
        <div class="slot-row">
          <input class="sinp" type="number" id="nid_{{ slot }}" value="{{ data.id }}">
          <button class="sbtn" onclick="changeSlot('{{ slot }}','{{ data.id }}','{{ character_id }}',this)"><i class="fas fa-sync-alt"></i> SET</button>
        </div>
      </div>
    {% endfor %}
  </div>
</div>
{% endif %}

<!-- Character Changer Section -->
{% if vault and 'Character' in vault %}
<div class="card">
  <div class="corner"></div>
  <div class="card-head">
    <div class="card-ico"><i class="fas fa-user-astronaut"></i></div>
    <div>
      <div class="card-ttl">Change Character</div>
      <div class="card-ep">/ SelectPresetLoadout &nbsp;•&nbsp; Current outfit auto-preserved</div>
    </div>
  </div>
  <div class="char-row">
    <select class="char-sel" id="charSel">
      <option value="">— Select a Character —</option>
      {% for ch in vault['Character'] %}
        <option value="{{ ch.id }}">{{ ch.name }} ({{ ch.id }})</option>
      {% endfor %}
    </select>
    <button class="btn btn-main" id="charBtn"><i class="fas fa-user-edit"></i> Switch</button>
  </div>
  <div class="char-note"><i class="fas fa-info-circle" style="color:var(--p)"></i> Head, Shoe, Bottom, Top &amp; Facepaint will be re-applied automatically.</div>
</div>
{% endif %}

<!-- Vault Section (Item categories isolated by tabs) -->
{% if vault %}
<div class="card">
  <div class="corner"></div>
  <div class="card-head">
    <div class="card-ico"><i class="fas fa-box-open"></i></div>
    <div>
      <div class="card-ttl">Premium Vault Directory</div>
      <div class="card-ep">{{ vault_total }} items &nbsp;•&nbsp; Filter and click to equip instantly</div>
    </div>
  </div>
  
  <!-- Category sub-tabs -->
  <div class="vault-tab-row">
    <button class="v-tab active" onclick="switchVaultCategory('all')"><i class="fas fa-th-large"></i> All Items</button>
    <button class="v-tab" onclick="switchVaultCategory('dress')"><i class="fas fa-shirt"></i> Tops (Dresses)</button>
    <button class="v-tab" onclick="switchVaultCategory('pant')"><i class="fas fa-socks"></i> Bottoms (Pants)</button>
    <button class="v-tab" onclick="switchVaultCategory('shoe')"><i class="fas fa-shoe-prints"></i> Shoes</button>
    <button class="v-tab" onclick="switchVaultCategory('head')"><i class="fas fa-hat-cowboy"></i> Head / Masks</button>
    <button class="v-tab" onclick="switchVaultCategory('emote')"><i class="fas fa-running"></i> Emotes</button>
    <button class="v-tab" onclick="switchVaultCategory('weapon')"><i class="fas fa-shield-halved"></i> Weapons</button>
    <button class="v-tab" onclick="switchVaultCategory('backpack')"><i class="fas fa-briefcase"></i> Backpacks &amp; Avatars</button>
  </div>

  {% for category, items in vault.items() %}
    <!-- Store category group map dynamically -->
    {% set css_group_class = 'all' %}
    {% if category.lower() == 'top' or category.lower() == 'dress' or category.lower() == 'bottom' or category.lower() == 'pant' or category.lower() == 'shoe' or category.lower() == 'shoes' or category.lower() == 'head' or category.lower() == 'mask' or category.lower() == 'facepaint' or category.lower() == 'emote' or category.lower() in ['avatars', 'headpic', 'backpack', 'bag'] %}
      {% if category.lower() in ['top', 'dress'] %}
        {% set css_group_class = 'dress' %}
      {% elif category.lower() in ['bottom', 'pant'] %}
        {% set css_group_class = 'pant' %}
      {% elif category.lower() in ['shoe', 'shoes'] %}
        {% set css_group_class = 'shoe' %}
      {% elif category.lower() in ['head', 'mask', 'facepaint'] %}
        {% set css_group_class = 'head' %}
      {% elif category.lower() == 'emote' %}
        {% set css_group_class = 'emote' %}
      {% elif category.lower() in ['avatars', 'headpic', 'backpack', 'bag'] %}
        {% set css_group_class = 'backpack' %}
      {% endif %}
    {% elif 'weapon' in category.lower() or 'gun' in category.lower() %}
      {% set css_group_class = 'weapon' %}
    {% endif %}

    <div class="vcat category-container" data-cat-group="{{ css_group_class }}">
      <div class="vcat-title">{{ category }} <span style="color:var(--dim);font-size:.62rem;font-family:'Exo 2',sans-serif;letter-spacing:1px">({{ items|length }})</span></div>
      <div class="vault-grid">
        {% for item in items %}
          <div class="item-card" data-id="{{ item.id }}" data-type="{{ category }}" data-name="{{ item.name }}">
            <div class="item-img">
              <img src="https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{{ item.id }}.png" onerror="this.src='data:image/svg+xml,%3Csvg xmlns=\\'http://www.w3.org/2000/svg\\' viewBox=\\'0 0 80 80\\'%3E%3Crect width=\\'80\\' height=\\'80\\' fill=\\'%23031a18\\'/%3E%3Ctext x=\\'40\\' y=\\'45\\' font-size=\\'8\\' text-anchor=\\'middle\\' fill=\\'%2300ffe7\\'%3E{{ item.id }}%3C/text%3E%3C/svg%3E'">
            </div>
            <div class="item-name">{{ item.name }}</div>
            <div class="item-iid">{{ item.id }}</div>
            <div class="item-rare">{{ item.rarity }}</div>
          </div>
        {% endfor %}
      </div>
    </div>
  {% endfor %}
</div>
{% endif %}

</div>
<hr class="divider">
<div class="foot">Crafted with <span>♥</span> by <span>AYAN</span> &nbsp;•&nbsp; UID: 2279016714</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.waves.min.js"></script>
<script>
const JWT="{{jwt or ''}}";
const CHAR_ID=parseInt("{{character_id or 0}}")||0;

const audio=document.getElementById('bgAudio');let playing=false;const mDisc=document.getElementById('mDisc'),mEq=document.getElementById('mEq'),mIcon=document.getElementById('mIcon'),mLbl=document.getElementById('mLbl'),mTitle=document.getElementById('mTitle');
function setMusic(on){playing=on;mDisc.classList.toggle('paused',!on);mEq.classList.toggle('paused',!on);mIcon.className=on?'fas fa-pause':'fas fa-play';mLbl.textContent=on?'PAUSE':'PLAY';mTitle.textContent=on?'♪ Now Playing — BGM':'♪ Music Paused';}
document.getElementById('mBtn').onclick=()=>{if(playing){audio.pause();setMusic(false);}else audio.play().then(()=>setMusic(true)).catch(()=>{});};
let autoTried=false;['click','touchstart'].forEach(ev=>document.addEventListener(ev,()=>{if(!autoTried&&!playing){autoTried=true;audio.play().then(()=>setMusic(true)).catch(()=>{});}},{once:true}));

function toast(msg,ok=true){const t=document.createElement('div');t.className='toast '+(ok?'ok':'er');t.innerHTML='<i class="fas fa-'+(ok?'check-circle':'times-circle')+'"></i>'+msg;document.body.appendChild(t);setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity .4s';setTimeout(()=>t.remove(),400);},3000);}
const overlay=document.getElementById('loadOverlay');function showOverlay(on){overlay.classList.toggle('show',on);}
function flash(el,ok){if(!el)return;el.classList.add(ok?'flash-ok':'flash-er');setTimeout(()=>el.classList.remove('flash-ok','flash-er'),900);}

async function apiCall(payload,targetEl){showOverlay(true);try{const r=await fetch('/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();showOverlay(false);if(d.success){toast(d.message||'Success! ✅');if(targetEl)flash(targetEl,true);}else{toast(d.error||'Failed ❌',false);if(targetEl)flash(targetEl,false);}return d;}catch(e){showOverlay(false);toast('Network Error: '+e.message,false);if(targetEl)flash(targetEl,false);return{success:false};}}

async function changeSlot(slot,curId,charId,btn){const inp=document.getElementById('nid_'+slot);const newId=parseInt(inp?.value);if(!newId){toast('Enter a valid ID',false);return;}if(newId===parseInt(curId)){toast('Same item already equipped',false);return;}const card=btn.closest('.slot-card');const r=await apiCall({action:'outfit_change',jwt:JWT,slot,new_id:newId,char_id:parseInt(charId)},card);if(r.success)setTimeout(()=>location.reload(),1200);}

document.getElementById('charBtn')?.addEventListener('click',async()=>{const sel=document.getElementById('charSel');if(!sel.value){toast('Select a character first',false);return;}const r=await apiCall({action:'change_character',jwt:JWT,new_char_id:parseInt(sel.value)},document.getElementById('charBtn'));if(r.success)setTimeout(()=>location.reload(),1200);});

document.querySelectorAll('.item-card').forEach(card=>{card.addEventListener('click',async function(){const id=parseInt(this.dataset.id);const type=(this.dataset.type||'').toLowerCase();let action='',payload={jwt:JWT};if(type==='emote'){action='emote';}else if(type.includes('weapon skin')){action='weapon';}else if(type.includes('avatars')||type.includes('headpic')){action='avatar';}else if(type.includes('bag')||type.includes('backpack')){action='backpack';}else{const slotMap={head:'head',mask:'head',shoe:'shoe',shoes:'shoe',bottom:'bottom',top:'top',facepaint:'facepaint'};const slot=slotMap[type];if(slot){action='outfit_change';payload.slot=slot;payload.char_id=CHAR_ID;}else{toast('Cannot determine slot for: '+this.dataset.type,false);flash(this,false);return;}}payload.action=action;payload.new_id=id;const r=await apiCall(payload,this);if(r.success&&action==='outfit_change'){setTimeout(()=>location.reload(),1200);}});});

function logout() {
    window.location.href = '/';
}

function switchVaultCategory(categoryGroup) {
    document.querySelectorAll('.v-tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    
    document.querySelectorAll('.category-container').forEach(container => {
        if (categoryGroup === 'all' || container.dataset.catGroup === categoryGroup) {
            container.style.display = 'block';
        } else {
            container.style.display = 'none';
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    VANTA.WAVES({
        el: "#vanta-bg",
        mouseControls: true, touchControls: true, gyroControls: false,
        minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
        color: 0x0a0523, shininess: 35.00, waveHeight: 12.00, waveSpeed: 0.7, zoom: 0.90
    });
    gsap.from("#outfit-panel", {duration: 0.6, y: 30, opacity: 0, ease: "power2.out"});
});
</script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    load_error = request.args.get('error')
    return render_template_string(LOGIN_HTML, load_error=load_error, UI_COMMON_HEADER=UI_COMMON_HEADER)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    jwt = request.args.get('jwt', '').strip()
    if not jwt:
        return redirect(url_for('index', error="Token is required to access dashboard"))
    try:
        account_id = decode_jwt(jwt)
        outfit_vals = fetch_current_outfit(jwt, account_id)
        raw_slots = extract_slots(outfit_vals)
        character_id = raw_slots.get('character')
        slots = {}
        for sname, sid in raw_slots.items():
            if sname == 'character':
                continue
            name, typ, rare = get_item_info(sid)
            slots[sname] = {'id': sid, 'name': name, 'type': typ, 'rarity': rare}
        item_ids = fetch_vault_items(jwt)
        grouped = defaultdict(list)
        for iid in item_ids:
            name, typ, rare = get_item_info(iid)
            if typ != 'Unknown':
                grouped[typ].append({'id': iid, 'name': name, 'rarity': rare})
        grouped = dict(sorted(grouped.items()))
        for typ in grouped:
            grouped[typ].sort(key=lambda x: x['name'])
        vault = grouped
        vault_total = sum(len(v) for v in vault.values())
        
        region = get_region(jwt) or 'Global'
        
        return render_template_string(
            DASHBOARD_HTML, 
            jwt=jwt, 
            slots=slots, 
            vault=vault, 
            vault_total=vault_total,
            character_id=character_id,
            account_id=account_id,
            region=region,
            UI_COMMON_HEADER=UI_COMMON_HEADER
        )
    except Exception as e:
        return redirect(url_for('index', error=f"Failed to load user session: {str(e)}"))

@app.route('/auto', methods=['POST'])
def auto_change():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request, JSON expected'}), 400

    jwt = data.get('jwt')
    action = data.get('action')
    if not jwt or not action:
        return jsonify({'success': False, 'error': 'Missing jwt or action'}), 400

    try:
        if action == 'outfit_change':
            slot = data.get('slot')
            new_id = data.get('new_id')
            char_id = data.get('char_id')
            if not all([slot, new_id, char_id]):
                return jsonify({'success': False, 'error': 'Missing slot/new_id/char_id'}), 400
            account_id = decode_jwt(jwt)
            outfit_vals = fetch_current_outfit(jwt, account_id)
            raw_slots = extract_slots(outfit_vals)
            if raw_slots.get(slot) == new_id:
                return jsonify({'success': False, 'error': 'Item already equipped in that slot'}), 400
            order = ['head', 'shoe', 'bottom', 'top']
            outfit_ids = []
            for s in order:
                if s == slot:
                    outfit_ids.append(new_id)
                else:
                    if s in raw_slots:
                        outfit_ids.append(raw_slots[s])
            if slot == 'facepaint':
                outfit_ids.append(new_id)
            if not outfit_ids:
                return jsonify({'success': False, 'error': 'No valid slot to change'}), 400
            success, status, error_text = send_change_request(jwt, char_id, outfit_ids)
            if success:
                return jsonify({'success': True, 'message': 'Outfit changed successfully'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'emote':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            region = get_region(jwt)
            if not region:
                return jsonify({'success': False, 'error': 'Could not detect region from JWT'}), 400
            server_url = REGION_SERVER_MAP.get(region)
            if not server_url:
                return jsonify({'success': False, 'error': f'No server for region {region}'}), 400
            encrypted = build_emote_payload(new_id)
            success, status, error_text = send_emote_request(jwt, server_url, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Emote equipped'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'weapon':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            encrypted = build_weapon_payload(new_id)
            success, status, error_text = send_weapon_request(jwt, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Weapon skin equipped'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'avatar':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            encrypted = build_avatar_payload(new_id)
            success, status, error_text = send_avatar_request(jwt, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Avatar changed'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'backpack':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            fields = {1: ('varint', new_id)}
            plain = serialize_fields(fields)
            encrypted = encrypt_aes_cbc(plain)
            success, status, error_text = send_backpack_request(jwt, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Backpack skin equipped'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'change_character':
            new_char_id = data.get('new_char_id')
            if not new_char_id:
                return jsonify({'success': False, 'error': 'Missing new_char_id'}), 400
            account_id = decode_jwt(jwt)
            outfit_vals = fetch_current_outfit(jwt, account_id)
            raw_slots = extract_slots(outfit_vals)
            outfit_order = ['head', 'shoe', 'bottom', 'top', 'facepaint']
            outfit_ids = [raw_slots[s] for s in outfit_order if s in raw_slots]
            if not outfit_ids:
                return jsonify({'success': False, 'error': 'No outfit items to preserve'}), 400
            vault_ids = fetch_vault_items(jwt)
            pet_id = 1300000113
            for iid in vault_ids:
                _, typ, _ = get_item_info(iid)
                if typ.lower() == 'pet':
                    pet_id = iid
                    break
            success, status, error_text = send_select_preset_request(jwt, new_char_id, pet_id)
            if not success:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400
            success2, status2, error_text2 = send_change_request(jwt, new_char_id, outfit_ids)
            if success2:
                return jsonify({'success': True, 'message': f'Character changed to {new_char_id} with outfit preserved'})
            else:
                return jsonify({'success': False, 'status': status2, 'error': error_text2}), 400

        else:
            return jsonify({'success': False, 'error': f'Unknown action: {action}'}), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/manual', methods=['GET', 'POST'])
def manual():
    if request.method == 'POST':
        jwt = request.form.get('jwt', '')
        char_id_str = request.form.get('char_id', '')
        const_val_str = request.form.get('const_val', '')
        outfit_ids_str = request.form.get('outfit_ids', '')
        if not jwt or not char_id_str or not outfit_ids_str:
            return render_template_string(MANUAL_HTML, jwt=jwt, error="Missing fields", result=None)
        try:
            char_id = int(char_id_str)
            const_val = int(const_val_str) if const_val_str else 50
            parts = [x.strip() for x in outfit_ids_str.split(',') if x.strip()]
            outfit_ids = [int(p) for p in parts]
        except Exception as e:
            return render_template_string(MANUAL_HTML, jwt=jwt, error=f"Invalid input: {e}", result=None)
        fields = {
            1: ('varint', char_id),
            3: ('varint', const_val),
            2: ('bytes', encode_packed_varint(outfit_ids))
        }
        plain_bytes = serialize_fields(fields)
        encrypted = encrypt_aes_cbc(plain_bytes)
        base_url = get_base_url(jwt)
        url = f"{base_url}/ChangeClothes"
        headers = {
            "User-Agent": "UnityPlayer/2022.3.47f1",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": "2022.3.47f1",
            "ReleaseVersion": "OB54",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {jwt}"
        }
        try:
            resp = requests.post(url, headers=headers, data=encrypted, timeout=15)
            result = {'success': resp.status_code == 200, 'status': resp.status_code, 'error': resp.text if resp.status_code != 200 else ''}
        except Exception as e:
            result = {'success': False, 'status': 0, 'error': str(e)}
        return render_template_string(MANUAL_HTML, jwt=jwt, decoded={'char_id': char_id, 'const_val': const_val, 'outfit_ids': ', '.join(str(i) for i in outfit_ids)}, result=result)
    jwt = request.args.get('jwt', '')
    if not jwt:
        return render_template_string(MANUAL_HTML, jwt=None, error=None, result=None)
    try:
        account_id = decode_jwt(jwt)
        outfit_vals = fetch_current_outfit(jwt, account_id)
        raw_slots = extract_slots(outfit_vals)
        char_id = raw_slots.get('character')
        if not char_id:
            raise ValueError("Character ID not found in outfit")
        order = ['head', 'shoe', 'bottom', 'top', 'facepaint']
        outfit_ids = [raw_slots[s] for s in order if s in raw_slots]
        decoded = {'char_id': char_id, 'const_val': 50, 'outfit_ids': ', '.join(str(i) for i in outfit_ids)}
        return render_template_string(MANUAL_HTML, jwt=jwt, decoded=decoded, error=None, result=None)
    except Exception as e:
        return render_template_string(MANUAL_HTML, jwt=jwt, error=str(e), result=None)

MANUAL_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Manual Outfit Editor</title><style>body{font-family:monospace;background:#0a0f1e;color:#eee;padding:20px}h2,h3{color:#ffcc00}.container{max-width:900px;margin:auto}label{display:block;margin-top:15px;color:#ffcc00}input,textarea{width:100%;background:#1e243b;color:#fff;border:1px solid #ffcc00;padding:10px;font-family:monospace;margin-top:5px}textarea{height:120px}button{padding:10px 20px;margin:15px 0;background:#ffcc00;color:#000;font-weight:bold;cursor:pointer;border:none;border-radius:4px}.error{color:#ff7777}.success{color:#88ff88}</style></head><body><div class="container"><h2>Manual Outfit Editor</h2><form method="GET"><label>JWT Token:</label><input type="text" name="jwt" value="{{ jwt or '' }}" placeholder="Paste your JWT"><button type="submit">Load Current Outfit</button></form>{% if error %}<div class="error">{{ error }}</div>{% endif %}{% if decoded %}<h3>Decoded ChangeClothes Request (Edit & Send)</h3><form method="POST"><input type="hidden" name="jwt" value="{{ jwt }}"><label>Field 1 (Character ID):</label><input type="number" name="char_id" value="{{ decoded.char_id }}"><label>Field 3 (Unknown constant):</label><input type="number" name="const_val" value="{{ decoded.const_val }}"><label>Field 2 (Outfit IDs – comma separated, order: head,shoe,bottom,top,facepaint):</label><textarea name="outfit_ids">{{ decoded.outfit_ids }}</textarea><button type="submit">Send Edited Request</button></form>{% endif %}{% if result %}<div class="{{ 'success' if result.success else 'error' }}">{% if result.success %}✅ Sent successfully (HTTP 200){% else %}❌ Failed (HTTP {{ result.status }}) – {{ result.error }}{% endif %}</div>{% endif %}<p style="margin-top:30px;"><a href="/" style="color:#ffcc00;">← Back to main</a></p></div></body></html>"""

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)