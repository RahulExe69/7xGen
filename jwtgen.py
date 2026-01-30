from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Init colorama
init(autoreset=True)

# Flask setup
app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

def get_token(password, uid):
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            # Updated to match the modern Android 14 standard for OB52
            "User-Agent": "GarenaMSDK/4.4.0 (A063; Android 14; en; IN;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        res = requests.post(url, headers=headers, data=data, timeout=10)
        if res.status_code != 200:
            return None
        token_json = res.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        else:
            return None
    except Exception:
        return None

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Both uid and password parameters are required"}), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password. Please check and try again.",
            "credit": "@rahulexez"
        }), 400

    # OB52 UPDATED GAME DATA
    game_data = my_pb2.GameData()
    game_data.timestamp = "2026-01-30 23:30:00"
    game_data.game_name = "free fire"
    game_data.game_version = 2
    # Changed from 1.109.2 to the current OB52 version
    game_data.version_code = "1.120.1" 
    game_data.os_info = "Android OS 14 / API-34"
    game_data.device_type = "Handheld"
    game_data.network_provider = "WIFI"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv8 NEON | 2800 | 8"
    game_data.total_ram = 7951
    game_data.gpu_name = "Adreno (TM) 740"
    game_data.gpu_version = "OpenGL ES 3.2"
    game_data.user_id = f"Google|{token_data['open_id']}"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Pixel 8"
    game_data.library_path = "/data/app/com.dts.freefireth/base.apk"
    game_data.apk_info = "OB52_hash_val|/data/app/com.dts.freefireth/base.apk"
    game_data.os_architecture = "64"
    game_data.build_number = "2026011400" # Current build number for January
    game_data.marketplace = "google_play"
    
    # Required constant fields from your original code
    game_data.field_60 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES3"
    game_data.rendering_api = 4
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_payload if 'encrypted_payload' in locals() else encrypted_data).decode()

        # CURRENT MAJORLOGIN ENDPOINT FOR 2026
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UD1A.230811.061)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream", # Binary format required
            'Expect': "100-continue",
            'X-Unity-Version': "2020.3.36f1", # Updated Unity engine version
            'X-GA': "v1 1",
            'ReleaseVersion': "1.120.1" # Mandatory OB52 numeric string
        }

        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False, timeout=20)

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                return jsonify({
                    "uid": uid,
                    "status": response_dict.get("status", "success"),
                    "token": response_dict.get("token", "N/A")
                })
            except Exception as e:
                return jsonify({"uid": uid, "error": f"Decoding failed: {str(e)}"}), 400
        else:
            return jsonify({"uid": uid, "error": f"HTTP {response.status_code} from Garena"}), response.status_code
            
    except Exception as e:
        return jsonify({"uid": uid, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
