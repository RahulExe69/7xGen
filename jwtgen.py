from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import warnings
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# =====================
# CONSTANTS (FIXED)
# =====================
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

RELEASEVERSION = "OB49"   # IMPORTANT: login OB, not game OB

# =====================
# FLASK SETUP
# =====================
app = Flask(__name__)
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 25200
})

# =====================
# HELPERS
# =====================
def get_token(password, uid):
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",
            "Content-Type": "application/x-www-form-urlencoded",
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
        j = res.json()
        if "access_token" in j and "open_id" in j:
            return j
        return None
    except:
        return None


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def parse_response(content):
    out = {}
    for line in content.split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


# =====================
# API
# =====================
@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or password"
        }), 400

    game_data = my_pb2.GameData()

    # ===== FIXED & SYNCED FIELDS =====
    game_data.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "free fire"
    game_data.game_version = 49                 # OB49 login identity
    game_data.version_code = "1.111.1"
    game_data.os_info = "Android OS 13 / API-33"
    game_data.device_type = "Handheld"
    game_data.network_provider = "airtel"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv8"
    game_data.total_ram = 6144
    game_data.gpu_name = "Adreno"
    game_data.gpu_version = "OpenGL ES 3.2"
    game_data.user_id = "Google|dummy"
    game_data.ip_address = "127.0.0.1"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "A063"

    try:
        serialized = game_data.SerializeToString()
        encrypted = encrypt_message(AES_KEY, AES_IV, serialized)
        payload = binascii.hexlify(encrypted).decode()

        # ===== FIXED LOGIN ENDPOINT =====
        url = "https://loginbp.ggblueshark.com/MajorLogin"

        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 13)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASEVERSION
        }

        response = requests.post(
            url,
            data=bytes.fromhex(payload),
            headers=headers,
            verify=False,
            timeout=15
        )

        if response.status_code != 200:
            return jsonify({
                "uid": uid,
                "error": f"HTTP {response.status_code}"
            }), 400

        msg = output_pb2.Garena_420()
        msg.ParseFromString(response.content)
        parsed = parse_response(str(msg))

        return jsonify({
            "uid": uid,
            "status": parsed.get("status", "N/A"),
            "token": parsed.get("token", "N/A")
        })

    except Exception as e:
        return jsonify({
            "uid": uid,
            "error": str(e)
        }), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
