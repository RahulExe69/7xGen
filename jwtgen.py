from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import base64
from google.protobuf import json_format
from ff_proto import freefire_pb2
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# AES Keys (same as before)
AES_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
AES_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

# Constants
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UP1A.231005.007)"
RELEASEVERSION = "OB50"  # update when new version comes

# Flask setup
app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})


# ---------------- TOKEN STEP ----------------
def get_token(uid, password):
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        
        payload = f"uid={uid}&password={password}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
        
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded"
        }

        res = requests.post(url, data=payload, headers=headers, timeout=10)
        data = res.json()

        return data.get("access_token"), data.get("open_id")

    except Exception:
        return None, None


# ---------------- AES ----------------
def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


# ---------------- MAIN ROUTE ----------------
@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def generate_jwt():

    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    access_token, open_id = get_token(uid, password)

    if not access_token:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password"
        }), 400

    try:
        # -------- NEW LOGIN PAYLOAD --------
        login_req = freefire_pb2.LoginReq()
        login_req.open_id = open_id
        login_req.open_id_type = 4
        login_req.login_token = access_token
        login_req.orign_platform_type = 4

        serialized = login_req.SerializeToString()
        encrypted = encrypt_message(AES_KEY, AES_IV, serialized)

        # -------- LOGIN REQUEST --------
        url = "https://loginbp.ggblueshark.com/MajorLogin"

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }

        response = requests.post(url, data=encrypted, headers=headers, verify=False)

        if response.status_code != 200:
            return jsonify({
                "uid": uid,
                "error": f"HTTP {response.status_code}"
            }), 400

        # -------- DECODE RESPONSE --------
        login_res = freefire_pb2.LoginRes()
        login_res.ParseFromString(response.content)

        response_dict = json.loads(json_format.MessageToJson(login_res))

        return jsonify({
            "uid": uid,
            "status": "success",
            "token": response_dict.get("token", "N/A"),
            "region": response_dict.get("lockRegion", "N/A")
        })

    except Exception as e:
        return jsonify({
            "uid": uid,
            "error": str(e)
        }), 500


# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
