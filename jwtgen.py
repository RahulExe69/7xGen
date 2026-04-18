from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
import json
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Import the working MajorLogin functions from new code
from Utilities.until import encode_protobuf, decode_protobuf
import Proto.compiled.MajorLogin_pb2
from Configuration.APIConfiguration import RELEASEVERSION  # or set directly e.g., "OB52"

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Init colorama
init(autoreset=True)

# Flask setup
app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

def get_token(password, uid):
    """Same as before – this part works fine"""
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
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
        return None
    except Exception:
        return None

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

    # ----- Use the NEW code's MajorLogin logic -----
    try:
        # Create encrypted payload using the working protobuf (only 3 fields)
        encrypted_payload = encode_protobuf({
            "openid": token_data['open_id'],
            "logintoken": token_data['access_token'],
            "platform": "4",
        }, Proto.compiled.MajorLogin_pb2.request())   # note: request() returns a protobuf message instance

        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; A063 Build/TKQ1.221220.001)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'Authorization': "Bearer",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION,   # e.g., "OB52"
        }

        response = requests.post(url, data=encrypted_payload, headers=headers, verify=False)

        if response.status_code == 200:
            # Decode response using new code's decoder
            message = decode_protobuf(response.content, Proto.compiled.MajorLogin_pb2.response())
            # Convert message to a dict (assuming message has 'status' and 'token' fields)
            # You may need to adapt this based on actual response structure
            return jsonify({
                "uid": uid,
                "status": getattr(message, 'status', 'N/A'),
                "token": getattr(message, 'token', 'N/A')
            })
        else:
            return jsonify({
                "uid": uid,
                "error": f"Failed to get response: HTTP {response.status_code}, {response.reason}"
            }), 400
    except Exception as e:
        return jsonify({
            "uid": uid,
            "error": f"Internal error: {str(e)}"
        }), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
