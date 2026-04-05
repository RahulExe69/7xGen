import json
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from google.protobuf import json_format
from ff_proto import freefire_pb2

# ---- CONSTANTS ----
AES_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
AES_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UP1A.231005.007)"
RELEASEVERSION = "OB50"   # if breaks later → update to OB51/OB52


# ---- AES ----
def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


# ---- STEP 1: GET ACCESS TOKEN ----
def get_token(uid, password):
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


# ---- MAIN HANDLER (VERCEL) ----
def handler(request):
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')

        if not uid or not password:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "uid and password required"})
            }

        access_token, open_id = get_token(uid, password)

        if not access_token:
            return {
                "statusCode": 400,
                "body": json.dumps({"status": "invalid"})
            }

        # ---- NEW LOGIN SYSTEM ----
        login_req = freefire_pb2.LoginReq()
        login_req.open_id = open_id
        login_req.open_id_type = 4
        login_req.login_token = access_token
        login_req.orign_platform_type = 4

        serialized = login_req.SerializeToString()
        encrypted = encrypt_message(AES_KEY, AES_IV, serialized)

        url = "https://loginbp.ggblueshark.com/MajorLogin"

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }

        response = requests.post(url, data=encrypted, headers=headers)

        login_res = freefire_pb2.LoginRes()
        login_res.ParseFromString(response.content)

        response_dict = json.loads(json_format.MessageToJson(login_res))

        return {
            "statusCode": 200,
            "body": json.dumps({
                "uid": uid,
                "status": "success",
                "token": response_dict.get("token"),
                "region": response_dict.get("lockRegion")
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
