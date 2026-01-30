import requests
import json
import Proto.compiled.MajorLogin_pb2 # Ensure these are compiled from the OB52 APK
from Utilities.until import encode_protobuf, decode_protobuf
from Configuration.APIConfiguration import DEBUG

# CURRENT OB52 VERSION (January 2026)
OB52_VERSION = "1.120.1" 
UNITY_VERSION = "2020.3.36f1"

def generate_jwt_token(logintoken, openid):
    """
    Final fixed code for OB52 (January 2026). 
    Fixes the duplicate header bug and updates versioning strings.
    """
    # Create the binary payload for MajorLogin
    try:
        encrypted_payload = encode_protobuf({
            "openid": openid,
            "logintoken": logintoken,
            "platform": "4", # Standard for Android
        }, Proto.compiled.MajorLogin_pb2.request())
    except Exception as e:
        print(f"[e] Protobuf Encoding Error: {e}")
        return None

    # Endpoint for login
    url = "https://loginbp.ggblueshark.com/MajorLogin"

    # FIXED HEADERS - Removed duplicate Content-Type
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UD1A.230811.061)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", # THIS MUST BE THE ONLY ONE
        'Expect': "100-continue",
        'Authorization': "Bearer",
        'X-Unity-Version': UNITY_VERSION, # Updated for OB52 compatibility
        'X-GA': "v1 1",
        'ReleaseVersion': OB52_VERSION, # Current Live Version
    }

    try:
        # Execute the request
        response = requests.post(url, data=encrypted_payload, headers=headers, timeout=20)
        response.raise_for_status()

        if DEBUG:
            print("[I] Raw Response Received")

        # Decode the binary response into a readable format
        message = decode_protobuf(response.content, Proto.compiled.MajorLogin_pb2.response)
        
        # Convert the protobuf object to a standard Python dictionary
        return json.loads(json.dumps(message, default=str))

    except requests.exceptions.HTTPError as e:
        print(f"[e] Server rejected request (Version/Auth Error): {e}")
    except Exception as e:
        print(f"[e] Unhandled Error: {e}")
    
    return False
