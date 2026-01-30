#!/usr/bin/env python3
"""
FreeFire JWT Generator (Standalone)
====================================
UID aur Password se JWT token generate karta hai - OB52 UPDATED
"""

import httpx
import asyncio
import json
import base64
from typing import Tuple
from google.protobuf import json_format, message
from Crypto.Cipher import AES
from ff_proto import freefire_pb2

# ===== ENCRYPTION CONSTANTS =====
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

# --- MODIFIED VERSIONS FOR OB52 (JANUARY 2026) ---
RELEASEVERSION = "1.120.1" 
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UD1A.230811.061)"
UNITY_VERSION = "2020.3.36f1"
# -------------------------------------------------

# ===== HELPER FUNCTIONS =====
async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    """JSON ko Protobuf bytes mein convert karta hai"""
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def pad(text: bytes) -> bytes:
    """PKCS7 Padding apply karta hai"""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-CBC encryption"""
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    return aes.encrypt(padded_plaintext)

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    """Protobuf bytes ko decode karta hai"""
    message_instance = message_type()
    message_instance.ParseFromString(encoded_data)
    return message_instance

# ===== STEP 1: ACCESS TOKEN OBTAIN KARO =====
async def get_access_token(uid: str, password: str) -> Tuple[str, str]:
    """
    Guest UID aur Password se Access Token obtain karta hai
    """
    print(f"\n[1/3] Access Token obtain kar rahe hain...")
    
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"uid={uid}&password={password}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=payload, headers=headers)
        data = response.json()
        
        access_token = data.get("access_token", "0")
        open_id = data.get("open_id", "0")
        
        if access_token == "0":
            raise ValueError("❌ Access Token obtain nahi hua!")
        
        print(f"   ✓ Access Token: {access_token[:20]}...")
        print(f"   ✓ Open ID: {open_id}")
        
        return access_token, open_id

# ===== STEP 2: JWT TOKEN GENERATE KARO =====
async def generate_jwt(uid: str, password: str) -> Tuple[str, str, str]:
    """
    Guest credentials se JWT token generate karta hai
    """
    # Step 1: Access Token lo
    access_token, open_id = await get_access_token(uid, password)
    
    # Step 2: Protobuf request banao
    print(f"\n[2/3] Protobuf request bana rahe hain...")
    
    json_data = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": access_token,
        "orign_platform_type": "4"
    })
    
    # Protobuf encode karo
    encoded_result = await json_to_proto(json_data, freefire_pb2.LoginReq())
    print(f"   ✓ Protobuf serialized: {len(encoded_result)} bytes")
    
    # Step 3: AES-CBC encrypt karo
    encrypted_payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
    print(f"   ✓ AES-CBC encrypted: {len(encrypted_payload)} bytes")
    
    # Step 4: MajorLogin API ko request bhejo
    print(f"\n[3/3] JWT generate kar rahe hain (OB52 Version)...")
    
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': UNITY_VERSION,
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=encrypted_payload, headers=headers)
        response_content = response.content
        
        # Response ko decode karo
        message = json.loads(json_format.MessageToJson(
            decode_protobuf(response_content, freefire_pb2.LoginRes)
        ))
        
        jwt_token = message.get("token", "0")
        region = message.get("lockRegion", "0")
        server_url = message.get("serverUrl", "0")
        
        if jwt_token == "0":
            raise ValueError("❌ JWT token generate nahi hua!")
        
        print(f"   ✓ JWT Token successfully generated!")
        
        return jwt_token, region, server_url

# ===== MAIN PROGRAM =====
async def main():
    print("=" * 60)
    print("    🔐 OB52 UPDATED: FreeFire JWT Generator")
    print("=" * 60)
    
    # User se input lo
    uid = input("\n📱 Guest UID enter karo: ").strip()
    password = input("🔑 Guest Password enter karo: ").strip()
    
    if not uid or not password:
        print("\n❌ UID aur Password dono zaruri hain!")
        return
    
    try:
        # JWT generate karo
        jwt_token, region, server_url = await generate_jwt(uid, password)
        
        # Results display karo
        print("\n" + "=" * 60)
        print("        ✅ JWT SUCCESSFULLY GENERATED!")
        print("=" * 60)
        print(f"\n🎫 JWT Token:")
        print(f"   {jwt_token}")
        print(f"\n🌍 Region: {region}")
        print(f"🖥️  Server URL: {server_url}")
        print("\n" + "=" * 60)
        
        # Optional: JSON format mein bhi dikhaao
        result = {
            "jwt_token": jwt_token,
            "region": region,
            "server_url": server_url,
            "uid": uid
        }
        
        print(f"\n📄 JSON Format:")
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
