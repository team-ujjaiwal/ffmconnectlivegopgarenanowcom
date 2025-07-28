from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import Fore, Style, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ignore SSL certificate warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Initialize colorama
init(autoreset=True)

# Initialize Flask app
app = Flask(__name__)

# Configure Flask-Caching
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
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
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None
    return response.json()

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def load_tokens(file_path, limit=None):
    with open(file_path, 'r') as file:
        data = json.load(file)
        tokens = list(data.items())
        if limit is not None:
            tokens = tokens[:limit]  # تحديد عدد التوكنات
        return tokens

def parse_response(response_content):
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_token(uid, password, index):
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "Failed to retrieve token"}

    # Create GameData Protobuf
    game_data = my_pb2.GameData()
    # ... [rest of your GameData initialization code remains the same] ...

    # Serialize and encrypt data
    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    # Send encrypted data to server
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB49"
    }
    edata = bytes.fromhex(hex_encrypted_data)

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                
                # Determine server URL based on index
                if index == 0:  # First account
                    server_info = {
                        "status": "live",
                        "region": "IND",
                        "serverUrl": "https://client.ind.freefiremobile.com",
                        "token": response_dict.get("token", "N/A")
                    }
                elif index == 1:  # Second account
                    server_info = {
                        "status": "live",
                        "region": "NA, BR, SAC, US",
                        "serverUrl": "https://client.us.freefiremobile.com",
                        "token": response_dict.get("token", "N/A")
                    }
                else:  # Third account and beyond
                    server_info = {
                        "status": "live",
                        "region": "SG, ID, VN, TH, TW, ME, PK, RU, CIS, BD, EROUPE",
                        "serverUrl": "https://clientbp.ggblueshark.com",
                        "token": response_dict.get("token", "N/A")
                    }
                
                return server_info
            except Exception as e:
                return {
                    "uid": uid,
                    "error": f"Failed to deserialize the response: {e}"
                }
        else:
            return {
                "uid": uid,
                "error": f"Failed to get response: HTTP {response.status_code}, {response.reason}"
            }
    except requests.RequestException as e:
        return {
            "uid": uid,
            "error": f"An error occurred while making the request: {e}"
        }

@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200)
def get_responses():
    # Load only first 3 UID-passwords from accs.txt
    tokens = load_tokens("accs.txt", limit=3)
    server_responses = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_uid = {
            executor.submit(process_token, uid, password, index): (uid, index) 
            for index, (uid, password) in enumerate(tokens)
        }
        
        for future in as_completed(future_to_uid):
            try:
                result = future.result()
                if result and "token" in result:
                    server_responses.append(result)
            except Exception:
                continue  # Skip on error

    return jsonify({"servers": server_responses})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=50011)
