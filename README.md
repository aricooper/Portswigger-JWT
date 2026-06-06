# PortSwigger JWT Attack Labs

Automated Python exploits for three PortSwigger Web Security Academy JWT labs, one at each difficulty level. Each script fully automates the attack chain: authenticate, exploit the JWT vulnerability, access the admin panel, and delete the target user.

## Overview

JWT (JSON Web Token) authentication is a common target in web app penetration testing. These labs demonstrate three distinct attack classes against misconfigured JWT implementations, progressing from trivial to cryptographically sophisticated.

| Script | Difficulty | Vulnerability | Technique |
|--------|-----------|---------------|-----------|
| `JWT_apprentice.py` | Apprentice | Signature not verified | Modify payload, reuse signature |
| `JWT_practitioner.py` | Practitioner | Weak HMAC secret | Brute-force secret, forge valid token |
| `JWT_expert.py` | Expert | Algorithm confusion (RS256 → HS256) | sig2n n-factor recovery, public key as HMAC secret |

## Setup

```bash
pip install requests beautifulsoup4 pyjwt jwcrypto cryptography
```

The expert lab also requires Docker for the `portswigger/sig2n` tool:

```bash
docker pull portswigger/sig2n
```

## Labs

### Apprentice — JWT authentication bypass via unverified signature

**Vulnerability:** The server accepts JWTs without verifying the signature — only the payload is checked.

**Attack:** Decode the base64 payload, change `role` to `admin` and `sub` to `administrator`, re-encode, and send the modified token with the original (unverified) signature.

```python
# Core of the attack
decoded_payload['role'] = 'admin'
decoded_payload['sub'] = 'administrator'
new_jwt = f'{header}.{new_payload}.{signature}'  # original signature reused
```

**Key insight:** JWTs are only secure if the server validates the signature. Accepting an unsigned or unverified token completely defeats the purpose of the mechanism.

---

### Practitioner — JWT authentication bypass via weak signing secret

**Vulnerability:** The server uses HS256 but with a guessable secret from a known wordlist.

**Attack:** Brute-force the HMAC-SHA256 secret by iterating a JWT-specific wordlist, then forge a new token with admin privileges signed with the recovered secret.

```python
# Brute-force the secret
for line in f:
    secret = line.strip()
    try:
        pyjwt.decode(jwt, secret, algorithms=["HS256"])
        break  # found it
    except pyjwt.exceptions.InvalidSignatureError:
        continue

# Forge a valid token
signature = hmac.new(secret.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest()
```

**Key insight:** HS256 security depends entirely on secret strength. Common secrets, short secrets, or secrets from wordlists are trivially crackable offline given any valid JWT.

---

### Expert — JWT authentication bypass via algorithm confusion (n-factor attack)

**Vulnerability:** The server uses RS256 (asymmetric) but can be confused into accepting HS256 tokens. The public key is recoverable from two JWT samples, and that public key is then used as the HMAC secret.

**Attack:**
1. Collect two JWT tokens signed with the same RSA private key
2. Use `portswigger/sig2n` (Docker) to recover candidate RSA modulus values from the two signatures
3. Test each candidate against the server to find the valid public key
4. Forge an admin token signed with the recovered public key as the HMAC secret

```python
# Run sig2n to recover the public key from two JWT samples
result = subprocess.run(
    ["sudo", "docker", "run", "--rm", "-it", "portswigger/sig2n", tokens[0], tokens[1]],
    capture_output=True, text=True
)
# Parse candidates, test each, forge admin token with valid public key
```

**Key insight:** Algorithm confusion attacks exploit servers that don't strictly enforce which algorithm they accept. If an RS256 server will also accept HS256, an attacker who can recover the public key (often possible from two JWT samples) can forge arbitrary tokens.

---

## Skills demonstrated

- HTTP session handling and CSRF token extraction with `requests` + `BeautifulSoup`
- JWT structure: base64url encoding/decoding of header, payload, and signature
- HMAC-SHA256 signing and verification with `hmac` and `hashlib`
- Offline secret recovery via wordlist brute-force
- RSA public key recovery from signature pairs (n-factor attack)
- Algorithm confusion exploitation
- Subprocess integration with Docker tooling
- Automated end-to-end exploit chains

## Notes

Scripts target specific lab instances (hardcoded URLs). To run against a new lab instance, update the `site` variable at the top of each script with the lab URL assigned by PortSwigger.

Completed as part of PSU CS 595, Web and Cloud Security, Winter 2026.