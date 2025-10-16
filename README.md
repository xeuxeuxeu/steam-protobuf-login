# SteamLogin (Python)

Minimal Steam login via Valve's modern auth flow. Gets access/refresh tokens and optionally the steamLoginSecure web cookie.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install requests rsa
```

## Usage

```python
from login import SteamLogin

login = SteamLogin("YOUR_STEAM_USERNAME", "YOUR_STEAM_PASSWORD", save_login_secure=True)
# If Steam Guard is enabled, you'll be prompted for a code.

print("SteamID64:", login.steamID64)
print("Access token:", login.access_token)
print("Refresh token:", login.refresh_token)
print("Claim cookie:", login.claim_cookie)  # sessionid=...; steamLoginSecure=...
```

## Outputs

- access_token, refresh_token, steamID64
- steamLoginSecure (when save_login_secure=True)
- claim_cookie (ready to paste), session (requests.Session)

## Notes

- Interactive prompt handles Steam Guard (email or TOTP).
- Keep tokens/cookies secret; do not commit credentials.
- Use with your own account and respect Steam's Terms.

## License

MIT (or your choice).
