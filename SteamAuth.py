import requests
import json
import rsa
import base64
from random import choice

class SteamLogin:
    def __init__(self, username: str, password: str, save_login_secure=False):
        self.username  = username
        self.password  = password
        self.save_login_secure = save_login_secure

        self.steamID64 = None
        self.steam_gaurd_type = None
        self.steamLoginSecure = None
        self.claim_cookie = None

        self.client_id = None
        self.request_id = None

        self.session = requests.Session()
        self.session_id = self.session.post("https://steamcommunity.com").cookies['sessionid']

       
        self.access_token = None
        self.refresh_token = None

        self._startLogin()


    def _fetch_rsa_params(self, retry: int = 3) -> dict:
        response = self.session.get("https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/?account_name=" + self.username)
        key_response = json.loads(response.text)
        for i in range(retry):
            try:
                rsa_mod = int(key_response["response"]['publickey_mod'], 16)
                rsa_exp = int(key_response["response"]['publickey_exp'], 16)
                rsa_timestamp = key_response["response"]['timestamp']
                rsa_key = rsa.PublicKey(rsa_mod, rsa_exp)
                encrypted_password = base64.b64encode(rsa.encrypt(self.password.encode('utf-8'), rsa_key))
                return {'encrypted_password': encrypted_password,
                        'rsa_timestamp': rsa_timestamp}
            except KeyError:
                if retry >= 2:
                    raise ValueError('Could not obtain rsa-key')

        

    def _startLogin(self):
        rsa = self._fetch_rsa_params()
        data = {
            'persistence': "1",
            'encrypted_password': rsa['encrypted_password'],
            'account_name': self.username,
            'encryption_timestamp': rsa['rsa_timestamp'],
        }
        response = self.session.post("https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1", data=data)
        key_response = json.loads(response.text)
        print(key_response)
        

        if '"confirmation_type":2' in response.text:
            self.steam_gaurd_type = 2
        
        if '"confirmation_type":3' in response.text:
            self.steam_gaurd_type = 3

        self._UpdateSteamGaurd(key_response)

    def _UpdateSteamGaurd(self, login_resposne):
        self.client_id = login_resposne['response']['client_id']
        self.request_id = login_resposne['response']['request_id']
        self.steamID64 = login_resposne["response"]["steamid"]

        if self.steam_gaurd_type == 3:
            code = input('[>] Steam MFA Code: ')
        elif self.steam_gaurd_type == 2:
            email_domain = next((c['associated_message'] 
                                    for c in login_resposne['response']['allowed_confirmations'] 
                                    if 'associated_message' in c), 
                                    None)
            code = input(f'[>] Email Code ({email_domain}): ')
        else: code = None

        update_data = {
            'client_id': self.client_id,
            'steamid': self.steamID64,
            'code_type': self.steam_gaurd_type,
            'code': code
        }

        self.session.post("https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/", data=update_data)
        self._pool_sessions()


    def _pool_sessions(self):
        pool_data = {
            'client_id': self.client_id,
            'request_id': self.request_id
        }

        headers = {
            "X-Requested-With": "com.valvesoftware.android.steam.community",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9"
        }
        response = self.session.post("https://api.steampowered.com//IAuthenticationService/PollAuthSessionStatus/v1/", data=pool_data, headers=headers)

        if '"access_token' in response.text:
            print(f'[+] Logged into {self.username}')
            self.refresh_token, self.access_token = (
                response.json()['response'][k]
                for k in ('refresh_token', 'access_token')
            )  

            if self.save_login_secure:
                self._fetchSteamLoginSecure()
        
        else:
            print(f'[-] Failed to login into {self.username}')

        
    def _fetchSteamLoginSecure(self):
        data = {
            'nonce': self.refresh_token,
            'sessionid':self.session_id,
            'redir':'https://store.steampowered.com/login/?redir=&redir_ssl=1'
        }

        response = self.session.post('https://login.steampowered.com/jwt/finalizelogin', data=data)
        key_response = response.json()
        nonce = next(item['params']['nonce']
                    for item in key_response['transfer_info']
                    if 'steamcommunity.com/login/settoken' in item['url'])
        auth  = next(item['params']['auth']
                    for item in key_response['transfer_info']
                    if 'steamcommunity.com/login/settoken' in item['url'])
        
        update_data = {
            'nonce':nonce,
            'auth':auth,
            'steamID':self.steamID64,
            }
        
        response = self.session.post('https://steamcommunity.com/login/settoken', data=update_data)

        self.steamLoginSecure = response.cookies['steamLoginSecure']
        self.claim_cookie = f'sessionid={self.session_id}; steamLoginSecure={self.steamLoginSecure}'



