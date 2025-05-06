import requests
import webbrowser
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from env import MERAKI_CLIENT_ID, MERAKI_CLIENT_SECRET, MERAKI_REDIRECT_URI, MERAKI_REFRESH_TOKEN_PATH
from urllib.parse import urlencode
import base64

AUTH_URL = "https://as.meraki.com/oauth/authorize"
TOKEN_URL = "https://as.meraki.com/oauth/token"
SCOPES = "dashboard:general:config:read sdwan:config:read sdwan:config:write"

# Step 1: Construct the authorization URL
params = {
    "response_type": "code",
    "client_id": MERAKI_CLIENT_ID,
    "redirect_uri": MERAKI_REDIRECT_URI,
    "scope": SCOPES,
    "state": "xyz"
}
print(f"scope: {SCOPES}")
auth_request_url = f"{AUTH_URL}?{urlencode(params)}"
print(f"[DEBUG] Auth URL being opened:\n{auth_request_url}\n")

# Step 2: Local web server to handle callback
class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        code = query.get('code', [None])[0]
        print(f"[DEBUG] Callback path: {self.path}")
        print(f"[DEBUG] Parsed query: {query}")
        if code:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authorization successful. You can close this window.")
            exchange_code_for_tokens(code)
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing authorization code.")

def exchange_code_for_tokens(code):
    basic_auth = f"{MERAKI_CLIENT_ID}:{MERAKI_CLIENT_SECRET}"
    encoded_auth = base64.b64encode(basic_auth.encode()).decode()
    headers = {
        "Authorization": f"Basic {encoded_auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": MERAKI_REDIRECT_URI,
        "scope": "dashboard:general:config:read sdwan:config:read sdwan:config:write"
    }
    response = requests.post(TOKEN_URL, data=payload, headers=headers)
    print(f"[DEBUG] Token endpoint response status: {response.status_code}")
    print(f"[DEBUG] Token endpoint response body: {response.text}")
    response.raise_for_status()
    tokens = response.json()
    refresh_token = tokens["refresh_token"]
    with open(MERAKI_REFRESH_TOKEN_PATH, "w") as f:
        json.dump({"refresh_token": refresh_token}, f, indent=2)
    print(f"\n✅ Refresh token saved to {MERAKI_REFRESH_TOKEN_PATH}")

if __name__ == "__main__":
    print("🌐 Opening browser for Meraki OAuth login...")
    webbrowser.open(auth_request_url)
    print("🚪 Starting local HTTP server to receive the callback...")
    httpd = HTTPServer(("localhost", 8080), OAuthHandler)
    httpd.handle_request()
