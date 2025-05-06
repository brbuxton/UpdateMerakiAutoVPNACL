import requests
import json
import os
from env import (
    MERAKI_CLIENT_ID,
    MERAKI_CLIENT_SECRET,
    MERAKI_REFRESH_TOKEN_PATH,
)

def load_refresh_token():
    with open(MERAKI_REFRESH_TOKEN_PATH, "r") as f:
        return json.load(f)["refresh_token"]

def save_refresh_token(new_refresh_token):
    os.makedirs(os.path.dirname(MERAKI_REFRESH_TOKEN_PATH), exist_ok=True)
    with open(MERAKI_REFRESH_TOKEN_PATH, "w") as f:
        json.dump({"refresh_token": new_refresh_token}, f)

def get_access_token():
    refresh_token = load_refresh_token()

    token_url = "https://as.meraki.com/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": MERAKI_CLIENT_ID,
        "client_secret": MERAKI_CLIENT_SECRET,
    }

    response = requests.post(token_url, data=payload)
    response.raise_for_status()
    tokens = response.json()

    access_token = tokens["access_token"]
    if "refresh_token" in tokens:
        save_refresh_token(tokens["refresh_token"])

    return access_token
