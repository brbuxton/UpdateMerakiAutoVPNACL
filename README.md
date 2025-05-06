# 🚧 Meraki AutoVPN ACL Updater

This script automates the management of **Cisco Meraki AutoVPN firewall rules**, enabling you to:

* Load a CSV list of destination IPs
* Construct a deny rule with a customizable source CIDR
* Apply that rule to an organization’s VPN firewall policy
* Avoid duplicating existing rules or breaking manual configurations

---

## 🛠️ Use Cases

* Block known bad or restricted IPs across an SD-WAN fabric
* Demonstrate AutoVPN ACL automation in customer PoCs
* Rapidly prototype Meraki API integrations

---

## 🔒 Authentication

This tool supports two authentication methods:

### 1. **API Key (Recommended for Demos)**

Simpler for short-term use cases. Ask your customer to:

* Generate an API key in the Meraki Dashboard
* Paste it into `env.py` or set it via environment variable

> ⚠️ API keys grant wide access — use only in trusted, time-bound contexts.

### 2. **OAuth 2.0 (Optional for Persistent Tools)**

Supports token-based access with scope granularity and refresh support.
To use:

* Run `init_oauth.py` once to authorize the app
* The token is saved locally and refreshed automatically by `token_manager.py`

> ⚠️ Cisco DevNet limits you to **10 apps** — OAuth is best for long-lived scripts.

---

## 📆 Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Create env.py from template
cp env.template.py env.py
```

### Edit `env.py`:

```python
# If using API Key
MERAKI_API_KEY = "your_api_key_here"
MERAKI_ORG_ID = "your_org_id"

# If using OAuth
MERAKI_CLIENT_ID = "..."
MERAKI_CLIENT_SECRET = "..."
MERAKI_REDIRECT_URI = "http://localhost:8080/callback"
MERAKI_REFRESH_TOKEN_PATH = "tokens/refresh_token.json"
```

---

## 📄 Running the Script

```bash
# Optional (OAuth only, first run)
python init_oauth.py

# Apply ACL updates
python updateACL.py
```

---

## 📁 File Structure

```
🔹 updateACL.py          # Main logic
🔹 init_oauth.py         # Interactive login flow
🔹 token_manager.py      # Handles OAuth token refresh
🔹 blocked_ips.csv       # List of destination IPs
🔹 env.py                # Secrets and org ID
🔹 tokens/               # Stores refresh_token.json
```

---

## 🔐 Security Tips

* Never check secrets or tokens into Git
* Always `.gitignore` your `env.py` and `tokens/`
* Use API keys for short-lived or low-risk work only

---

## 📄 License

Copyright (c) Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample Code License:
[https://github.com/CiscoSE/cisco-sample-code/blob/master/LICENSE](https://github.com/CiscoSE/cisco-sample-code/blob/master/LICENSE)

You may use, copy, modify, and create derivative works of the Sample Code, subject to the terms of the License.
This software is provided "as is" and Cisco disclaims all warranties.

---

## 🤝 Contributing / Questions

This script is maintained for demo and PoC purposes only.
Issues and pull requests are welcome, but not guaranteed to be merged.

For questions, reach out to your Cisco account team or SE.
