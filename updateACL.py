import os
import json
import csv
from meraki import DashboardAPI
from env import MERAKI_API_KEY, MERAKI_ORG_ID

# === CONFIGURABLE ===
SOURCE_CIDR = "192.160.0.0/16"
CSV_PATH = "blocked_ips.csv"

# === Load Dashboard ===
dashboard = DashboardAPI(api_key=MERAKI_API_KEY)

def load_blocked_ips(csv_path):
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return [row['IPAddress'] for row in reader if 'IPAddress' in row]

def get_current_fabric_acl(org_id):
    rules = dashboard.appliance.getOrganizationApplianceVpnVpnFirewallRules(org_id)
    print("\nCurrent Fabric ACL:\n", json.dumps(rules, indent=2))
    return rules['rules']

def rule_matches_all_ips(rule, ip_list):
    # Strip spaces, handle comma separation, compare as sets
    dest_ips = set(ip.strip() for ip in rule['destinationCidr'].split(','))
    return set(ip_list).issubset(dest_ips)

def any_ip_matches_rule(rule, ip_list):
    dest_ips = set(ip.strip() for ip in rule['destinationCidr'].split(','))
    return bool(set(ip_list) & dest_ips)

def find_matching_rule(rules, ip_list):
    for rule in rules:
        if rule_matches_all_ips(rule, ip_list):
            return rule
    return None

def find_partial_matches(rules, ip_list):
    return [rule for rule in rules if any_ip_matches_rule(rule, ip_list)]

def create_new_rule(ip_list):
    return {
        "comment": "Auto-generated block for pin pads",
        "policy": "deny",
        "protocol": "any",
        "srcCidr": SOURCE_CIDR,
        "destCidr": ",".join(ip_list),
        "srcPort": "any",
        "destPort": "any",
        "syslogEnabled": False
    }

def update_acl_with_new_rule(org_id, rules, new_rule):
    updated_rules = rules + [new_rule]
    result = dashboard.appliance.updateOrganizationApplianceVpnVpnFirewallRules(org_id, rules=updated_rules)
    print("\nUpdated Fabric ACL successfully.")
    return result

def main():
    ip_list = load_blocked_ips(CSV_PATH)
    current_rules = get_current_fabric_acl(MERAKI_ORG_ID)

    match = find_matching_rule(current_rules, ip_list)
    if match:
        print("\n✅ A matching deny rule already exists:\n", json.dumps(match, indent=2))
    else:
        print("\n⚠️ No rule exactly matches the full IP list.")
        partials = find_partial_matches(current_rules, ip_list)
        if partials:
            print("\nSome rules match **some** IPs in your list:")
            for rule in partials:
                print(json.dumps(rule, indent=2))

        confirm = input("\nWould you like to create a new deny rule for these IPs? (y/n): ").strip().lower()
        if confirm == 'y':
            new_rule = create_new_rule(ip_list)
            update_acl_with_new_rule(MERAKI_ORG_ID, current_rules, new_rule)
        else:
            print("No changes made.")

if __name__ == "__main__":
    main()
