import os
import json
import csv
import ipaddress
import logging
from meraki import DashboardAPI
from env import MERAKI_API_KEY, MERAKI_ORG_ID

# === CONFIGURABLE ===
SOURCE_CIDR = "192.168.0.0/16"
CSV_PATH = "blocked_ips.csv"
LOG_FILE = "update_acl.log"

# === Setup Logging ===
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# === Load Dashboard ===
dashboard = DashboardAPI(api_key=MERAKI_API_KEY)

def load_blocked_ips(csv_path):
    with open(csv_path, newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames
        logging.debug("Detected CSV headers: %s", fieldnames)

        if not fieldnames or not any(field.strip().lower() == 'ipaddress' for field in fieldnames):
            raise ValueError("❌ 'IPAddress' column not found in CSV header.")

        return [row['IPAddress'].strip() for row in reader if row.get('IPAddress') and row['IPAddress'].strip()]

def get_current_fabric_acl(org_id):
    rules = dashboard.appliance.getOrganizationApplianceVpnVpnFirewallRules(org_id)
    print("\nCurrent Fabric ACL:\n", json.dumps(rules, indent=2))
    logging.info("Current Fabric ACL: %s", json.dumps(rules, indent=2))
    return rules['rules']

def rule_fully_matches(rule, ip_list, src_cidr, policy="deny", protocol="any", src_port="any", dest_port="any"):
    if rule.get('policy', '').lower() != policy:
        return False
    if rule.get('protocol', '').lower() != protocol:
        return False
    if rule.get('srcCidr', '').lower() != src_cidr.lower():
        return False
    if rule.get('srcPort', '').lower() != src_port.lower():
        return False
    if rule.get('destPort', '').lower() != dest_port.lower():
        return False

    try:
        rule_dest_networks = {ipaddress.ip_network(cidr.strip()) for cidr in rule['destCidr'].split(',')}
        target_networks = {ipaddress.ip_network(ip.strip(), strict=False) for ip in ip_list}
    except ValueError:
        return False

    return rule_dest_networks == target_networks


def get_partial_rule_matches(rules, ip_list, src_cidr, policy="deny", protocol="any", src_port="any", dest_port="any"):
    matches = []

    for index, rule in enumerate(rules):
        result = {
            "index": index,
            "rule": rule,
            "ip_matches": [],
            "field_matches": {
                "policy": rule.get('policy', '').lower() == policy,
                "protocol": rule.get('protocol', '').lower() == protocol,
                "srcCidr": rule.get('srcCidr', '').lower() == src_cidr.lower(),
                "srcPort": rule.get('srcPort', '').lower() == src_port.lower(),
                "destPort": rule.get('destPort', '').lower() == dest_port.lower()
            }
        }

        try:
            rule_dest_networks = [ipaddress.ip_network(cidr.strip()) for cidr in rule['destCidr'].split(',')]
            for ip in ip_list:
                ip_obj = ipaddress.ip_network(ip.strip(), strict=False)
                for net in rule_dest_networks:
                    if ip_obj.subnet_of(net) or ip_obj.network_address in net:
                        result["ip_matches"].append(str(ip_obj))
                        break
        except ValueError:
            continue

        if result["ip_matches"]:
            matches.append(result)

    return matches

def create_new_rule(ip_list):
    valid_ips = []
    for ip in ip_list:
        try:
            ip_obj = ipaddress.ip_network(ip.strip(), strict=False)
            valid_ips.append(str(ip_obj))
        except ValueError:
            print(f"⚠️ Skipping invalid IP: {ip.strip()}")
            logging.warning("Skipping invalid IP: %s", ip.strip())

    if not valid_ips:
        raise ValueError("❌ No valid IPs to add in destCidr.")

    new_rule = {
        "comment": "Auto-generated block for pin pads",
        "policy": "deny",
        "protocol": "any",
        "srcCidr": SOURCE_CIDR,
        "destCidr": ",".join(valid_ips),
        "srcPort": "any",
        "destPort": "any",
        "syslogEnabled": False
    }

    logging.info("Prepared new rule: %s", json.dumps(new_rule, indent=2))
    return new_rule

def update_acl_with_new_rule(org_id, rules, new_rule, position='top', insert_before_comment=None):
    if position == 'top':
        updated_rules = [new_rule] + rules
    elif position == 'bottom':
        updated_rules = rules + [new_rule]
    elif position == 'before' and insert_before_comment:
        index = next((i for i, r in enumerate(rules) if r.get('comment') == insert_before_comment), len(rules))
        updated_rules = rules[:index] + [new_rule] + rules[index:]
    else:
        updated_rules = rules + [new_rule]
    logging.info("Submitting updated ruleset with %d rules", len(updated_rules))
    logging.info("Full ruleset being submitted: %s", json.dumps(updated_rules, indent=2))
    result = dashboard.appliance.updateOrganizationApplianceVpnVpnFirewallRules(org_id, rules=updated_rules)
    print("\nUpdated Fabric ACL successfully.")
    logging.info("ACL update response: %s", json.dumps(result, indent=2))
    return result

def main():
    try:
        ip_list = load_blocked_ips(CSV_PATH)
        logging.info("Loaded %d IPs from CSV: %s", len(ip_list), ip_list)
        print(f"\n🧾 IPs to block: {ip_list}")
    except Exception as e:
        print(f"Error loading blocked IPs: {e}")
        logging.error("Error loading blocked IPs: %s", str(e))
        return

    current_rules = get_current_fabric_acl(MERAKI_ORG_ID)

    match_found = False
    for rule in current_rules:
        if rule_fully_matches(rule, ip_list, SOURCE_CIDR):
            print("\n✅ A matching deny rule already exists:\n", json.dumps(rule, indent=2))
            logging.info("Matching rule found: %s", json.dumps(rule, indent=2))
            match_found = True
            break

    if not match_found:
        print("\n⚠️ No rule exactly matches the full IP list.")
        partials = get_partial_rule_matches(current_rules, ip_list, SOURCE_CIDR)
        if partials:
            print("\n🔍 Found overlapping rules (not full matches):\n")
            for match in partials:
                print(f"🔢 Rule #{match['index']} – Comment: {match['rule'].get('comment', '')}")
                print(f"🧩 Matching IPs: {', '.join(match['ip_matches'])}")
                print("🧪 Field matches:")
                for field, is_match in match["field_matches"].items():
                    print(f"    - {field}: {'✅' if is_match else '❌'}")
                print(f"🧾 Rule content: {json.dumps(match['rule'], indent=2)}\n")
                logging.info("Partial match found at index %d: %s", match['index'], json.dumps(match['rule'], indent=2))
        else:
            print("\nℹ️ No partial matches found in current rules.\n")
            logging.info("No partial matches found.")

        confirm = input("\nWould you like to create a new deny rule for these IPs? (y/n): ").strip().lower()
        if confirm == 'y':
            try:
                new_rule = create_new_rule(ip_list)
                print("\nCurrent rules:")
                for idx, rule in enumerate(current_rules):
                    print(f"  {idx}: {rule.get('comment', '<no comment>')}")
                position = input("\nWhere should the new rule be inserted? (top/bottom/before): ").strip().lower()
                if position == 'before':
                    try:
                        rule_index = int(input("Enter the rule number to insert before (as shown above): ").strip())
                        if 0 <= rule_index < len(current_rules):
                            comment = current_rules[rule_index].get('comment', '')
                            update_acl_with_new_rule(MERAKI_ORG_ID, current_rules, new_rule, position=position, insert_before_comment=comment)
                        else:
                            print("Invalid rule number. Defaulting to bottom.")
                            update_acl_with_new_rule(MERAKI_ORG_ID, current_rules, new_rule, position='bottom')
                    except ValueError:
                        print("Invalid input. Defaulting to bottom.")
                        update_acl_with_new_rule(MERAKI_ORG_ID, current_rules, new_rule, position='bottom')
                elif position in ['top', 'bottom']:
                    update_acl_with_new_rule(MERAKI_ORG_ID, current_rules, new_rule, position=position)
                else:
                    print("Invalid position. Defaulting to bottom.")
                    update_acl_with_new_rule(MERAKI_ORG_ID, current_rules, new_rule, position='bottom')
            except ValueError as ve:
                print(str(ve))
                logging.error("Failed to create rule: %s", str(ve))
        else:
            print("No changes made.")
            logging.info("User declined to make changes.")

if __name__ == "__main__":
    main()
