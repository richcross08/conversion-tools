import pandas as pd
import json
import ipaddress

def load_policies(json_file):
    """Load and flatten policy JSON"""
    with open(json_file, "r") as f:
        data = json.load(f)

    policies = []
    for entry in data[0][0].values():
        for policy in entry:
            policies.append(policy)
    return policies

def ip_in_list(ip, ip_list):
    """Check if an IP matches any in a list of IPs or CIDRs"""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for net in ip_list:
        try:
            if "/" in net:  # subnet
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            else:  # single IP
                if ip == net:
                    return True
        except ValueError:
            continue
    return False

def service_matches(protocol, port, service_list):
    """Check if <protocol>_<port> matches a policy's service definition"""
    proto_map = {"6": "tcp", "17": "udp"}  # Common IP protocol numbers
    proto_name = proto_map.get(str(protocol), None)

    if proto_name is None:
        return False

    candidate = f"{proto_name}_{port}"

    for service in service_list:
        if service == candidate:
            return True
        elif service in ("any", "application-default"):
            return True
    return False

def match_policies_to_logs(csv_file, json_file, output_file=None):
    # Columns we care about
    selected_columns = [
        "Generate Time",
        "Source address",
        "Destination address",
        "IP Protocol",
        "Destination Port"
    ]

    df = pd.read_csv(csv_file)
    df = df[selected_columns]

    policies = load_policies(json_file)

    matches = []
    for _, row in df.iterrows():
        src = row["Source address"]
        dst = row["Destination address"]
        proto = row["IP Protocol"]
        dport = row["Destination Port"]

        matching_policies = []
        for policy in policies:
            if ip_in_list(src, policy["source"]) and \
               ip_in_list(dst, policy["destination"]) and \
               service_matches(proto, dport, policy["service"]):
                matching_policies.append(policy["name"])

        matches.append(", ".join(matching_policies) if matching_policies else "NO MATCH")

    df["Matched Policies"] = matches

    if output_file:
        df.to_csv(output_file, index=False)
        print(f"Results saved to {output_file}")
    else:
        return df

# Example usage
if __name__ == "__main__":
    log_file = "logs/log.csv"
    policy_file = "policy/tmc-policies.json"   # save your JSON here
    output = "log_with_policies.csv"

    result = match_policies_to_logs(log_file, policy_file, output)
