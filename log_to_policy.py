import pandas as pd
import json
import ipaddress

def load_policies(json_file):
    """Load and flatten policy JSON"""
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise ValueError(f"Error loading policy file {json_file}: {e}")

    policies = []
    try:
        for entry in data[0][0].values():
            for policy in entry:
                # Ensure required fields exist
                if all(key in policy for key in ["name", "source", "destination", "service"]):
                    policies.append(policy)
                else:
                    print(f"Warning: Skipping policy with missing fields: {policy.get('name', 'unnamed')}")
    except (IndexError, KeyError, TypeError) as e:
        raise ValueError(f"Error parsing policy structure: {e}")
        
    if not policies:
        raise ValueError("No valid policies found in JSON file")
        
    return policies

def ip_in_list(ip, ip_list):
    """Check if an IP matches any in a list of IPs or CIDRs"""
    if not ip or not ip_list:
        return False
        
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return False

    for net in ip_list:
        if not net:  # Skip empty entries
            continue
            
        try:
            net = net.strip()
            if "/" in net:  # subnet
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            else:  # single IP
                if ip_obj == ipaddress.ip_address(net):
                    return True
        except (ValueError, AttributeError):
            continue
    return False

def service_matches(protocol, port, service_list):
    """Check if <protocol>_<port> matches a policy's service definition"""
    # Handle both string protocols (from logs) and numeric protocols
    if isinstance(protocol, str):
        proto_name = protocol.lower()
    else:
        proto_map = {"6": "tcp", "17": "udp"}  # Common IP protocol numbers
        proto_name = proto_map.get(str(protocol), None)

    if proto_name is None:
        return False

    candidate = f"{proto_name}_{port}"
    port_num = int(port)
    
    # Common named service mappings
    named_service_map = {
        "service-http": [("tcp", 80)],
        "service-https": [("tcp", 443)],
        "service-dns": [("tcp", 53), ("udp", 53)],
        "service-ftp": [("tcp", 21)],
        "service-ssh": [("tcp", 22)],
        "service-telnet": [("tcp", 23)],
        "service-smtp": [("tcp", 25)],
        "service-dhcp": [("udp", 67), ("udp", 68)],
    }

    for service in service_list:
        if service == candidate:
            return True
        elif service in ("any", "application-default"):
            return True
        # Handle service ranges like "tcp_1050-1081"
        elif service.startswith(f"{proto_name}_") and "-" in service:
            try:
                range_part = service.split("_", 1)[1]
                if "-" in range_part:
                    start_port, end_port = map(int, range_part.split("-"))
                    if start_port <= port_num <= end_port:
                        return True
            except (ValueError, IndexError):
                continue
        # Handle named services
        elif service in named_service_map:
            for svc_proto, svc_port in named_service_map[service]:
                if svc_proto == proto_name and svc_port == port_num:
                    return True
    return False

def match_policies_to_logs(csv_file, json_file, output_file=None, debug=False):
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
    
    if debug:
        print(f"Loaded {len(policies)} policies")
        print(f"Processing {len(df)} log entries")

    matches = []
    for idx, row in df.iterrows():
        src = row["Source address"]
        dst = row["Destination address"]
        proto = row["IP Protocol"]
        dport = row["Destination Port"]

        if debug and idx < 3:  # Debug first few entries
            print(f"\n--- Log entry {idx+1} ---")
            print(f"Source: {src}, Dest: {dst}, Protocol: {proto}, Port: {dport}")

        matching_policies = []
        policy_check_count = 0
        
        for policy in policies:
            policy_check_count += 1
            src_match = ip_in_list(src, policy["source"])
            dst_match = ip_in_list(dst, policy["destination"])
            svc_match = service_matches(proto, dport, policy["service"])
            
            if debug and idx < 3 and policy_check_count <= 5:  # Debug first few policies for first few entries
                print(f"  Policy '{policy['name']}': src={src_match}, dst={dst_match}, svc={svc_match}")
                print(f"    Source IPs: {policy['source'][:3]}{'...' if len(policy['source']) > 3 else ''}")
                print(f"    Dest IPs: {policy['destination'][:3]}{'...' if len(policy['destination']) > 3 else ''}")
                print(f"    Services: {policy['service']}")
            
            if src_match and dst_match and svc_match:
                matching_policies.append(policy["name"])
                if debug and idx < 3:
                    print(f"  *** MATCH: {policy['name']} ***")

        matches.append(", ".join(matching_policies) if matching_policies else "NO MATCH")
        
        if debug and idx < 3:
            print(f"Final result: {matches[-1]}")

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

    result = match_policies_to_logs(log_file, policy_file, output, debug=False)
