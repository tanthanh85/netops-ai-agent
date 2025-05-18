
from flask import Flask, request, jsonify
from datetime import datetime
import json

app = Flask(__name__)

def print_section(title, data):
    print(f"\n{'='*10} {title} {'='*10}")
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                print(f"{key}:")
                print(json.dumps(value, indent=4))
            else:
                print(f"{key}: {value}")
    elif isinstance(data, list):
        for item in data:
            print(json.dumps(item, indent=4))
    else:
        print(data)

@app.route("/alert", methods=["POST"])
def receive_alert():
    alert = request.get_json()
    print(f"\n{'#'*80}")
    print(f"[ALERT RECEIVED @ {datetime.utcnow().isoformat()}]")
    print(f"{'-'*80}")
    print(f"Router ID : {alert.get('router_id')}")
    print(f"Severity  : {alert.get('event_type')}")
    print(f"Message   : {alert.get('message')}")
    print(f"Diagnosis : {alert.get('diagnosis')}")
    print(f"Suggestion: {alert.get('suggestion')}")
    print(f"Timestamp : {alert.get('timestamp')}")

    ospf = alert.get("ospf_info", {})
    conn = alert.get("connectivity", {})

    if ospf:
        print_section("OSPF Parsed", ospf.get("parsed", {}))
        print_section("OSPF Raw Interfaces", ospf.get("raw", {}).get("interfaces", ""))
        print_section("OSPF Raw Neighbors", ospf.get("raw", {}).get("neighbors", ""))
        print_section("OSPF Raw Config", ospf.get("raw", {}).get("config", ""))

    if conn:
        print_section("CDP Parsed", conn.get("parsed", {}).get("cdp", []))
        print_section("LLDP Parsed", conn.get("parsed", {}).get("lldp", []))
        print_section("CDP Raw", conn.get("raw", {}).get("cdp", ""))
        print_section("LLDP Raw", conn.get("raw", {}).get("lldp", ""))

    print(f"{'#'*80}\n")
    return jsonify({"status": "received"}), 200

if __name__ == "__main__":
    print("[*] Simple Master Agent is running on port 8000...")
    app.run(host="0.0.0.0", port=8000)
