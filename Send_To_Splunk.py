
import os
import requests

# ========== Splunk Config ==========
SPLUNK_HEC_URL = os.getenv("splunk_url")
SPLUNK_HEC_TOKEN = os.getenv("splunk_token")

# ========== Send event to Splunk ==========
def send_to_splunk(payload):
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(SPLUNK_HEC_URL, headers=headers, data=json.dumps(payload), verify=False)
        print("[+] Sent to Splunk. Status:", response.status_code)
    except Exception as e:
        print("[!] Failed to send to Splunk:", e)