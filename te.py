import requests
import json
import time
from dotenv import load_dotenv
import os

# === LOAD ENV VARIABLES ===
load_dotenv()

THOUSANDEYES_API_TOKEN = os.getenv("te_token")
TEST_ID = os.getenv("te_test_id")
SPLUNK_HEC_URL = os.getenv("splunk_url")
SPLUNK_TOKEN = os.getenv("te_splunk_token")

# === HEADERS ===
TE_HEADERS = {
    "Authorization": f"Bearer {THOUSANDEYES_API_TOKEN}"
}
SPLUNK_HEADERS = {
    "Authorization": f"Splunk {SPLUNK_TOKEN}",
    "Content-Type": "application/json"
}

def fetch_test_metadata(test_id):
    url = f"https://api.thousandeyes.com/v7/tests/agent-to-agent/{test_id}"
    resp = requests.get(url, headers=TE_HEADERS)
    resp.raise_for_status()
    return resp.json()

def fetch_results(urls):
    results = {}
    for result in urls:
        name = result["href"].split("/")[-1]  # 'network', 'path-vis', 'bgp', etc.
        resp = requests.get(result["href"], headers=TE_HEADERS)
        resp.raise_for_status()
        results[name] = resp.json()
    return results

def send_to_splunk(full_payload):
    event = {
        "event": full_payload,
        "sourcetype": "thousandeyes:a2a_test",
        "source": "thousandeyes",
        "index": "te"
    }

    resp = requests.post(SPLUNK_HEC_URL, headers=SPLUNK_HEADERS, data=json.dumps(event), verify=False)
    resp.raise_for_status()
    print("✅ Event sent to Splunk")

def main_loop():
    while True:
        try:
            metadata = fetch_test_metadata(TEST_ID)
            result_links = metadata.get("_links", {}).get("testResults", [])
            all_results = fetch_results(result_links)

            # COMBINE EVERYTHING INTO ONE STRUCTURE
            full_payload = {
                "metadata": metadata,
                "results": all_results
            }

            send_to_splunk(full_payload)

        except Exception as e:
            print(f"❌ Error: {e}")
        time.sleep(60)

if __name__ == "__main__":
    main_loop()
