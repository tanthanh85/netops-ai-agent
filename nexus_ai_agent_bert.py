
import time
import socket
import threading
import schedule
import requests
from datetime import datetime
from netmiko import ConnectHandler
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F
# import json
import pickle
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import os

# ========== Load Environment Variables ==========
load_dotenv()
SPLUNK_HEC_URL = os.getenv("splunk_url")
SPLUNK_HEC_TOKEN = os.getenv("splunk_token")

# ========== Nexus Switch Info ==========
switch = {
    'device_type': 'cisco_nxos',
    'host': '192.168.50.112',
    'username': os.getenv('sw_username'),
    'password': os.getenv('sw_password'),
}
agent_id = f"nexus-{switch['host'].replace('.', '-')}"


import math

def clean_json(obj):
    if isinstance(obj, dict):
        return {k: clean_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_json(v) for v in obj]
    elif isinstance(obj, float):
        if math.isinf(obj) or math.isnan(obj):
            return 0.0
        return obj
    else:
        return obj

# ========== Model Directories ==========
model_dir = "./nexus_ai_model_bert"
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased", local_files_only=True)
severity_model = AutoModelForSequenceClassification.from_pretrained(f"{model_dir}/severity_model", local_files_only=True)
show_model = AutoModelForSequenceClassification.from_pretrained(f"{model_dir}/show_cmd_model", local_files_only=True)
debug_model = AutoModelForSequenceClassification.from_pretrained(f"{model_dir}/debug_cmd_model", local_files_only=True)

# ========== Load Encoders ==========
with open(f"{model_dir}/severity_encoder.pkl", "rb") as f:
    severity_encoder = pickle.load(f)
with open(f"{model_dir}/show_cmd_encoder.pkl", "rb") as f:
    show_encoder = pickle.load(f)
with open(f"{model_dir}/debug_cmd_encoder.pkl", "rb") as f:
    debug_encoder = pickle.load(f)

# ========== Inference Function ==========
def predict(message, model, encoder):
    inputs = tokenizer(message, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = F.softmax(outputs.logits, dim=1)
        label_id = torch.argmax(probs, dim=1).item()
        confidence = torch.max(probs).item()
        label = encoder.inverse_transform([label_id])[0]
        return label, confidence



# ========== Handle Syslog ==========
def handle_syslog(data):
    timestamp = datetime.utcnow().isoformat()
    message = data.decode(errors="ignore").strip()

    severity, confidence = predict(message, severity_model, severity_encoder)
    print(f"[Syslog] {message} --> Severity: {severity} (Confidence: {confidence:.2f})")

    if severity == "Info":
        print("[AI Agent] Message is informational. Ignored.")
        return

    show_cmd, _ = predict(message, show_model, show_encoder)
    debug_cmd, _ = predict(message, debug_model, debug_encoder)

    #show_cmd = str(show_cmd)
    print("show commands to issue: " + str(show_cmd))
    
    #debug_cmd = str(debug_cmd)
    print("debug commands to issue: " + str(debug_cmd))
    # Collect debug logs
    # try:
    #     conn = ConnectHandler(**switch)
    #     debug_logs = conn.send_command("show logging last 200")
    # except Exception as e:
    #     debug_logs = f"Failed to collect debug logs: {str(e)}"
    collected_debug_data = {}
    collected_show_data = {}
    try:
        conn = ConnectHandler(**switch)
        
        show_cmd = str(show_cmd)
        for cmd in show_cmd.split(","):
            cmd = cmd.strip()
            cmd = str(cmd).strip()
            if cmd:
                collected_show_data[cmd] = conn.send_command(cmd)

        
        debug_cmd = str(debug_cmd)
        for cmd in debug_cmd.split(","):
            cmd = cmd.strip()
            cmd = str(cmd).strip()
            if cmd:
                conn.send_command("terminal monitor")
                conn.send_command("debug {}{}".format("" if cmd.startswith("debug") else "", cmd))
                time.sleep(60)  # wait for logs to accumulate
                conn.send_command("undebug all")
                collected_debug_data[cmd] = conn.send_command("show logging last 200")
        conn.disconnect()
        collected_output = {
            "show_outputs": collected_show_data,
            "debug_logs": collected_debug_data
        }
        # print(collected_output)
    except Exception as e:
        collected_output = {"error": str(e)}
        print(collected_output)
    
    payload = {
        "host": agent_id,
        "sourcetype": "otel:switch:agent",
        "source": "http:AINetwork",
        "time": time.time(),
        "event": {
            "resource": {
                "attributes": {
                    "host.name": agent_id,
                    "service.name": "switch-ai-agent"
                }
            },
            "scope": {
                "name": "nexus_event_agent",
                "version": "1.0.0"
            },
            "logs": [
                {
                    "time_unix_nano": int(time.time() * 1e9),
                    "severity_text": severity,
                    "body": message,
                    "attributes": {
                        "agent_id": agent_id,
                        "severity": severity,
                        "confidence": round(confidence, 4),
                        "message": message,
                        "show_cmds": show_cmd,
                        "debug_cmds": debug_cmd,
                        "collected_output": {
                            "show_outputs": collected_show_data,
                            "debug_logs": collected_debug_data
                        },
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            ]
        }
    }

    send_to_splunk(payload)

def send_to_splunk(payload):
    
    print("\n\n")
    print("\n\n")


    #print(json.dumps(payload, indent=2))

    print("\n\n")
    print('Sending data to Splunk now...')
    print("\n\n")
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
    try:
        response=requests.post(SPLUNK_HEC_URL, json=clean_json(payload), headers=headers, timeout=5,verify=False)
        #print("Status code"+response.status_code)
        print(response.status_code)
        if response.status_code==200:
            print(f"Sent to Splunk successfully!")
    except Exception as e:
        print(f"Splunk send error: {e}")



def syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 612))
    print("[Switch Agent] Listening on UDP port 612 for syslog...")
    while True:
        data, _ = sock.recvfrom(4096)
        handle_syslog(data)

# ========== Main ==========
if __name__ == "__main__":
    syslog_thread = threading.Thread(target=syslog_listener, daemon=True)
    syslog_thread.start()
    while True:
        schedule.run_pending()
        time.sleep(1)
