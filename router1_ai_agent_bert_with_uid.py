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
import json
import pickle
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import os


import hashlib

#==========generate unique event id================
def generate_event_uid(event_data: dict, agent_id: str = None) -> str:
    try:
        if not agent_id:
            agent_id = socket.gethostbyname(socket.gethostname())
        timestamp = int(time.time() * 1000)
        content_str = json.dumps(event_data, sort_keys=True)
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:8]
        return f"{agent_id}-{timestamp}-{content_hash}"
    except Exception as e:
        return f"unknown-{int(time.time() * 1000)}"

# ========== Post-Classification Fallback Rules ==========
def apply_fallback_rules(message, predicted_severity):
    msg = message.lower()

    # BGP-related escalation
    if "bgp" in msg and any(keyword in msg for keyword in ["down", "reset", "notification", "hold time expired"]):
        return "Critical"

    # CPU usage escalation
    if "cpu" in msg:
        try:
            cpu_val = int([s for s in msg.split() if s.isdigit()][0])
            if cpu_val >= 90:
                return "Critical"
            elif cpu_val >= 80:
                return "Warning"
        except:
            pass

    # Memory usage escalation
    if "memory" in msg:
        try:
            mem_val = int([s for s in msg.split() if s.isdigit()][0])
            if mem_val >= 90:
                return "Critical"
            elif mem_val >= 80:
                return "Warning"
        except:
            pass

    return predicted_severity

# ========== Splunk Config ==========
SPLUNK_HEC_URL = "https://192.168.50.18:8088/services/collector/event"
SPLUNK_HEC_TOKEN = os.getenv("splunk_token")

# ========== Router Info ==========
router = {
    'device_type': 'cisco_ios',
    'host': '192.168.50.101',
    'username': os.getenv('username'),
    'password': os.getenv('password'),
    'secret': 'cisco123'
}
agent_id = f"router-{router['host'].replace('.', '-')}"
model_dir = "./router_ai_model_bert"
recent_events = {}

# ========== Load AI Models ==========
tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
severity_model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True).to("cpu").eval()
show_model = AutoModelForSequenceClassification.from_pretrained(f"{model_dir}/show_cmd_model", local_files_only=True).to("cpu").eval()
debug_model = AutoModelForSequenceClassification.from_pretrained(f"{model_dir}/debug_cmd_model", local_files_only=True).to("cpu").eval()

with open(f"{model_dir}/show_cmd_encoder.pkl", "rb") as f:
    show_cmd_encoder = pickle.load(f)
with open(f"{model_dir}/debug_cmd_encoder.pkl", "rb") as f:
    debug_cmd_encoder = pickle.load(f)

severity_labels = ["Critical", "Warning", "Info", "Noise"]

# ========== AI Prediction Functions ==========
def predict_severity(message):
    inputs = tokenizer(message, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
    with torch.no_grad():
        logits = severity_model(**inputs).logits
        probs = F.softmax(logits, dim=-1)
        predicted = torch.argmax(probs, dim=-1).item()
        confidence = probs[0][predicted].item()
    predicted_label = apply_fallback_rules(message, severity_labels[predicted])
    return predicted_label, confidence

def predict_show_debug_cmds(message):
    inputs = tokenizer(message, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
    with torch.no_grad():
        show_logits = show_model(**inputs).logits
        debug_logits = debug_model(**inputs).logits
        show_idx = torch.argmax(show_logits, dim=-1).item()
        debug_idx = torch.argmax(debug_logits, dim=-1).item()
    return show_cmd_encoder.inverse_transform([show_idx])[0], debug_cmd_encoder.inverse_transform([debug_idx])[0]

# ========== Router Collector ==========
def collect_router_data(show_cmds, debug_cmds):
    conn = ConnectHandler(**router)
    conn.enable()
    conn.send_command_timing("terminal length 0")

    # Start debug commands
    for dbg in debug_cmds.split(","):
        conn.send_command_timing(dbg.strip())
    time.sleep(60)
    debug_output = conn.send_command("show logging last 100")
    conn.send_command_timing("undebug all")

    # Show command outputs with clear separation
    show_outputs = {}
    for cmd in show_cmds.split(","):
        cmd = cmd.strip()
        try:
            result = conn.send_command(cmd, use_textfsm=True)
            if not result:
                result = conn.send_command(cmd)
        except Exception:
            result = conn.send_command(cmd)
        show_outputs[cmd] = result

    # Compare with golden config
    running_config = conn.send_command("show running-config")
    golden_config = conn.send_command("more flash:golden_config")
    config_changed = running_config.strip() != golden_config.strip()
    config_diff = [line for line in running_config.splitlines() if line not in golden_config.splitlines()]
    conn.disconnect()

    return show_outputs, debug_output, config_changed, config_diff[:50]

# ========== Payload Builder ==========
def build_otel_payload(message, severity, confidence, show_data, debug_output, show_cmds, debug_cmds, config_changed, config_diff):
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "host": agent_id,
        "sourcetype": "otel:router:agent",
        "time": time.time(),
        "event": {
            "resource": {
                "attributes": {
                    "host.name": agent_id,
                    "service.name": "router-ai-agent"
                }
            },
            "scope": {
                "name": "router_agent_otel",
                "version": "1.0.1"
            },
            "logs": [
                {
                    "time_unix_nano": int(time.time() * 1e9),
                    "severity_text": severity,
                    "body": message,
                    "attributes": {
                        "router_id": agent_id,
                        "severity": severity,
                        "confidence": round(confidence, 2),
                        "message": message,
                        "show_cmds": show_cmds,
                        "debug_cmds": debug_cmds,
                        "collected_show_data": show_data,
                        "debug_log_raw": debug_output[:200000],
                        "config_changed": config_changed,
                        "config_diff": config_diff,
                        "timestamp": now
                    }
                }
            ]
        }
    }

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

# ========== Main Event Handler ==========
def process_syslog(message):
    try:
        now = time.time()
        if message in recent_events and now - recent_events[message] < 60:
            print("[!] Duplicate syslog within 1 minute, skipping:", message)
            return
        recent_events[message] = now

        # Force critical severity for known issues
        if "%OSPF-4-DUP_RTRID_NBR" in message or "%OSPF-4-DUPRID" in message:
            severity = "Critical"
            confidence = 1.0
            print(f"[Syslog] {message}  --> Forced Severity: {severity} (Confidence: {confidence:.2f})")
        else:
            severity, confidence = predict_severity(message)
            print(f"[Syslog] {message}  --> Severity: {severity} (Confidence: {confidence:.2f})")

        if severity == "Critical":
            show_cmds, debug_cmds = predict_show_debug_cmds(message)
            show_data, debug_output, config_changed, config_diff = collect_router_data(show_cmds, debug_cmds)
            payload = build_otel_payload(message, severity, confidence, show_data, debug_output, show_cmds, debug_cmds, config_changed, config_diff)
            payload["event"]["event_uid"] = generate_event_uid(payload["event"])
            send_to_splunk(payload)
        else:
            print("[AI Agent] Message is non critical/info. Ignored.")
    except Exception as e:
        print("[!] Error handling syslog:", e)

# ========== Syslog Server ==========
def syslog_server(host="0.0.0.0", port=514):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        print(f"[+] Syslog server listening on {host}:{port}")
    except PermissionError:
        print("[!] Permission denied. Use sudo or change port >1024.")
        return

    executor = ThreadPoolExecutor(max_workers=4)
    while True:
        data, addr = sock.recvfrom(4096)
        message = data.decode(errors='ignore').strip()
        executor.submit(process_syslog, message)

# ========== Main ==========
if __name__ == "__main__":
    print("Router AI Agent is running...")
    threading.Thread(target=syslog_server, daemon=True).start()
    while True:
        schedule.run_pending()
        time.sleep(1)



