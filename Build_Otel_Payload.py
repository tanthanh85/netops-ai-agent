
from Gen_Unique_Event_Id import generate_event_id
from datetime import datetime,timezone
from time import time


# ========== Payload Builder ==========
def build_otel_payload(message, severity, confidence, show_data, debug_output, show_cmds, debug_cmds, config_changed, config_diff,agent_id):
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    event_id=generate_event_id(agent_id,now,message)

    return {
        "host": agent_id,
       "event_id": event_id,
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
                "name": "router_ai_agent",
                "version": "1.0.1"
            },
            "logs": [
                {
                    "time_unix_nano": int(time.time() * 1e9),
                    "severity": severity,
                    "original syslog message": message,
                    "attributes": {
                        "router_id": agent_id,
                        "severity": severity,
                        "confidence": round(confidence, 2),
                        "collected_show_data": {
                            "show commands": show_cmds,
                            "show_outputs": show_data
                        },
                        "collected_debug_data": {
                            "debug commands": debug_cmds,
                            "debug data": debug_output
                        },
                        "config_changed?": config_changed,
                        "config_diff": config_diff,
                        "timestamp": now
                    }
                }
            ]
        }
    }