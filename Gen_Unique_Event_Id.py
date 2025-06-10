import uuid
import hashlib
from datetime import datetime,timezone

def generate_event_id(agent_hostname: str, event_timestamp: str, syslog_text: str) -> str:
    """
    Generate a unique ID for each event coming from a router agent.
    
    Parameters:
    - agent_hostname: unique hostname or router ID (e.g., "R1")
    - event_timestamp: ISO format or raw string timestamp of the event (e.g., "2025-06-09T16:30:15Z")
    - syslog_text: raw syslog message from the router
    
    Returns:
    - UUIDv5 string unique per agent + event instance
    """
    # Combine into a unique string
    unique_string = f"{agent_hostname}|{event_timestamp}|{syslog_text.strip()}"
    
    # Use a fixed namespace UUID (can be arbitrary)
    namespace = uuid.UUID('12345678-1234-5678-1234-567812345678')
    
    # Generate a UUIDv5
    return str(uuid.uuid5(namespace, unique_string))

if __name__=="__main__":
    agent_name="R1"
    timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    message="%OSPF-4-DUP_RTRID_NBR: OSPF detected duplicate router-id 1.1.1.1 from 192.168.1.1 on interface Loopback0"

    id=generate_event_id(agent_name,timestamp,message)

    print(id)