import asyncio
import json
import time
import math
import pyshark
from collections import defaultdict, deque
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Enable CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Flow Tracking State
active_flows = {}  # Extracted Flow Dictionary
flow_history = deque(maxlen=100)  # Sliding window to keep memory clean
subscribers = set() # WebSocket Clients

class FlowTracker:
    def __init__(self, key):
        self.key = key
        self.count = 0
        self.bytes = 0
        self.timestamps = []
        self.packet_sizes = []
        self.sni = "Unknown"
        self.ja3 = "None"
        self.latest_timestamp = time.time()
        
    def add_packet(self, size, current_time, is_tls=False, sni=None, ja3=None):
        self.count += 1
        self.bytes += size
        self.timestamps.append(current_time)
        self.packet_sizes.append(size)
        self.latest_timestamp = current_time
        
        if sni and self.sni == "Unknown":
            self.sni = sni
        if ja3 and self.ja3 == "None":
            self.ja3 = ja3
            
        # Keep manageable history for math
        if len(self.timestamps) > 50:
            self.timestamps.pop(0)
            self.packet_sizes.pop(0)

    def calculate_stats(self):
        # Calculate IAT (Inter-Arrival Time) and packet size stats
        if len(self.timestamps) < 2:
            return {
                "iatMean": 0, "iatStdDev": 0,
                "avgPacketSize": self.bytes, "packetSizeStdDev": 0,
                "periodicityScore": 0, "score": 0, "status": "BENIGN"
            }
            
        iats = [self.timestamps[i] - self.timestamps[i-1] for i in range(1, len(self.timestamps))]
        iat_mean = sum(iats) / len(iats)
        iat_variance = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
        iat_std_dev = math.sqrt(iat_variance)
        
        avg_packet_size = self.bytes / self.count
        size_variance = sum((x - avg_packet_size) ** 2 for x in self.packet_sizes) / len(self.packet_sizes)
        packet_size_std_dev = math.sqrt(size_variance)
        
        # Periodicity Score (Beaconing mathematical model constraint)
        # Highly periodic = low IAT std dev. 
        # Normalized score where 0 variance = 100 score.
        periodicity_score = 0
        if len(iats) >= 5:
            # If standard deviation is extremely low, the signal is periodic (C2 Beacon)
            if iat_std_dev < 0.1:
                periodicity_score = min(100, 100 - (iat_std_dev * 500))
            else:
                periodicity_score = max(0, 50 - (iat_std_dev * 10))

        # Risk Model (Approximation of RandomForest)
        base_score = 0
        status = "BENIGN"
        
        base_score += periodicity_score * 0.6  # 60% weight to periodicity (C2 Beacons)

        # JA3/SNI Penalty
        if self.sni != "Unknown":
            known_benign = ["google", "apple", "microsoft", "amazon", "cloudflare", "facebook", "youtube"]
            if not any(good in self.sni.lower() for good in known_benign):
                base_score += 20 # Unknown/suspicious SNI penalty
                
        # High uniform packet sizes = malware trait
        if packet_size_std_dev < 50 and avg_packet_size < 300:
             base_score += 15

        final_score = min(100, int(base_score))
        if final_score > 60:
            status = "BEACON DETECTED"
        elif final_score > 30:
            status = "SUSPICIOUS"

        return {
            "iatMean": round(iat_mean, 4),
            "iatStdDev": round(iat_std_dev, 4),
            "avgPacketSize": round(avg_packet_size, 2),
            "packetSizeStdDev": round(packet_size_std_dev, 2),
            "periodicityScore": round(periodicity_score, 2),
            "score": final_score,
            "status": status
        }

    def to_dict(self):
        stats = self.calculate_stats()
        src_ip, dest_ip, port = self.key.split("-")
        return {
            "id": self.key,
            "timestamp": time.time(),
            "sourceIp": src_ip,
            "destinationIp": dest_ip,
            "sourcePort": int(port),
            "destinationPort": int(port),
            "protocol": "TCP",
            "sni": self.sni,
            "ja3": self.ja3[:15] + "..." if self.ja3 != "None" else "None",
            "isAnomalous": stats["score"] > 60,
            "totalPackets": self.count,
            "totalBytes": self.bytes,
            "riskScore": stats["score"],
            "iatMean": stats["iatMean"],
            "iatStdDev": stats["iatStdDev"],
            "avgPacketSize": stats["avgPacketSize"],
            "packetSizeStdDev": stats["packetSizeStdDev"],
            "periodicityScore": stats["periodicityScore"]
        }

def process_packet(packet):
    try:
        if not hasattr(packet, 'ip'):
            return

        src_ip = packet.ip.src
        dest_ip = packet.ip.dst
        length = int(packet.length)
        current_time = float(packet.sniff_timestamp)
        
        # We assume HTTPS/TLS traffic for CryptGuard
        port = getattr(packet.tcp, 'dstport', None) if hasattr(packet, 'tcp') else getattr(packet.udp, 'dstport', "0") if hasattr(packet, 'udp') else "0"
        
        if port not in ["443", "8443"]:
             return # Skip non-TLS for this demo profile

        # Flow Key (Bidirectional mapping)
        key_tuple = sorted([src_ip, dest_ip])
        flow_key = f"{key_tuple[0]}-{key_tuple[1]}-{port}"

        sni = None
        ja3 = None
        is_tls = False
        
        if hasattr(packet, 'tls'):
            is_tls = True
            sni = getattr(packet.tls, 'handshake_extensions_server_name', None)
            ja3 = getattr(packet.tls, 'handshake_ja3', None) # Pyshark 0.6 supports JA3 extraction internally or via field configs
            
        if flow_key not in active_flows:
            active_flows[flow_key] = FlowTracker(flow_key)
            
        active_flows[flow_key].add_packet(length, current_time, is_tls, sni, ja3)

    except Exception as e:
        # Ignore malformed packets silently to keep stream alive
        pass

async def fallback_generator():
    """Generates realistic live traffic mathematically if Wireshark is missing."""
    import random
    print("WARNING: Wireshark not found. Running in Dynamic Hybrid Mock Mode.")
    
    benign_snis = ["google.com", "slack-edge.com", "github.com", "zoom.us", "aws.amazon.com"]
    malicious_snis = ["auth-verify-portal.pw", "update-service-win.com"]
    
    while True:
        await asyncio.sleep(random.uniform(0.01, 0.1))  # Faster packet arrival for immediate feedback
        
        # 90% benign, 10% malicious
        is_malicious = random.random() > 0.90
        
        src = f"192.168.1.{random.choice([10, 11, 12, 13, 14, 15])}"
        dest_pool = ["104.18.2.1", "142.250.190.46", "35.190.247.0", "52.95.116.115", "93.184.216.34", "185.199.108.153"]
        malicious_dest = ["103.14.23.44", "45.18.9.112"]
        
        if is_malicious:
            dest = random.choice(malicious_dest)
            sni = random.choice(malicious_snis)
            ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
            size = random.randint(100, 150) # Uniform sizes
        else:
            dest = random.choice(dest_pool)
            sni = random.choice(benign_snis)
            ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0"
            size = random.randint(50, 1500) # Highly variable
            
        flow_key = f"{src}-{dest}-443"
        
        if flow_key not in active_flows:
            active_flows[flow_key] = FlowTracker(flow_key)
            
        current_time = time.time()
        
        # For malicious, we want to simulate beaconing (consistent IATs)
        # We do this by artificially setting the timestamps so std_dev remains low
        if is_malicious and active_flows[flow_key].count > 0:
            current_time = active_flows[flow_key].latest_timestamp + 5.0 # Exactly 5 seconds apart
            
        active_flows[flow_key].add_packet(size, current_time, True, sni, ja3)


async def sniff_network():
    import shutil
    if not shutil.which("tshark") and not shutil.which(r"C:\Program Files\Wireshark\tshark.exe"):
        await fallback_generator()
        return

    try:
        # Since LiveCapture on Windows often requires Admin Npcap privileges, 
        # we will simulate a live stream by reading the test PCAP file in a loop.
        print("Starting PyShark File Capture Simulation (reading 'test_dpi.pcap')...")
        
        def run_capture():
            import os
            pcap_file = r"..\Packet_analyzer\test_dpi.pcap"
            if not os.path.exists(pcap_file):
                print(f"Could not find {pcap_file}, falling back to mock generator.")
                return False

            while True:
                try:
                    capture = pyshark.FileCapture(pcap_file, tshark_path=r"C:\Program Files\Wireshark\tshark.exe")
                    for packet in capture:
                        process_packet(packet)
                        time.sleep(0.1)  # Simulate network propagation delay
                    capture.close()
                except Exception as e:
                    print(e)
                    break
            return True
                
        loop = asyncio.get_event_loop()
        success = await loop.run_in_executor(None, run_capture)
        if not success:
             await fallback_generator()

    except Exception as e:
        print(f"PyShark Initialization Failed: {e}")
        await fallback_generator()

async def stream_flows():
    while True:
        await asyncio.sleep(2.0)  # Push updates to React every 2 seconds
        
        # Clean up stale flows (older than 30 seconds)
        current_time = time.time()
        stale_keys = [k for k, v in active_flows.items() if current_time - v.latest_timestamp > 30]
        for k in stale_keys:
            del active_flows[k]

        if not subscribers:
            continue

        # Convert active flows to output format
        out_flows = [flow.to_dict() for flow in active_flows.values() if flow.count > 0] # Output all active flows for demonstration
        
        if not out_flows:
             out_flows = []

        message = json.dumps({"flows": out_flows})
        
        # Broadcast to all connected clients
        dead_clients = set()
        for subscriber in subscribers:
            try:
                print(f"DEBUG: Broadcasting {len(out_flows)} flows to a client.")
                await subscriber.send_text(message)
            except Exception:
                dead_clients.add(subscriber)
                
        for dead in dead_clients:
            subscribers.remove(dead)

@app.websocket("/api/stream")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    subscribers.add(websocket)
    try:
        while True:
            await websocket.receive_text() # keep-alive block
    except Exception:
        subscribers.remove(websocket)

@app.on_event("startup")
async def startup_event():
    # Start the background sniff loops
    asyncio.create_task(sniff_network())
    asyncio.create_task(stream_flows())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
