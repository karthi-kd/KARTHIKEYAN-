from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap, ARP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import tempfile
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    # ---------- VALIDATION ----------
    if not file.filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only PCAP files allowed")

    temp_path = None

    try:
        contents = await file.read()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(contents)
            temp_path = tmp.name

        packets = rdpcap(temp_path)

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid PCAP file: {str(e)}")

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

    # ---------- ANALYSIS ----------
    ip_count = {}
    arp_count = 0
    non_ip_packets = 0

    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src

        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src

        elif pkt.haslayer(ARP):
            arp_count += 1
            continue

        else:
            non_ip_packets += 1
            continue

        ip_count[src] = ip_count.get(src, 0) + 1

    # ---------- RESPONSE TABLE ----------
    table_data = [
        {
            "source_ip": ip,
            "packet_count": count,
            "status": "Suspicious" if count > 100 else "Normal"
        }
        for ip, count in ip_count.items()
    ]

    return {
        "total_packets": len(packets),
        "ip_packets": sum(ip_count.values()),
        "arp_packets": arp_count,
        "non_ip_packets": non_ip_packets,
        "table": table_data
    }
