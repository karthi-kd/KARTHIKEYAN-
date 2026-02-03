from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap
from scapy.layers.inet import IP
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
    if not file.filename.endswith(".pcap"):
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

    ip_count = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            ip_count[src] = ip_count.get(src, 0) + 1

    table_data = []
    for ip, count in ip_count.items():
        table_data.append({
            "source_ip": ip,
            "packet_count": count,
            "status": "Suspicious" if count > 100 else "Normal"
        })

    return {
        "total_packets": len(packets),
        "table": table_data
    }
