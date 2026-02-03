from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    contents = await file.read()

    # Save uploaded PCAP
    with open(file.filename, "wb") as f:
        f.write(contents)

    # Read packets
    packets = rdpcap(file.filename)

    ip_count = {}
    for pkt in packets:
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            ip_count[src] = ip_count.get(src, 0) + 1

    # Prepare table-style data
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