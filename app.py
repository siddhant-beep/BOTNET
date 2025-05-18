from flask import Flask, jsonify
from scapy.all import sniff, IP
import threading

app = Flask(__name__)
packet_data = []  # Stores captured packets

# Function to capture packets
def capture_packets():
    def process_packet(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_data.append({"Source IP": src_ip, "Destination IP": dst_ip})
            print(f"📡 Source IP: {src_ip} → Destination IP: {dst_ip}")

    sniff(prn=process_packet, store=False, count=0)  # Capture indefinitely

# Run packet capture in a separate thread
threading.Thread(target=capture_packets, daemon=True).start()

@app.route("/api/packets", methods=["GET"])
def get_packets():
    return jsonify(packet_data)






if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
