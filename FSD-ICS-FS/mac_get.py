from flask import Flask, request, jsonify
from scapy.all import ARP, Ether, srp
import socket

app = Flask(__name__)

def get_mac(ip, iface=None):
    try:
        # Create an ARP request packet to get the MAC address associated with the provided IP address
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcasting to all devices on the network
        packet = ether/arp_request

        # Send the packet and receive the response
        if iface:
            result = srp(packet, timeout=5, verbose=1, iface=iface)[0]
        else:
            result = srp(packet, timeout=5, verbose=1)[0]

        # Print the received packets for debugging
        print(result)

        # Return the MAC address from the response
        return result[0][1].hwsrc if result and result[0] else None
    except Exception as e:
        print(f"Error getting MAC address: {e}")
        return None

def get_network_interface():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        interface = s.getsockname()[1]
        s.close()
        return interface
    except Exception as e:
        print(f"Error getting network interface: {e}")
        return None

@app.route('/')
def get_info():
    try:
        client_ip = request.remote_addr
        client_mac = get_mac(client_ip, iface=get_network_interface())

        response = {
            'ip_address': client_ip,
            'mac_address': client_mac,
            'network_interface': get_network_interface(),
        }

        print(f"Captured information for {client_ip}: {response}")

        return jsonify(response)

    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500

if __name__ == '__main__':
    def get_public_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            public_ip = s.getsockname()[0]
            s.close()
            return public_ip
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None
    app.run(debug=True, host=str(get_public_ip()), port=5000)
