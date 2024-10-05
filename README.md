
# TrafficEye

TrafficEye is a Python-based packet sniffer that captures and analyzes network traffic in real-time. This tool provides insights into source and destination IPs, protocols, and suspicious activities, making it an essential resource for monitoring network activity and enhancing cybersecurity.

## Features

- **Real-Time Packet Capture**: Monitor network traffic live.
- **Detailed Analysis**: Display information on IPs, protocols, and packet sizes.
- **Suspicious Activity Alerts**: Identify potential threats based on known malicious IPs.
- **User-Friendly Interface**: Easy to use with a graphical interface.

## Requirements

- Python 3.x
- Scapy
- Tkinter
- Pillow
 
## Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd TrafficEye
   ```
2. Install required packages:
   ```bash
   pip install scapy pillow
   ```
## Usage
To run the tool, ensure you have superuser privileges. Execute the following command in your terminal:

Run the tool using:
```bash
sudo python TrafficEye.py
```

## License

This project is licensed under the MIT License.

## Acknowledgements

- [Scapy](https://scapy.readthedocs.io/en/latest/) for packet manipulation and sniffing capabilities.
