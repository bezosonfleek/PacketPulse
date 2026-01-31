# PacketPulse - this service is still in production and has not been tested.
A Dynamic Network Vulnerability Scanner still in progress.

Start date: 29/01/2026.

Using Docker:
-Create a new folder named PacketPulse with these files: index.html, demo.py & Dockerfile as provided
-Open terminal from the folder to use Docker in CLI mode
-Build the image: docker build -t packetpulse:local .
-Launch the container: docker run -d --name packet_pulse -p 9000:8000 packetpulse:local
-You can confirm status by running 'docker ps' and access the app via http://localhost:9000
