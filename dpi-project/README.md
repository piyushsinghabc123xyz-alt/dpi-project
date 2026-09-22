========================================================================
             DEEP PACKET INSPECTION & THREAT CONTROL CENTER
========================================================================

A real-time network traffic analyzer and dynamic firewall control center 
built for macOS. It captures live packet data from your Wi-Fi card, inspects 
Layer-7 headers to see which websites and protocols are using bandwidth, 
and lets you block any domain or IP instantly at the macOS kernel level.

------------------------------------------------------------------------
1. TECH STACK
------------------------------------------------------------------------
  * Frontend:      React.js, Chart.js, Socket.io-client, Axios
  * Backend:       Node.js, Express.js, Socket.io
  * Packet Engine: "cap" (C++ libpcap wrapper for Node.js)
  * System Tools:  macOS libpcap, pfctl (Packet Filter), /etc/hosts

------------------------------------------------------------------------
2. SYSTEM REQUIREMENTS & ONE-TIME SETUP
------------------------------------------------------------------------
Before running the project, make sure you have installed:
  - Node.js (v18 or higher)
  - Xcode Command Line Tools (for compiling native C++ bindings)

To install Xcode tools, open Terminal and run:
  xcode-select --install

Because reading raw Wi-Fi frames requires system-level packet access, 
run these two commands in your Mac terminal once:

  1) Grant access to BSD Packet Filters:
     sudo chown $USER /dev/bpf*

  2) Turn on macOS's built-in pf firewall:
     sudo pfctl -e

------------------------------------------------------------------------
3. HOW TO START AND RUN THE PROJECT
------------------------------------------------------------------------

STEP 1: Start the Backend Engine
--------------------------------
1. Open Terminal and navigate to the backend directory:
     cd dpi-project/backend

2. Install backend dependencies:
     npm install

3. Start the backend with 'sudo' (required for kernel firewall rules):
     sudo node server.js

You should see: "DPI Engine listening on port 5001"
(Keep this terminal window open while using the project).


STEP 2: Start the Frontend Dashboard
-------------------------------------
1. Open a SECOND terminal window and navigate to the frontend directory:
     cd dpi-project/frontend

2. Install frontend dependencies:
     npm install

3. Launch the React dashboard:
     npm start

Your browser will automatically open to http://localhost:3000.

------------------------------------------------------------------------
4. HOW TO TEST THE PROJECT
------------------------------------------------------------------------
1. Live Traffic Monitoring:
   Open a few websites on your Mac (like Wikipedia, Google, or news sites). 
   Watch the Protocol Breakdown chart and the Bandwidth Leaderboard update 
   live every second.

2. Blocking a Website:
   Type any domain name (e.g., youtube.com or facebook.com) into the 
   "Block Any Website" form and click "Block Website Instantly".

3. Verify the Block:
   Try opening youtube.com in Chrome or Safari. The connection will fail 
   or time out instantly across all browsers.

4. Unblocking:
   Click the green "Unblock" button next to the blocked domain in the UI 
   dashboard, and your internet access to that site will be restored immediately.

------------------------------------------------------------------------
5. PROJECT FILE STRUCTURE
------------------------------------------------------------------------
dpi-project/
├── backend/
│   ├── package.json
│   └── server.js      <-- Packet capture, WebSockets, and pfctl logic
└── frontend/
    ├── package.json
    └── src/
        └── App.js     <-- React UI dashboard and WebSocket client
========================================================================