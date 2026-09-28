const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Cap, decoders } = require('cap');
const { exec } = require('child_process');
const dns = require('dns').promises;

const app = express();
app.use(cors());
app.use(express.json());

const srv = http.createServer(app);
const io = new Server(srv, { cors: { origin: '*' } });
//Create and initialize a C++ object/module that wraps libpcap and uses 
// it to capture network packets from a network interface
const pcap = new Cap();
const rawBuf = Buffer.alloc(65535);

try {
  pcap.open('en0', 'ip or ip6', 10485760, rawBuf);
  if (pcap.setMinBytes) pcap.setMinBytes(0);
} catch (err) {
  console.log('[-] Could not open network interface:', err.message);
}

const sessionData = {
  //stores live network traffic stats,protocol counts,and firewall status in memory
  protocolTotals: { HTTPS: 0, DNS: 0, HTTP: 0, OTHER: 0 },
  clientUsage: {},
  knownDomains: {},
  blocklist: {},
  logs: [],
  totalFrames: 0
};

// maps common local infrastructure and broadcast IPs to their expected values
const localMap = {
  '192.168.1.18': 'My Mac (Host)',
  '192.168.1.1': 'Home Gateway',
  '192.168.1.255': 'Subnet Broadcast',
  '224.0.0.251': 'mDNS / AirPlay'
};
// packet capture loop that fires every time a raw Ethernet frame is intercepted on interface 'en0
pcap.on('packet', (size) => {
  sessionData.totalFrames++;
  let res = decoders.Ethernet(rawBuf);
  
  if (res.info.type === decoders.PROTOCOL.ETHERNET.IPV4) {
    res = decoders.IPV4(rawBuf, res.offset);
    const destination = res.info.dstaddr;
    const protoType = res.info.protocol;

    if (!sessionData.clientUsage[destination]) {
      const tag = localMap[destination] || sessionData.knownDomains[destination] || 'Unresolved Host';
      sessionData.clientUsage[destination] = { bytes: 0, domain: tag };
      if (!localMap[destination]) resolveHostName(destination);
    }
    sessionData.clientUsage[destination].bytes += size;
    //check if Layer-4 protocol is TCP - protocol number 6
    if (protoType === 6) { // TCP
      const tcpHeader = decoders.TCP(rawBuf, res.offset);
      const payloadStart = res.offset + tcpHeader.offset;
      const port = tcpHeader.info.dstport;
      const srcPort = tcpHeader.info.srcport;
      if (port === 443 || srcPort === 443) {
        sessionData.protocolTotals.HTTPS++;
        parseSniHeader(rawBuf.slice(payloadStart, size), destination);
      } else if (port === 80 || srcPort === 80) {
        sessionData.protocolTotals.HTTP++;
      } else {
        sessionData.protocolTotals.OTHER++;
      }
    } // check if Layer-4 protocol is UDP - protocol number 17
    else if (protoType === 17) { // UDP
      const udpHeader = decoders.UDP(rawBuf, res.offset);
      if (udpHeader.info.dstport === 53 || udpHeader.info.srcport === 53) {
        sessionData.protocolTotals.DNS++;
      } else {
        sessionData.protocolTotals.OTHER++;
      }
    }
  }
});
// handles reverse DNS lookups in the background
// finds the domain name associated with an IP address
function resolveHostName(addr) {
  if (sessionData.knownDomains[addr]) return;
  
  dns.reverse(addr).then(ptrs => {
    if (ptrs && ptrs.length > 0) {
      let hostLabel = ptrs[0];
      if (hostLabel.includes('amazonaws.com')) hostLabel = 'AWS Infrastructure';
      if (hostLabel.includes('1e100.net') || hostLabel.includes('google')) hostLabel = 'Google Cloud / YT';
      if (hostLabel.includes('cloudfront')) hostLabel = 'Cloudfront CDN';      
      sessionData.knownDomains[addr] = hostLabel;
      if (sessionData.clientUsage[addr]) sessionData.clientUsage[addr].domain = hostLabel;
    }
  }).catch(() => {
    sessionData.knownDomains[addr] = 'Remote Server';
    if (sessionData.clientUsage[addr]) sessionData.clientUsage[addr].domain = 'Remote Server';
  });
}
//extracts the hostname from the TLS client hello packet
function parseSniHeader(data, targetIp) {
  if (data.length < 5 || data[0] !== 22) return; // 0x16 Handshake
  const str = data.toString('binary');
  const found = str.match(/([a-z0-9|-]+\.)+[a-z]{2,}/i);
  
  if (found) {
    const hostname = found[0];
    sessionData.knownDomains[targetIp] = hostname;
    if (sessionData.clientUsage[targetIp]) sessionData.clientUsage[targetIp].domain = hostname;
  }
}
function formatDataVolume(totalBytes) { //converts byte values into readable units like KB, MB, and GB
  if (!totalBytes) return '0 B';
  const labels = ['B', 'KB', 'MB', 'GB'];
  const idx = Math.floor(Math.log(totalBytes) / Math.log(1024));
  return (totalBytes / Math.pow(1024, idx)).toFixed(1) + ' ' + labels[idx];
}
//collects packet stats every second and sends them to the React client through Websockets
setInterval(() => {
  const sortedEndpoints = Object.entries(sessionData.clientUsage)
    .map(([ip, details]) => ({
      ip,
      domain: details.domain || localMap[ip] || sessionData.knownDomains[ip] || 'Unknown',
      bytes: details.bytes,
      formattedSize: formatDataVolume(details.bytes)
    }))
    .sort((x, y) => y.bytes - x.bytes)
    .slice(0, 7);

  const activeRules = Object.entries(sessionData.blocklist).map(([site, ips]) => ({
    target: site,
    ipCount: ips.length
  }));
  io.emit('telemetry', {
    protocols: sessionData.protocolTotals,
    topIps: sortedEndpoints,
    blockedDomains: activeRules,
    alerts: sessionData.logs,
    totalPackets: sessionData.totalFrames
  });
}, 1000);
// POST /api/block-domain
// Blocking -> Takes a domain from the request and applies the firewall block.
app.post('/api/block-domain', async (req, res) => {
  let domain = req.body.target;
  if (!domain) return res.status(400).json({ error: 'No domain provided' });

  domain = domain.replace(/^(?:https?:\/\/)?(?:www\.)?/i, '').split('/')[0];
  let ips = [];
  let queryTargets = [domain, `www.${domain}`];

  if (domain.includes('youtube')) {
    queryTargets.push('googlevideo.com', 'ytimg.com', 'youtube-nocookie.com');
  }

  for (const t of queryTargets) {
    try {
      const v4 = await dns.resolve4(t);
      ips.push(...v4);
    } catch (_) {}
    try {
      const v6 = await dns.resolve6(t);
      ips.push(...v6);
    } catch (_) {}
  }
  if (ips.length === 0) ips = [domain];
  //. Inject pfctl drop rules into dedicated anchor
  ips.forEach(ip => {
    exec(`echo 'block drop out proto { tcp, udp } to ${ip}' | sudo pfctl -a dpi_rules -f -`);
  });
  // terminate active socket states so streams cut immediately
  exec('sudo pfctl -k 0.0.0.0/0 -k 0.0.0.0/0');
  exec(`echo "127.0.0.1 ${domain} www.${domain}" | sudo tee -a /etc/hosts`);
  sessionData.blocklist[domain] = ips;
  sessionData.logs.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    type: 'ENFORCED',
    message: `Enforced kernel block for "${domain}" (${ips.length} endpoints dropped)`
  });
  res.json({ success: true, domain, resolvedEndpoints: ips });
});
// POST /api/unblock-domain
// Unblocking -> Removes the block for a previously blocked domain.
app.post('/api/unblock-domain', (req, res) => {
  let domain = req.body.target;
  domain = domain.replace(/^(?:https?:\/\/)?(?:www\.)?/i, '').split('/')[0];
  if (sessionData.blocklist[domain]) {
    delete sessionData.blocklist[domain];
  }
  exec('sudo pfctl -a dpi_rules -F all');
  exec(`sudo sed -i '' '/${domain}/d' /etc/hosts`);
  sessionData.logs.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    type: 'CLEARED',
    message: `Cleared firewall rule for "${domain}"`
  });
  res.json({ success: true });
});
srv.listen(5001, () => console.log('[+] Traffic inspector live on port 5001'));