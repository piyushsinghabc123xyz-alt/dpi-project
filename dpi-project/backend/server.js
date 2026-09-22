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

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// --- Packet Capture Setup ---
const cap = new Cap();
const device = 'en0';
const filter = 'ip or ip6';
const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

try {
  cap.open(device, filter, bufSize, buffer);
  cap.setMinBytes && cap.setMinBytes(0);
} catch (e) {
  console.error("Interface open error:", e);
}

// --- State Store ---
let activeStats = {
  protocols: { HTTPS: 0, DNS: 0, HTTP: 0, OTHER: 0 },
  ipUsage: {},       
  ipToDomain: {},    
  blockedRules: {},
  securityAlerts: [],
  totalPackets: 0
};

// Common IP-to-Domain Map Overrides for Clean UI Output
const StaticDomainMap = {
  '192.168.1.18': 'Your Local Mac (This Device)',
  '192.168.1.1': 'Home Wi-Fi Router',
  '192.168.1.255': 'Local Wi-Fi Network Broadcast',
  '224.0.0.251': 'Apple AirPlay / MDNS Service'
};

// --- Layer-7 Packet Capture Loop ---
cap.on('packet', (nbytes) => {
  activeStats.totalPackets++;
  let ret = decoders.Ethernet(buffer);
  
  if (ret.info.type === decoders.PROTOCOL.ETHERNET.IPV4) {
    ret = decoders.IPV4(buffer, ret.offset);
    const dstIp = ret.info.dstaddr;
    const protocol = ret.info.protocol;

    if (!activeStats.ipUsage[dstIp]) {
      const knownLabel = StaticDomainMap[dstIp] || activeStats.ipToDomain[dstIp] || 'Resolving Host...';
      activeStats.ipUsage[dstIp] = { bytes: 0, domain: knownLabel };
      if (!StaticDomainMap[dstIp]) resolveIpDomain(dstIp);
    }
    activeStats.ipUsage[dstIp].bytes += nbytes;

    if (protocol === 6) { // TCP
      const tcp = decoders.TCP(buffer, ret.offset);
      const payloadOffset = ret.offset + tcp.offset;
      if (tcp.info.dstport === 443 || tcp.info.srcport === 443) {
        activeStats.protocols.HTTPS++;
        parseTlsSni(buffer.slice(payloadOffset, nbytes), dstIp);
      } else if (tcp.info.dstport === 80 || tcp.info.srcport === 80) {
        activeStats.protocols.HTTP++;
      } else {
        activeStats.protocols.OTHER++;
      }
    } else if (protocol === 17) { // UDP
      const udp = decoders.UDP(buffer, ret.offset);
      if (udp.info.dstport === 53 || udp.info.srcport === 53) {
        activeStats.protocols.DNS++;
      } else {
        activeStats.protocols.OTHER++;
      }
    }
  }
});

async function resolveIpDomain(ip) {
  if (activeStats.ipToDomain[ip]) return;
  try {
    const hostnames = await dns.reverse(ip);
    if (hostnames && hostnames.length > 0) {
      let name = hostnames[0];
      // Clean AWS/Cloud reverse DNS strings into readable labels
      if (name.includes('amazonaws.com')) name = 'Amazon Web Services (AWS)';
      if (name.includes('1e100.net') || name.includes('google')) name = 'Google Services / YouTube';
      if (name.includes('cloudfront')) name = 'Cloudfront CDN';
      
      activeStats.ipToDomain[ip] = name;
      if (activeStats.ipUsage[ip]) activeStats.ipUsage[ip].domain = name;
    }
  } catch (err) {
    activeStats.ipToDomain[ip] = 'Web Server / Cloud Host';
    if (activeStats.ipUsage[ip]) activeStats.ipUsage[ip].domain = 'Web Server / Cloud Host';
  }
}

function parseTlsSni(payload, dstIp) {
  if (payload.length < 5 || payload[0] !== 0x16) return;
  const payloadStr = payload.toString('binary');
  const domainMatch = payloadStr.match(/([a-z0-9|-]+\.)+[a-z]{2,}/i);
  
  if (domainMatch) {
    const domain = domainMatch[0];
    activeStats.ipToDomain[dstIp] = domain;
    if (activeStats.ipUsage[dstIp]) activeStats.ipUsage[dstIp].domain = domain;
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Broadcast loop
setInterval(() => {
  const sortedIps = Object.entries(activeStats.ipUsage)
    .map(([ip, data]) => ({
      ip,
      domain: data.domain || StaticDomainMap[ip] || activeStats.ipToDomain[ip] || 'Web Host',
      bytes: data.bytes,
      formattedSize: formatBytes(data.bytes)
    }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 7);

  const blockedList = Object.entries(activeStats.blockedRules).map(([target, ips]) => ({
    target,
    ipCount: ips.length
  }));

  io.emit('telemetry', {
    protocols: activeStats.protocols,
    topIps: sortedIps,
    blockedDomains: blockedList,
    alerts: activeStats.securityAlerts,
    totalPackets: activeStats.totalPackets
  });
}, 1000);

// --- REAL WORKING BLOCKING ENGINE ---
app.post('/api/block-domain', async (req, res) => {
  let { target } = req.body;
  if (!target) return res.status(400).json({ success: false });

  // Clean input (remove https:// or www.)
  target = target.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split('/')[0];

  let ipsToBlock = [];
  let targetsToResolve = [target, `www.${target}`];

  if (target.includes('youtube')) {
    targetsToResolve.push('googlevideo.com', 'ytimg.com', 'youtube-nocookie.com');
  }

  for (let t of targetsToResolve) {
    try {
      const resolved4 = await dns.resolve4(t);
      ipsToBlock.push(...resolved4);
    } catch (e) {}
    try {
      const resolved6 = await dns.resolve6(t);
      ipsToBlock.push(...resolved6);
    } catch (e) {}
  }

  if (ipsToBlock.length === 0) ipsToBlock = [target];

  // 1. Enforce Firewall Drops
  ipsToBlock.forEach(ip => {
    exec(`echo 'block drop out proto { tcp, udp } to ${ip}' | sudo pfctl -a dpi_rules -f -`);
  });

  // 2. Kill Active Socket Connections immediately so browsers stop streaming
  exec(`sudo pfctl -k 0.0.0.0/0 -k 0.0.0.0/0`);

  // 3. Hosts File Sinkhole for instant browser redirection block
  const hostsRule = `127.0.0.1 ${target} www.${target}`;
  exec(`echo "${hostsRule}" | sudo tee -a /etc/hosts`);

  activeStats.blockedRules[target] = ipsToBlock;
  activeStats.securityAlerts.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    type: 'FIREWALL_RULE_ENFORCED',
    message: `Kernel Block Enforced for "${target}" (${ipsToBlock.length} IP endpoints dropped)`
  });

  res.json({ success: true, target, ipsToBlock });
});

// --- UNBLOCK ENGINE ---
app.post('/api/unblock-domain', (req, res) => {
  let { target } = req.body;
  target = target.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split('/')[0];

  if (activeStats.blockedRules[target]) {
    delete activeStats.blockedRules[target];
  }

  // 1. Clear pfctl firewall anchor
  exec(`sudo pfctl -a dpi_rules -F all`);

  // 2. Remove rule from /etc/hosts
  exec(`sudo sed -i '' '/${target}/d' /etc/hosts`);

  activeStats.securityAlerts.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    type: 'FIREWALL_RULE_CLEARED',
    message: `Flushed firewall & unblocked domain: "${target}"`
  });

  res.json({ success: true, message: `Unblocked ${target}` });
});

server.listen(5001, () => console.log('DPI Engine listening on port 5001'));