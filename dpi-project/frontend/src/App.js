import React, { useEffect, useState } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);
const socket = io('http://localhost:5001');

function App() {
  const [telemetry, setTelemetry] = useState({ protocols: { HTTPS: 0, DNS: 0, HTTP: 0, OTHER: 0 }, topIps: [], blockedDomains: [], alerts: [], totalPackets: 0 });
  const [targetToBlock, setTargetToBlock] = useState('');

  useEffect(() => {
    socket.on('telemetry', (data) => setTelemetry(data));
    return () => socket.off('telemetry');
  }, []);

  const handleBlockSubmit = async (e) => {
    e.preventDefault();
    if (!targetToBlock) return;
    try {
      await axios.post('http://localhost:5001/api/block-domain', { target: targetToBlock });
      setTargetToBlock('');
    } catch (err) {
      console.error(err);
    }
  };

  const handleUnblock = async (target) => {
    try {
      await axios.post('http://localhost:5001/api/unblock-domain', { target });
    } catch (err) {
      console.error(err);
    }
  };

  // Protocol Percentage Calculations
  const totalProtocols = Object.values(telemetry.protocols || {}).reduce((a, b) => a + b, 0) || 1;
  const getPercent = (count) => (((count || 0) / totalProtocols) * 100).toFixed(1);

  const chartData = {
    labels: ['HTTPS (Secure Web)', 'DNS (Domain Lookup)', 'HTTP (Web)', 'OTHER'],
    datasets: [{
      data: [
        telemetry.protocols.HTTPS || 0,
        telemetry.protocols.DNS || 0,
        telemetry.protocols.HTTP || 0,
        telemetry.protocols.OTHER || 0
      ],
      backgroundColor: ['#3b82f6', '#ef4444', '#f59e0b', '#10b981'],
      borderWidth: 0
    }],
  };

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>Deep Packet Inspection & Website Blocker</h1>
          <p style={styles.subtitle}>Real-Time Network Traffic Monitor & Kernel Firewall Controller</p>
        </div>
        <div style={styles.badge}>
          <span style={styles.livePulse}></span> Live Monitor | {telemetry.totalPackets || 0} Packets Processed
        </div>
      </header>

      <div style={styles.grid}>
        {/* Protocol Pie Chart & Percentages */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Traffic Protocol Breakdown</h3>
          <div style={{ width: '180px', margin: '0 auto 15px auto' }}>
            <Doughnut data={chartData} options={{ plugins: { legend: { display: false } } }} />
          </div>

          {/* Percentage Breakdown Display Below Pie Chart */}
          <div style={styles.percentageBox}>
            <div style={styles.percentRow}>
              <span><strong style={{ color: '#3b82f6' }}>●</strong> HTTPS (Secure Web):</span>
              <strong>{getPercent(telemetry.protocols.HTTPS)}%</strong>
            </div>
            <div style={styles.percentRow}>
              <span><strong style={{ color: '#ef4444' }}>●</strong> DNS (Domain Queries):</span>
              <strong>{getPercent(telemetry.protocols.DNS)}%</strong>
            </div>
            <div style={styles.percentRow}>
              <span><strong style={{ color: '#f59e0b' }}>●</strong> HTTP (Unencrypted):</span>
              <strong>{getPercent(telemetry.protocols.HTTP)}%</strong>
            </div>
            <div style={styles.percentRow}>
              <span><strong style={{ color: '#10b981' }}>●</strong> Other Traffic:</span>
              <strong>{getPercent(telemetry.protocols.OTHER)}%</strong>
            </div>
          </div>
        </div>

        {/* Bandwidth Leaderboard */}
        <div style={{ ...styles.card, flex: '2' }}>
          <h3 style={styles.cardTitle}>Top Website & Device Traffic Usage</h3>
          <table style={styles.table}>
            <thead>
              <tr style={styles.tableHeader}>
                <th style={styles.th}>IP Address</th>
                <th style={styles.th}>Website / Device Name</th>
                <th style={styles.th}>Data Transfer</th>
                <th style={styles.th}>Quick Action</th>
              </tr>
            </thead>
            <tbody>
              {(telemetry.topIps || []).map((item) => (
                <tr key={item.ip} style={styles.tableRow}>
                  <td style={styles.td}><code>{item.ip}</code></td>
                  <td style={{ ...styles.td, color: '#38bdf8', fontWeight: '600' }}>
                    {item.domain}
                  </td>
                  <td style={styles.td}><strong>{item.formattedSize}</strong></td>
                  <td style={styles.td}>
                    <button 
                      onClick={() => setTargetToBlock(item.domain.includes('.') ? item.domain : item.ip)}
                      style={styles.quickBlockBtn}
                    >
                      Block This
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Website Blocker Form */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Block Any Website</h3>
          <p style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '15px' }}>
            Type any domain (e.g. <code>youtube.com</code> or <code>facebook.com</code>) to cut access across all browsers instantly.
          </p>
          <form onSubmit={handleBlockSubmit}>
            <input 
              type="text" 
              placeholder="e.g. youtube.com" 
              value={targetToBlock} 
              onChange={(e) => setTargetToBlock(e.target.value)}
              style={styles.input}
            />
            <button type="submit" style={styles.blockBtn}>
              Block Website Instantly
            </button>
          </form>

          <div style={{ marginTop: '20px' }}>
            <h4 style={{ fontSize: '13px', color: '#94a3b8', margin: '0 0 10px 0' }}>Currently Blocked Websites:</h4>
            <div style={{ maxHeight: '130px', overflowY: 'auto' }}>
              {(telemetry.blockedDomains || []).length === 0 ? (
                <span style={{ fontSize: '12px', color: '#64748b' }}>No websites blocked right now.</span>
              ) : (
                telemetry.blockedDomains.map((item, idx) => (
                  <div key={idx} style={styles.blockedBadge}>
                    <span>🚫 <strong>{item.target}</strong></span>
                    <button onClick={() => handleUnblock(item.target)} style={styles.unblockBtn}>
                      Unblock
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Security Event Log */}
      <div style={{ ...styles.card, marginTop: '20px' }}>
        <h3 style={styles.cardTitle}>Live Firewall Activity Log</h3>
        <div style={{ maxHeight: '150px', overflowY: 'auto' }}>
          {(telemetry.alerts || []).length === 0 ? (
            <p style={{ color: '#6b7280', fontSize: '14px' }}>No activity logged yet.</p>
          ) : (
            telemetry.alerts.map((alert) => (
              <div key={alert.id} style={styles.alertRow}>
                <span style={styles.timestamp}>[{alert.timestamp}]</span>
                <span style={{ 
                  ...styles.alertType, 
                  backgroundColor: alert.type === 'FIREWALL_RULE_ENFORCED' ? '#065f46' : '#991b1b',
                  color: alert.type === 'FIREWALL_RULE_ENFORCED' ? '#34d399' : '#f87171'
                }}>
                  {alert.type}
                </span>
                <span style={{ color: '#e5e7eb' }}>{alert.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

const styles = {
  container: { padding: '30px', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', backgroundColor: '#0f172a', color: '#f8fafc', minHeight: '100vh' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '25px', borderBottom: '1px solid #1e293b', paddingBottom: '15px' },
  title: { margin: 0, fontSize: '26px', fontWeight: '700' },
  subtitle: { margin: '5px 0 0 0', color: '#94a3b8', fontSize: '14px' },
  badge: { backgroundColor: '#1e293b', padding: '8px 14px', borderRadius: '20px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px', border: '1px solid #334155' },
  livePulse: { width: '8px', height: '8px', backgroundColor: '#22c55e', borderRadius: '50%', display: 'inline-block' },
  grid: { display: 'flex', gap: '20px', flexWrap: 'wrap' },
  card: { background: '#1e293b', padding: '20px', borderRadius: '12px', border: '1px solid #334155' },
  cardTitle: { margin: '0 0 15px 0', fontSize: '16px', fontWeight: '600' },
  percentageBox: { borderTop: '1px solid #334155', paddingTop: '12px', marginTop: '10px' },
  percentRow: { display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px', color: '#cbd5e1' },
  table: { width: '100%', borderCollapse: 'collapse', textAlign: 'left' },
  tableHeader: { borderBottom: '1px solid #334155', color: '#94a3b8', fontSize: '13px' },
  th: { padding: '10px 8px' },
  tableRow: { borderBottom: '1px solid #1e293b', fontSize: '14px' },
  td: { padding: '12px 8px' },
  input: { width: '92%', padding: '10px', backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '6px', color: '#fff', marginBottom: '12px' },
  blockBtn: { width: '100%', padding: '10px', backgroundColor: '#ef4444', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: '600' },
  quickBlockBtn: { padding: '4px 8px', backgroundColor: '#334155', color: '#38bdf8', border: '1px solid #0284c7', borderRadius: '4px', cursor: 'pointer', fontSize: '12px', fontWeight: '600' },
  blockedBadge: { padding: '8px 10px', backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '6px', fontSize: '12px', color: '#f87171', marginBottom: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  unblockBtn: { padding: '3px 8px', backgroundColor: '#059669', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '11px', fontWeight: '600' },
  alertRow: { padding: '8px 0', borderBottom: '1px solid #334155', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '10px' },
  timestamp: { color: '#64748b' },
  alertType: { padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: '600' }
};

export default App;