import React, { useEffect, useState } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

import './App.css';

ChartJS.register(ArcElement, Tooltip, Legend);
const socket = io('http://localhost:5001');

function App() {
  const [telemetry, setTelemetry] = useState({ 
    protocols: { HTTPS: 0, DNS: 0, HTTP: 0, OTHER: 0 }, 
    topIps: [], 
    blockedDomains: [], 
    alerts: [], 
    totalPackets: 0 
  });
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
      console.error('Failed to submit block rule:', err);
    }
  };

  const handleUnblock = async (target) => {
    try {
      await axios.post('http://localhost:5001/api/unblock-domain', { target });
    } catch (err) {
      console.error('Failed to unblock rule:', err);
    }
  };

  // Percentage Calculations
  const totalProtocols = Object.values(telemetry.protocols || {}).reduce((a, b) => a + b, 0) || 1;
  const getPercent = (count) => (((count || 0) / totalProtocols) * 100).toFixed(1);

  const chartData = {
    labels: ['HTTPS', 'DNS', 'HTTP', 'OTHER'],
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
    <div className="app-container">
      {/* Header */}
      <header className="dashboard-header">
        <div>
          <h1 className="dashboard-title">Deep Packet Inspection & Website Blocker</h1>
          <p className="dashboard-subtitle">Real-Time Network Traffic Monitor & Kernel Firewall Controller</p>
        </div>
        <div className="status-badge">
          <span className="pulse-dot"></span> Live Monitor | {telemetry.totalPackets || 0} Packets Processed
        </div>
      </header>

      {/* Main Grid */}
      <div className="dashboard-grid">
        
        {/* Card 1: Protocol Pie Chart & Breakdown */}
        <div className="dashboard-card">
          <h3 className="card-title">Traffic Protocol Breakdown</h3>
          <div className="chart-wrapper">
            <Doughnut data={chartData} options={{ plugins: { legend: { display: false } } }} />
          </div>

          <div className="percentage-box">
            <div className="percent-row">
              <span><strong className="dot-https">●</strong> HTTPS (Secure Web):</span>
              <strong>{getPercent(telemetry.protocols.HTTPS)}%</strong>
            </div>
            <div className="percent-row">
              <span><strong className="dot-dns">●</strong> DNS (Domain Queries):</span>
              <strong>{getPercent(telemetry.protocols.DNS)}%</strong>
            </div>
            <div className="percent-row">
              <span><strong className="dot-http">●</strong> HTTP (Unencrypted):</span>
              <strong>{getPercent(telemetry.protocols.HTTP)}%</strong>
            </div>
            <div className="percent-row">
              <span><strong className="dot-other">●</strong> Other Traffic:</span>
              <strong>{getPercent(telemetry.protocols.OTHER)}%</strong>
            </div>
          </div>
        </div>

        {/* Card 2: Bandwidth Table */}
        <div className="dashboard-card large">
          <h3 className="card-title">Top Website & Device Traffic Usage</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Website / Device Name</th>
                <th>Data Transfer</th>
                <th>Quick Action</th>
              </tr>
            </thead>
            <tbody>
              {(telemetry.topIps || []).map((item) => (
                <tr key={item.ip}>
                  <td><code>{item.ip}</code></td>
                  <td className="domain-name">{item.domain}</td>
                  <td><strong>{item.formattedSize}</strong></td>
                  <td>
                    <button 
                      onClick={() => setTargetToBlock(item.domain.includes('.') ? item.domain : item.ip)}
                      className="btn-quick-block"
                    >
                      Block This
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Card 3: Website Blocker Controls */}
        <div className="dashboard-card">
          <h3 className="card-title">Block Any Website</h3>
          <p className="card-description">
            Type any domain (e.g. <code>youtube.com</code> or <code>facebook.com</code>) to cut access instantly.
          </p>
          
          <form onSubmit={handleBlockSubmit}>
            <input 
              type="text" 
              placeholder="e.g. youtube.com" 
              value={targetToBlock} 
              onChange={(e) => setTargetToBlock(e.target.value)}
              className="block-input"
            />
            <button type="submit" className="btn-primary">
              Block Website Instantly
            </button>
          </form>

          <div style={{ marginTop: '20px' }}>
            <h4 style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '10px' }}>Currently Blocked Websites:</h4>
            <div style={{ maxHeight: '130px', overflowY: 'auto' }}>
              {(telemetry.blockedDomains || []).length === 0 ? (
                <span style={{ fontSize: '12px', color: '#64748b' }}>No websites blocked right now.</span>
              ) : (
                telemetry.blockedDomains.map((item, idx) => (
                  <div key={idx} className="blocked-badge">
                    <span>🚫 <strong>{item.target}</strong></span>
                    <button onClick={() => handleUnblock(item.target)} className="btn-unblock">
                      Unblock
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

      </div>

      {/* Security Event Feed */}
      <div className="dashboard-card" style={{ marginTop: '20px' }}>
        <h3 className="card-title">Live Firewall Activity Log</h3>
        <div className="alert-container">
          {(telemetry.alerts || []).length === 0 ? (
            <p style={{ color: '#6b7280', fontSize: '14px' }}>No activity logged yet.</p>
          ) : (
            telemetry.alerts.map((alert) => (
              <div key={alert.id} className="alert-row">
                <span className="alert-timestamp">[{alert.timestamp}]</span>
                <span className={`alert-tag ${alert.type === 'FIREWALL_RULE_ENFORCED' ? 'enforced' : 'cleared'}`}>
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

export default App;