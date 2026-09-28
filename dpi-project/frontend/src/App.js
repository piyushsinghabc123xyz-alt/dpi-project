import React, { useEffect, useState } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import './App.css';

ChartJS.register(ArcElement, Tooltip, Legend);
const socket = io('http://localhost:5001');

function App() {
  const [metrics, setMetrics] = useState({
    protocols: { HTTPS: 0, DNS: 0, HTTP: 0, OTHER: 0 },
    topIps: [],
    blockedDomains: [],
    alerts: [],
    totalPackets: 0
  });
  const [targetInput, setTargetInput] = useState('');

  useEffect(() => {
    socket.on('telemetry', (payload) => setMetrics(payload));
    return () => socket.off('telemetry');
  }, []);

  const submitBlock = (e) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    
    axios.post('http://localhost:5001/api/block-domain', { target: targetInput })
      .then(() => setTargetInput(''))
      .catch(err => console.log('Error enforcing block:', err));
  };

  const removeBlock = (site) => {
    axios.post('http://localhost:5001/api/unblock-domain', { target: site })
      .catch(err => console.log('Error clearing block:', err));
  };

  const total = Object.values(metrics.protocols || {}).reduce((acc, curr) => acc + curr, 0) || 1;
  const getPercentage = (val) => (((val || 0) / total) * 100).toFixed(1);

  const pieData = {
    labels: ['HTTPS', 'DNS', 'HTTP', 'OTHER'],
    datasets: [{
      data: [
        metrics.protocols.HTTPS || 0,
        metrics.protocols.DNS || 0,
        metrics.protocols.HTTP || 0,
        metrics.protocols.OTHER || 0
      ],
      backgroundColor: ['#2563eb', '#dc2626', '#d97706', '#059669'],
      borderWidth: 0
    }],
  };

  return (
    <div className="dashboard-root">
      <div className="top-bar">
        <div>
          <h2>Network DPI & Firewall Panel</h2>
          <p className="sub-heading">macOS Kernel Packet Inspector</p>
        </div>
        <div className="status-pill">
          <span className="indicator-dot"></span> {metrics.totalPackets || 0} Packets Captured
        </div>
      </div>

      <div className="panel-grid">
        <div className="panel-card">
          <h3>Protocol Distribution</h3>
          <div className="doughnut-holder">
            <Doughnut data={pieData} options={{ plugins: { legend: { display: false } } }} />
          </div>
          <div className="breakdown-list">
            <div className="stat-item"><span className="legend-marker c-https">■</span> HTTPS: <strong>{getPercentage(metrics.protocols.HTTPS)}%</strong></div>
            <div className="stat-item"><span className="legend-marker c-dns">■</span> DNS: <strong>{getPercentage(metrics.protocols.DNS)}%</strong></div>
            <div className="stat-item"><span className="legend-marker c-http">■</span> HTTP: <strong>{getPercentage(metrics.protocols.HTTP)}%</strong></div>
            <div className="stat-item"><span className="legend-marker c-other">■</span> Other: <strong>{getPercentage(metrics.protocols.OTHER)}%</strong></div>
          </div>
        </div>

        <div className="panel-card double-width">
          <h3>Bandwidth Usage by Destination</h3>
          <table className="network-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Resolved Domain</th>
                <th>Transfer Size</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {(metrics.topIps || []).map((row) => (
                <tr key={row.ip}>
                  <td><code>{row.ip}</code></td>
                  <td className="domain-cell">{row.domain}</td>
                  <td>{row.formattedSize}</td>
                  <td>
                    <button 
                      onClick={() => setTargetInput(row.domain.includes('.') ? row.domain : row.ip)}
                      className="btn-action-small"
                    >
                      Quick Block
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel-card">
          <h3>Block Domain</h3>
          <form onSubmit={submitBlock}>
            <input 
              type="text" 
              placeholder="e.g. youtube.com" 
              value={targetInput} 
              onChange={(e) => setTargetInput(e.target.value)}
              className="form-input"
            />
            <button type="submit" className="btn-block-action">Add Firewall Rule</button>
          </form>

          <div className="active-blocks-container">
            <h4>Enforced Rules:</h4>
            <div className="scroll-list">
              {(!metrics.blockedDomains || !metrics.blockedDomains.length) ? (
                <p className="no-data-msg">No sites currently blocked</p>
              ) : (
                metrics.blockedDomains.map((rule, idx) => (
                  <div key={idx} className="rule-badge">
                    <span>{rule.target}</span>
                    <button onClick={() => removeBlock(rule.target)} className="btn-unblock-small">Remove</button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="panel-card full-width-card">
        <h3>System Event Log</h3>
        <div className="log-scroll">
          {(!metrics.alerts || !metrics.alerts.length) ? (
            <p className="no-data-msg">No logged events yet</p>
          ) : (
            metrics.alerts.map((log) => (
              <div key={log.id} className="log-row">
                <span className="log-time">[{log.timestamp}]</span>
                <span className={`status-badge ${log.type === 'ENFORCED' ? 'badge-red' : 'badge-green'}`}>{log.type}</span>
                <span className="log-text">{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export default App;