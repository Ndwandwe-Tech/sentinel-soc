import express from 'express';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const httpServer = createServer(app);
  const wss = new WebSocketServer({ server: httpServer });
  const PORT = 3000;

  app.use(express.json());

  // In-memory state for simulation
  let blockedIPs: Set<string> = new Set();
  let trafficLogs: any[] = [];
  let alerts: any[] = [];

  // WebSocket connection handling
  wss.on('connection', (ws) => {
    console.log('Client connected to WebSocket');
    ws.send(JSON.stringify({ type: 'INIT', message: 'Connected to Sentinel SOC' }));
  });

  const broadcast = (data: any) => {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  };

  // API Endpoints
  app.get('/api/traffic', (req, res) => {
    res.json(trafficLogs.slice(-100));
  });

  app.get('/api/alerts', (req, res) => {
    res.json(alerts.slice(-50));
  });

  app.post('/api/block-ip', (req, res) => {
    const { ip, reason } = req.body;
    if (ip) {
      blockedIPs.add(ip);
      const alert = {
        id: Date.now().toString(),
        threat_type: 'Manual Block',
        severity: 'High',
        source_ip: ip,
        timestamp: new Date().toISOString(),
        status: 'Blocked',
        details: reason || 'Blocked by administrator'
      };
      alerts.push(alert);
      broadcast({ type: 'ALERT', data: alert });
      res.json({ success: true, message: `IP ${ip} blocked` });
    } else {
      res.status(400).json({ error: 'IP is required' });
    }
  });

  // Traffic Simulation & Anomaly Detection
  const protocols = ['TCP', 'UDP', 'SSH', 'HTTP', 'HTTPS', 'DNS', 'FTP'];
  const commonIPs = ['192.168.1.1', '192.168.1.5', '10.0.0.15', '172.16.0.22'];
  
  setInterval(() => {
    // Generate normal traffic
    const sourceIp = commonIPs[Math.floor(Math.random() * commonIPs.length)];
    const destIp = `10.0.0.${Math.floor(Math.random() * 255)}`;
    
    if (blockedIPs.has(sourceIp)) return;

    const log = {
      id: Math.random().toString(36).substr(2, 9),
      source_ip: sourceIp,
      destination_ip: destIp,
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      packet_size: Math.floor(Math.random() * 1500),
      timestamp: new Date().toISOString(),
      connection_count: 1
    };

    trafficLogs.push(log);
    if (trafficLogs.length > 1000) trafficLogs.shift();
    broadcast({ type: 'TRAFFIC', data: log });

    // Occasional Anomaly Simulation
    if (Math.random() > 0.95) {
      simulateAnomaly();
    }
  }, 1000);

  function simulateAnomaly() {
    const anomalyTypes = [
      { type: 'Brute Force', severity: 'High', details: 'High frequency SSH connection attempts detected.' },
      { type: 'DDoS', severity: 'Critical', details: 'Abnormal packet burst from single source.' },
      { type: 'Port Scan', severity: 'Medium', details: 'Sequential port probing detected.' },
      { type: 'Buffer Overflow', severity: 'Critical', details: 'Unusually large packet payload detected.' }
    ];

    const anomaly = anomalyTypes[Math.floor(Math.random() * anomalyTypes.length)];
    const sourceIp = `45.33.10.${Math.floor(Math.random() * 255)}`;
    
    if (blockedIPs.has(sourceIp)) return;

    const alert = {
      id: Date.now().toString(),
      threat_type: anomaly.type,
      severity: anomaly.severity,
      source_ip: sourceIp,
      timestamp: new Date().toISOString(),
      status: 'Active',
      details: anomaly.details
    };

    alerts.push(alert);
    if (alerts.length > 100) alerts.shift();
    broadcast({ type: 'ALERT', data: alert });
  }

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Sentinel SOC Server running on http://localhost:${PORT}`);
  });
}

startServer();
