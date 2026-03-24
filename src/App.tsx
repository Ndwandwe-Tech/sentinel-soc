import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Lock, 
  Server, 
  BarChart3, 
  LogOut, 
  Search, 
  Filter, 
  Wifi, 
  WifiOff,
  ChevronRight,
  Database,
  Globe,
  Trash2,
  Ban,
  Mail,
  UserPlus
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Chart as ChartJS, 
  CategoryScale, 
  LinearScale, 
  PointElement, 
  LineElement, 
  Title, 
  Tooltip, 
  Legend, 
  Filler,
  BarElement
} from 'chart.js';
import { Line, Bar } from 'react-chartjs-2';
import { format } from 'date-fns';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

import { 
  auth, 
  db, 
  googleProvider, 
  signInWithPopup, 
  signOut, 
  onAuthStateChanged, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  collection, 
  onSnapshot, 
  addDoc, 
  deleteDoc, 
  doc, 
  query, 
  orderBy, 
  limit,
  User,
  getDocs,
  setDoc
} from './lib/firebase';

ChartJS.register(
  CategoryScale, 
  LinearScale, 
  PointElement, 
  LineElement, 
  BarElement,
  Title, 
  Tooltip, 
  Legend, 
  Filler
);

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Types ---

interface TrafficLog {
  id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  packet_size: number;
  timestamp: string;
  connection_count: number;
}

interface Alert {
  id: string;
  threat_type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  source_ip: string;
  timestamp: string;
  status: 'Active' | 'Blocked' | 'Resolved';
  details: string;
}

interface BlockedIP {
  id: string;
  ip_address: string;
  blocked_at: string;
  reason: string;
}

// --- Components ---

const StatCard = ({ title, value, icon: Icon, color, trend }: any) => (
  <motion.div 
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl flex items-center justify-between"
  >
    <div>
      <p className="text-zinc-500 text-sm font-medium mb-1">{title}</p>
      <h3 className="text-2xl font-bold text-white">{value}</h3>
      {trend && (
        <p className={cn("text-xs mt-1", trend > 0 ? "text-emerald-500" : "text-rose-500")}>
          {trend > 0 ? '+' : ''}{trend}% from last hour
        </p>
      )}
    </div>
    <div className={cn("p-3 rounded-xl bg-opacity-10", color)}>
      <Icon className={cn("w-6 h-6", color.replace('bg-', 'text-'))} />
    </div>
  </motion.div>
);

interface AlertItemProps {
  alert: Alert;
  onBlock: (ip: string) => void | Promise<void>;
}

const AlertItem: React.FC<AlertItemProps> = ({ alert, onBlock }) => {
  const severityColors = {
    Low: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
    Medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
    High: 'text-orange-400 bg-orange-400/10 border-orange-400/20',
    Critical: 'text-rose-400 bg-rose-400/10 border-rose-400/20',
  };

  return (
    <motion.div 
      layout
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="p-4 bg-zinc-900/30 border border-zinc-800 rounded-xl mb-3 flex items-start gap-4"
    >
      <div className={cn("p-2 rounded-lg border", severityColors[alert.severity])}>
        <AlertTriangle className="w-5 h-5" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <h4 className="font-bold text-white truncate">{alert.threat_type}</h4>
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider">
            {format(new Date(alert.timestamp), 'HH:mm:ss')}
          </span>
        </div>
        <p className="text-sm text-zinc-400 mb-2 line-clamp-2">{alert.details}</p>
        <div className="flex items-center justify-between">
          <code className="text-xs text-zinc-500 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800">
            {alert.source_ip}
          </code>
          {alert.status === 'Active' && (
            <button 
              onClick={() => onBlock(alert.source_ip)}
              className="text-[10px] font-bold uppercase tracking-widest text-rose-500 hover:text-rose-400 transition-colors"
            >
              Block IP
            </button>
          )}
          {alert.status === 'Blocked' && (
            <span className="text-[10px] font-bold uppercase tracking-widest text-zinc-600">
              Blocked
            </span>
          )}
        </div>
      </div>
    </motion.div>
  );
};

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [traffic, setTraffic] = useState<TrafficLog[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([]);
  const [wsStatus, setWsStatus] = useState<'connecting' | 'open' | 'closed'>('connecting');
  
  // Email Auth State
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSigningUp, setIsSigningUp] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  // --- Auth ---

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setLoading(false);
    });
    return () => unsubscribe();
  }, []);

  const handleLogin = async () => {
    setAuthError(null);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (error: any) {
      console.error('Login error:', error);
      setAuthError(error.message);
    }
  };

  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    try {
      if (isSigningUp) {
        await createUserWithEmailAndPassword(auth, email, password);
      } else {
        await signInWithEmailAndPassword(auth, email, password);
      }
    } catch (error: any) {
      console.error('Email auth error:', error);
      setAuthError(error.message);
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  // --- Real-time Data (WebSockets) ---

  useEffect(() => {
    if (!user) return;

    const connectWS = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${protocol}//${window.location.host}`);
      wsRef.current = ws;

      ws.onopen = () => setWsStatus('open');
      ws.onclose = () => {
        setWsStatus('closed');
        setTimeout(connectWS, 3000); // Reconnect
      };
      
      ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === 'TRAFFIC') {
          setTraffic(prev => [message.data, ...prev].slice(0, 50));
        } else if (message.type === 'ALERT') {
          setAlerts(prev => [message.data, ...prev].slice(0, 50));
          // Persist to Firestore if admin
          if (user.email === 'LBmkhatshwa@gmail.com') {
            addDoc(collection(db, 'alerts'), message.data).catch(console.error);
          }
        }
      };
    };

    connectWS();
    return () => wsRef.current?.close();
  }, [user]);

  // --- Firestore Sync ---

  useEffect(() => {
    if (!user) return;

    const qAlerts = query(collection(db, 'alerts'), orderBy('timestamp', 'desc'), limit(50));
    const unsubAlerts = onSnapshot(qAlerts, (snapshot) => {
      const data = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Alert));
      setAlerts(data);
    });

    const qBlocked = query(collection(db, 'blocked_ips'), orderBy('blocked_at', 'desc'));
    const unsubBlocked = onSnapshot(qBlocked, (snapshot) => {
      const data = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as BlockedIP));
      setBlockedIPs(data);
    });

    return () => {
      unsubAlerts();
      unsubBlocked();
    };
  }, [user]);

  // --- Actions ---

  const blockIP = async (ip: string) => {
    if (!user || user.email !== 'LBmkhatshwa@gmail.com') return;

    try {
      // 1. Update Backend
      await fetch('/api/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason: 'Automated threat detection' })
      });

      // 2. Persist to Firestore
      await addDoc(collection(db, 'blocked_ips'), {
        ip_address: ip,
        blocked_at: new Date().toISOString(),
        reason: 'Security Anomaly'
      });

      // 3. Update alert status in Firestore if it exists
      const alertToUpdate = alerts.find(a => a.source_ip === ip && a.status === 'Active');
      if (alertToUpdate) {
        await setDoc(doc(db, 'alerts', alertToUpdate.id), { ...alertToUpdate, status: 'Blocked' });
      }
    } catch (error) {
      console.error('Error blocking IP:', error);
    }
  };

  // --- Chart Data ---

  const trafficChartData = useMemo(() => {
    const labels = Array.from({ length: 10 }, (_, i) => format(new Date(Date.now() - (9 - i) * 10000), 'HH:mm:ss'));
    return {
      labels,
      datasets: [
        {
          label: 'Throughput (KB/s)',
          data: labels.map(() => Math.floor(Math.random() * 800) + 200),
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 0,
        }
      ]
    };
  }, [traffic]);

  const attackFreqData = useMemo(() => {
    const types = ['Brute Force', 'DDoS', 'Port Scan', 'Buffer Overflow'];
    return {
      labels: types,
      datasets: [
        {
          label: 'Attack Frequency',
          data: types.map(t => alerts.filter(a => a.threat_type === t).length),
          backgroundColor: [
            'rgba(244, 63, 94, 0.6)',
            'rgba(249, 115, 22, 0.6)',
            'rgba(234, 179, 8, 0.6)',
            'rgba(139, 92, 246, 0.6)',
          ],
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
        }
      ]
    };
  }, [alerts]);

  // --- Render Helpers ---

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Shield className="w-12 h-12 text-emerald-500 animate-pulse" />
          <p className="text-zinc-500 font-mono text-sm tracking-widest uppercase">Initializing Sentinel SOC...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-6">
        <motion.div 
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="max-w-md w-full bg-zinc-900 border border-zinc-800 p-8 rounded-3xl text-center"
        >
          <div className="w-20 h-20 bg-emerald-500/10 rounded-2xl flex items-center justify-center mx-auto mb-6 border border-emerald-500/20">
            <Shield className="w-10 h-10 text-emerald-500" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Sentinel SOC</h1>
          <p className="text-zinc-400 mb-8">Access the next-generation cybersecurity monitoring platform.</p>
          
          <form onSubmit={handleEmailAuth} className="space-y-4 mb-6">
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input 
                type="email" 
                placeholder="Email Address" 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full bg-zinc-950 border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-sm focus:outline-none focus:border-emerald-500/50 transition-all text-white"
              />
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input 
                type="password" 
                placeholder="Password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-zinc-950 border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-sm focus:outline-none focus:border-emerald-500/50 transition-all text-white"
              />
            </div>
            
            {authError && (
              <p className="text-xs text-rose-500 text-left px-1">{authError}</p>
            )}

            <button 
              type="submit"
              className="w-full bg-emerald-600 text-white font-bold py-3 rounded-xl hover:bg-emerald-500 transition-colors flex items-center justify-center gap-2"
            >
              {isSigningUp ? <UserPlus className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
              {isSigningUp ? 'Create Account' : 'Sign In'}
            </button>
          </form>

          <div className="flex items-center gap-4 mb-6">
            <div className="h-px bg-zinc-800 flex-1" />
            <span className="text-[10px] text-zinc-600 uppercase tracking-widest font-bold">Or continue with</span>
            <div className="h-px bg-zinc-800 flex-1" />
          </div>

          <button 
            onClick={handleLogin}
            className="w-full bg-white text-black font-bold py-3 rounded-xl hover:bg-zinc-200 transition-colors flex items-center justify-center gap-3"
          >
            <Globe className="w-5 h-5" />
            Google Account
          </button>

          <button 
            onClick={() => setIsSigningUp(!isSigningUp)}
            className="mt-6 text-xs text-zinc-500 hover:text-white transition-colors"
          >
            {isSigningUp ? 'Already have an account? Sign In' : "Don't have an account? Create one"}
          </button>

          <p className="mt-8 text-[10px] text-zinc-600 uppercase tracking-widest font-bold">
            Authorized personnel only
          </p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] text-zinc-300 font-sans">
      {/* --- Sidebar --- */}
      <aside className="fixed left-0 top-0 bottom-0 w-20 bg-zinc-950 border-r border-zinc-900 flex flex-col items-center py-8 gap-8 z-50">
        <div className="p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/20">
          <Shield className="w-6 h-6 text-emerald-500" />
        </div>
        
        <nav className="flex-1 flex flex-col gap-6">
          <button className="p-3 text-emerald-500 bg-emerald-500/10 rounded-xl"><BarChart3 className="w-6 h-6" /></button>
          <button className="p-3 text-zinc-600 hover:text-white transition-colors"><Activity className="w-6 h-6" /></button>
          <button className="p-3 text-zinc-600 hover:text-white transition-colors"><Database className="w-6 h-6" /></button>
          <button className="p-3 text-zinc-600 hover:text-white transition-colors"><Lock className="w-6 h-6" /></button>
        </nav>

        <button 
          onClick={handleLogout}
          className="p-3 text-zinc-600 hover:text-rose-500 transition-colors"
        >
          <LogOut className="w-6 h-6" />
        </button>
      </aside>

      {/* --- Main Content --- */}
      <main className="pl-20 min-h-screen">
        {/* Header */}
        <header className="h-20 border-b border-zinc-900 flex items-center justify-between px-8 sticky top-0 bg-[#050505]/80 backdrop-blur-xl z-40">
          <div className="flex items-center gap-4">
            <h2 className="text-xl font-bold text-white tracking-tight">Security Operations Center</h2>
            <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800">
              <div className={cn("w-2 h-2 rounded-full animate-pulse", wsStatus === 'open' ? "bg-emerald-500" : "bg-rose-500")} />
              <span className="text-[10px] uppercase tracking-widest font-bold text-zinc-500">
                {wsStatus === 'open' ? 'Live System' : 'System Offline'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input 
                type="text" 
                placeholder="Search threats, IPs, logs..." 
                className="bg-zinc-900 border border-zinc-800 rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-emerald-500/50 w-64 transition-all"
              />
            </div>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-xs font-bold text-white">{user.displayName}</p>
                <p className="text-[10px] text-zinc-600 uppercase tracking-tighter">Senior Analyst</p>
              </div>
              <img src={user.photoURL || ''} className="w-10 h-10 rounded-xl border border-zinc-800" referrerPolicy="no-referrer" />
            </div>
          </div>
        </header>

        <div className="p-8 max-w-[1600px] mx-auto">
          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard title="Total Traffic" value={`${(traffic.length * 1.2).toFixed(1)} GB`} icon={Globe} color="bg-blue-500" trend={12} />
            <StatCard title="Active Threats" value={alerts.filter(a => a.status === 'Active').length} icon={AlertTriangle} color="bg-rose-500" trend={-5} />
            <StatCard title="Blocked IPs" value={blockedIPs.length} icon={Ban} color="bg-orange-500" trend={2} />
            <StatCard title="System Health" value="99.9%" icon={Server} color="bg-emerald-500" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Column: Charts & Logs */}
            <div className="lg:col-span-2 space-y-8">
              {/* Main Chart */}
              <div className="bg-zinc-900/50 border border-zinc-800 p-6 rounded-3xl">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-bold text-white flex items-center gap-2">
                    <Activity className="w-4 h-4 text-emerald-500" />
                    Network Throughput
                  </h3>
                  <select className="bg-zinc-950 border border-zinc-800 text-xs rounded-lg px-2 py-1 outline-none">
                    <option>Real-time</option>
                    <option>Last Hour</option>
                  </select>
                </div>
                <div className="h-[300px]">
                  <Line 
                    data={trafficChartData} 
                    options={{ 
                      responsive: true, 
                      maintainAspectRatio: false,
                      scales: {
                        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#52525b' } },
                        x: { grid: { display: false }, ticks: { color: '#52525b' } }
                      },
                      plugins: { legend: { display: false } }
                    }} 
                  />
                </div>
              </div>

              {/* Traffic Logs Table */}
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden">
                <div className="p-6 border-b border-zinc-800 flex items-center justify-between">
                  <h3 className="font-bold text-white flex items-center gap-2">
                    <Database className="w-4 h-4 text-blue-500" />
                    Live Traffic Logs
                  </h3>
                  <button className="text-xs text-zinc-500 hover:text-white flex items-center gap-1">
                    <Filter className="w-3 h-3" /> Filter
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="text-zinc-500 border-b border-zinc-800/50">
                        <th className="px-6 py-4 font-medium">Timestamp</th>
                        <th className="px-6 py-4 font-medium">Source IP</th>
                        <th className="px-6 py-4 font-medium">Protocol</th>
                        <th className="px-6 py-4 font-medium">Size</th>
                        <th className="px-6 py-4 font-medium">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      <AnimatePresence mode="popLayout">
                        {traffic.slice(0, 10).map((log) => (
                          <motion.tr 
                            key={log.id}
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="border-b border-zinc-800/30 hover:bg-white/[0.02] transition-colors"
                          >
                            <td className="px-6 py-4 text-zinc-500 font-mono text-xs">
                              {format(new Date(log.timestamp), 'HH:mm:ss')}
                            </td>
                            <td className="px-6 py-4">
                              <span className="text-white font-mono">{log.source_ip}</span>
                            </td>
                            <td className="px-6 py-4">
                              <span className="px-2 py-0.5 rounded bg-zinc-800 text-[10px] font-bold text-zinc-400">
                                {log.protocol}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-zinc-400">{log.packet_size} B</td>
                            <td className="px-6 py-4">
                              <button 
                                onClick={() => blockIP(log.source_ip)}
                                className="p-1.5 hover:bg-rose-500/10 hover:text-rose-500 rounded-lg transition-colors text-zinc-600"
                              >
                                <Ban className="w-4 h-4" />
                              </button>
                            </td>
                          </motion.tr>
                        ))}
                      </AnimatePresence>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Right Column: Alerts & Attack Frequency */}
            <div className="space-y-8">
              {/* Alerts Feed */}
              <div className="bg-zinc-900/50 border border-zinc-800 p-6 rounded-3xl flex flex-col h-[600px]">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-bold text-white flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-500" />
                    Threat Intel Feed
                  </h3>
                  <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-500 text-[10px] font-bold uppercase">
                    Live
                  </span>
                </div>
                <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                  <AnimatePresence mode="popLayout">
                    {alerts.length === 0 ? (
                      <div className="h-full flex flex-col items-center justify-center text-zinc-600 gap-3">
                        <Shield className="w-8 h-8 opacity-20" />
                        <p className="text-xs">No active threats detected</p>
                      </div>
                    ) : (
                      alerts.map((alert) => (
                        <AlertItem key={alert.id} alert={alert} onBlock={blockIP} />
                      ))
                    )}
                  </AnimatePresence>
                </div>
              </div>

              {/* Attack Frequency Chart */}
              <div className="bg-zinc-900/50 border border-zinc-800 p-6 rounded-3xl">
                <h3 className="font-bold text-white mb-6 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-yellow-500" />
                  Attack Vectors
                </h3>
                <div className="h-[200px]">
                  <Bar 
                    data={attackFreqData}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      scales: {
                        y: { display: false },
                        x: { grid: { display: false }, ticks: { color: '#52525b', font: { size: 10 } } }
                      },
                      plugins: { legend: { display: false } }
                    }}
                  />
                </div>
              </div>

              {/* Blocked IPs List */}
              <div className="bg-zinc-900/50 border border-zinc-800 p-6 rounded-3xl">
                <h3 className="font-bold text-white mb-4 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-orange-500" />
                  Recent Blocks
                </h3>
                <div className="space-y-3">
                  {blockedIPs.slice(0, 5).map((ip) => (
                    <div key={ip.id} className="flex items-center justify-between text-xs p-3 bg-zinc-950 rounded-xl border border-zinc-800/50">
                      <div className="flex items-center gap-3">
                        <Ban className="w-3 h-3 text-rose-500" />
                        <span className="font-mono text-zinc-400">{ip.ip_address}</span>
                      </div>
                      <span className="text-zinc-600">{format(new Date(ip.blocked_at), 'MMM d, HH:mm')}</span>
                    </div>
                  ))}
                  {blockedIPs.length === 0 && (
                    <p className="text-center text-zinc-600 text-xs py-4 italic">No blocked IPs</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #27272a;
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #3f3f46;
        }
      `}</style>
    </div>
  );
}
