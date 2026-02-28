import { useState } from 'react';
import { Shield, Play, Square, Activity } from 'lucide-react';
import { useLiveTrafficStream } from './hooks/useLiveTrafficStream';
import { LiveTrafficFeed } from './components/LiveTrafficFeed';
import { ThreatCharts } from './components/ThreatCharts';
import { PrivacyBadge } from './components/PrivacyBadge';

function App() {
  const [isActive, setIsActive] = useState(false);
  const { flows, stats } = useLiveTrafficStream(isActive);

  return (
    <div className="min-h-screen p-4 md:p-8 flex flex-col gap-6 max-w-7xl mx-auto">
      {/* Header element */}
      <header className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 py-4 border-b border-cyber-accent/20">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-cyber-dark glass-panel rounded-lg border-cyber-accent/50 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
            <Shield className="w-8 h-8 text-cyber-accent" />
          </div>
          <div>
            <h1 className="text-3xl font-black font-mono tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-white to-cyber-accent">
              OpenCryptGuard
            </h1>
            <p className="text-cyber-accent/70 font-mono text-sm uppercase tracking-widest mt-1">
              Behavioral Threat Intelligence
            </p>
          </div>
        </div>

        <div className="flex flex-col items-end gap-3">
          <PrivacyBadge />
          
          <button
            onClick={() => setIsActive(!isActive)}
            className={`flex items-center gap-2 px-6 py-2.5 rounded-full font-bold text-sm tracking-wider uppercase transition-all duration-300
              ${isActive 
                ? 'bg-cyber-alert/20 text-cyber-alert border border-cyber-alert/50 hover:bg-cyber-alert/30 hover:shadow-[0_0_20px_rgba(255,0,85,0.4)]' 
                : 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/50 hover:bg-cyber-accent/30 hover:shadow-[0_0_20px_rgba(0,240,255,0.4)]'
              }
            `}
          >
            {isActive ? <Square className="w-4 h-4 fill-current" /> : <Play className="w-4 h-4 fill-current" />}
            {isActive ? 'Halt Capture' : 'Initiate Scan'}
          </button>
        </div>
      </header>

      {/* Main Grid */}
      <main className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1">
        
        {/* Left Column: Visuals & Stats */}
        <div className="lg:col-span-4 flex flex-col gap-6">
          <ThreatCharts flows={flows} stats={stats} />
          
          {/* Detailed Statistics Tile */}
          <div className="glass-panel p-6 rounded-xl flex-1 border-t-2 border-t-cyber-accent/50">
            <h3 className="text-slate-400 font-mono text-xs uppercase tracking-wider mb-6 flex items-center gap-2">
              <Activity className="w-4 h-4" /> Global Metrics
            </h3>
            
            <div className="space-y-4 font-mono">
              <div className="flex justify-between items-end border-b border-white/5 pb-2">
                <span className="text-slate-500 text-sm">TOTAL FLOWS PROCESSED</span>
                <span className="text-2xl font-bold">{stats.total}</span>
              </div>
              <div className="flex justify-between items-end border-b border-white/5 pb-2">
                <span className="text-slate-500 text-sm">BENIGN TRAFFIC</span>
                <span className="text-xl text-cyber-success">{stats.benign}</span>
              </div>
              <div className="flex justify-between items-end pb-2">
                <span className="text-slate-500 text-sm">C2 BEACONS DETECTED</span>
                <span className="text-xl text-cyber-alert font-bold glow">{stats.anomalous}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Live Table */}
        <div className="lg:col-span-8">
          <LiveTrafficFeed flows={flows} />
        </div>

      </main>
      
      <footer className="mt-8 text-center text-xs font-mono text-slate-600">
        <p>Live Hackathon Mode active: The Python backend is currently analyzing Wireshark/NPcap network packets in real-time.</p>
        <p>Real-time JA3 Metadata Classification & IAT Analysis.</p>
      </footer>
    </div>
  );
}

export default App;
