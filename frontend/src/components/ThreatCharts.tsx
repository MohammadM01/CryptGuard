import { XAxis, YAxis, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';
import type { Flow } from '../types/flow';

interface Props {
  flows: Flow[];
  stats: { total: number, anomalous: number, benign: number };
}

export function ThreatCharts({ flows, stats }: Props) {
  // Take last 20 flows for the chart, reverse to chronological order
  const chartData = flows.slice(0, 20).reverse().map(f => ({
    time: f.timestamp,
    score: f.riskScore,
    periodicity: f.periodicityScore * 100 // mapped to 0-100 for visual comparison
  }));

  const threatLevel = stats.total === 0 ? 0 : Math.round((stats.anomalous / stats.total) * 100);

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {/* Gauge / Overview Card */}
      <div className="glass-panel rounded-xl p-6 flex flex-col justify-center items-center relative overflow-hidden">
        <div className="absolute top-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-accent to-transparent"></div>
        <h3 className="text-slate-400 font-mono text-sm uppercase tracking-wider mb-2">Network Threat Level</h3>
        <div className={`text-6xl font-bold font-mono tracking-tighter ${threatLevel > 15 ? 'text-cyber-alert cyber-glow-alert' : 'text-cyber-accent cyber-glow'}`}>
          {threatLevel}%
        </div>
        <p className="text-xs text-slate-500 mt-4 text-center">
          {threatLevel > 15 ? "High volume of anomalous beaconing detected." : "Traffic patterns normal. No C2 activity."}
        </p>
      </div>

      {/* Line Chart */}
      <div className="glass-panel rounded-xl p-6 md:col-span-2 flex flex-col">
        <h3 className="text-slate-400 font-mono text-sm uppercase tracking-wider mb-4">Risk & Periodicity Timeline</h3>
        <div className="flex-1 min-h-[150px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff0055" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#ff0055" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorPeriod" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="time" hide />
              <YAxis domain={[0, 100]} stroke="#334155" fontSize={10} tickFormatter={(val) => `${val}`} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px', fontFamily: 'monospace' }} 
                itemStyle={{ color: '#e2e8f0' }}
              />
              <Area type="monotone" dataKey="score" stroke="#ff0055" strokeWidth={2} fillOpacity={1} fill="url(#colorScore)" name="Risk Score" />
              <Area type="monotone" dataKey="periodicity" stroke="#00f0ff" strokeWidth={2} fillOpacity={1} fill="url(#colorPeriod)" name="Periodicity %" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
