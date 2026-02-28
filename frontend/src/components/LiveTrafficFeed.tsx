import type { Flow } from '../types/flow';
import { AlertTriangle, CheckCircle, Activity } from 'lucide-react';

interface Props {
  flows: Flow[];
}

export function LiveTrafficFeed({ flows }: Props) {
  return (
    <div className="glass-panel rounded-xl overflow-hidden flex flex-col h-[600px]">
      <div className="bg-cyber-dark/80 px-6 py-4 border-b border-white/5 flex items-center justify-between">
        <h2 className="text-lg font-mono font-bold text-white flex items-center gap-2">
          <Activity className="text-cyber-accent w-5 h-5 animate-pulse" />
          LIVE ENCRYPTED TRAFFIC STREAM
        </h2>
        <span className="text-xs text-slate-400 font-mono">FLOW COUNT: {flows.length}</span>
      </div>
      
      <div className="flex-1 overflow-y-auto p-4">
        <table className="w-full text-left font-mono text-sm border-separate border-spacing-y-2">
          <thead>
            <tr className="text-slate-500 uppercase tracking-wider text-xs px-4">
              <th className="pb-2 font-medium">Source IP</th>
              <th className="pb-2 font-medium">Dest IP</th>
              <th className="pb-2 font-medium">SNI Match</th>
              <th className="pb-2 font-medium">JA3 Hash Fragment</th>
              <th className="pb-2 font-medium text-center">Score</th>
              <th className="pb-2 font-medium text-right">Status</th>
            </tr>
          </thead>
          <tbody>
            {flows.map((flow) => (
              <tr 
                key={flow.id} 
                className={`transition-all duration-300 animate-slide-up
                  ${flow.isAnomalous 
                    ? 'bg-cyber-alert/10 border-cyber-alert/50 text-red-200' 
                    : 'bg-white/5 border-white/10 text-slate-300 hover:bg-white/10'
                  } 
                  border rounded-lg shadow-sm
                `}
              >
                <td className="py-3 px-2 rounded-l-lg truncate max-w-[120px]" title={flow.sourceIp}>
                  {flow.sourceIp}:{flow.sourcePort}
                </td>
                <td className="py-3 px-2 truncate max-w-[120px]" title={flow.destinationIp}>
                  {flow.destinationIp}:{flow.destinationPort}
                </td>
                <td className="py-3 px-2 truncate max-w-[150px]" title={flow.sni}>
                  {flow.sni}
                </td>
                <td className="py-3 px-2 text-xs opacity-70 truncate max-w-[150px]" title={flow.ja3}>
                  {flow.ja3.substring(0, 16)}...
                </td>
                <td className="py-3 px-2 text-center">
                  <span className={`px-2 py-1 rounded inline-block min-w-[3rem] ${flow.riskScore > 75 ? 'bg-cyber-alert text-white font-bold' : 'bg-cyber-dark text-slate-400'}`}>
                    {flow.riskScore}
                  </span>
                </td>
                <td className="py-3 px-2 rounded-r-lg text-right">
                  {flow.isAnomalous ? (
                    <span className="flex items-center justify-end gap-1 text-cyber-alert font-bold">
                      <AlertTriangle className="w-4 h-4 animate-ping-slow" />
                      BEACON DETECTED
                    </span>
                  ) : (
                    <span className="flex items-center justify-end gap-1 text-cyber-success/80">
                      <CheckCircle className="w-4 h-4" />
                      BENIGN
                    </span>
                  )}
                </td>
              </tr>
            ))}
            {flows.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center py-10 text-slate-500 italic">
                  Awaiting traffic capture...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
