import { useState, useEffect } from 'react';
import type { Flow } from '../types/flow';
import { generateFlow } from '../lib/trafficSimulator';

export function useTrafficStream(isActive: boolean) {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [stats, setStats] = useState({ total: 0, anomalous: 0, benign: 0 });

  useEffect(() => {
    if (!isActive) return;

    // Simulate real-time flow generation
    const interval = setInterval(() => {
      setFlows(prev => {
        // Maintain a rolling window of max 50 flows so memory doesn't explode
        const nextFlows = [...prev];
        if (nextFlows.length >= 50) nextFlows.pop();

        // 10% chance of a malicious flow for demo purposes
        const isMalicious = Math.random() < 0.1;
        const newFlow = generateFlow(isMalicious);

        // Update Stats
        setStats(s => ({
          total: s.total + 1,
          anomalous: newFlow.isAnomalous ? s.anomalous + 1 : s.anomalous,
          benign: !newFlow.isAnomalous ? s.benign + 1 : s.benign
        }));

        return [newFlow, ...nextFlows];
      });
    }, 1500); // New flow every 1.5s

    return () => clearInterval(interval);
  }, [isActive]);

  return { flows, stats };
}
