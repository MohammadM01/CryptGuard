import { useState, useEffect } from 'react';
import type { Flow } from '../types/flow';

export function useLiveTrafficStream(isActive: boolean) {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [stats, setStats] = useState({
    total: 0,
    benign: 0,
    anomalous: 0
  });

  useEffect(() => {
    if (!isActive) return;

    // Connect to Python FastAPI Backend
    const ws = new WebSocket('ws://localhost:8080/api/stream');

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data && data.flows) {
            
          setFlows(() => {
             // We want to merge updates or just take the backend's active list
             // The backend sends the full active table state currently.
             const newFlows = data.flows;
             
             // Update stats based on the latest flows snapshot
             let newAnomalous = 0;
             newFlows.forEach((f: Flow) => {
                 if (f.riskScore > 30) newAnomalous++;
             });
             
             setStats({
                 total: newFlows.length,
                 benign: newFlows.length - newAnomalous,
                 anomalous: newAnomalous
             });
             
             return newFlows;
          });
        }
      } catch (e) {
        console.error("Failed to parse live traffic stream:", e);
      }
    };

    ws.onerror = (error) => {
      console.error("WebSocket error. Ensure Python backend is running on port 8000.", error);
    };

    return () => {
      ws.close();
    };
  }, [isActive]);

  return { flows, stats };
}
