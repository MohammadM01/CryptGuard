export interface Flow {
  id: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  sni: string;
  ja3: string;
  
  // Metadata / Extracted Features
  totalPackets: number;
  totalBytes: number;
  avgPacketSize: number;
  packetSizeStdDev: number;
  
  // Timing Analysis
  iatMean: number;      // Inter-Arrival Time Mean
  iatStdDev: number;    // Inter-Arrival Time Std Dev
  periodicityScore: number; // 0.0 to 1.0 (Higher means more periodic/beacon-like)
  
  // Engine Conclusion
  riskScore: number;    // 0 to 100
  isAnomalous: boolean;
  timestamp: number;
}
