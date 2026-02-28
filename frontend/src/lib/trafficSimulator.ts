import type { Flow } from '../types/flow';

// Mock Databases for realistic simulation
const BENIGN_SNI = [
  'google.com', 'outlook.office365.com', 'aws.amazon.com', 
  'github.com', 'slack-edge.com', 'zoom.us', 'wikipedia.org'
];

const MALICIOUS_SNI = [
  'update-server-sys.ru', 'cdn-metrics-tracker.xyz', 'auth-verify-portal.pw',
  'api-telemetry.onion.ws', 'cmd-broker.net', '188.166.x.x'
];

const BENIGN_JA3 = [
  '771,4865-4866-4867-49195-49199,0-11-10-35,23-24',
  '771,4865-4866-4867,0-5-10-11-13-35,45-43',
  '771,49195-49199-52393,0-10-11-13,23'
];

const MALICIOUS_JA3 = [
  '771,49192-49191-49172,0-11-10-13,23', // Trickbot style
  '771,49196-49195-49200,0-5-10-11,23',  // Cobalt Strike style
  '771,49199-49195-49200,65281-0-10-11,23' // Metasploit
];

/**
 * Utility to generate an IP
 */
const randomIp = () => `${Math.floor(Math.random()*200+10)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;

/**
 * Calculates a simple "periodicity" score based on the coefficient of variation of the inter-arrival times.
 * If IAT is perfectly periodic (like malware beaconing), standard deviation is very close to 0.
 * Therefore, cv = stdDev / mean.
 * Score = max(0, 1 - cv).
 * Thus, small stdDev -> Score approaches 1.0. High stdDev -> Score approaches 0.
 */
function calculatePeriodicityScore(iatMean: number, iatStdDev: number): number {
  if (iatMean === 0) return 0;
  const cv = iatStdDev / iatMean;
  // Non-linear mapping: if cv is < 0.2 (very regular), score is very high.
  // if cv is > 1.0 (very random/bursty), score is low.
  const score = Math.max(0, 1 - cv);
  // Curve it to emphasize strict beacons
  return Math.pow(score, 2); 
}

/**
 * Generates a mock flow
 */
export function generateFlow(isMalicious: boolean): Flow {
  const sourceIp = randomIp();
  const destinationIp = randomIp();
  const sourcePort = Math.floor(Math.random() * 50000) + 1024;
  const destinationPort = 443; // TLS
  
  // Benign traffic is bursty, highly variable sizes, varying IAT.
  // Malicious traffic is periodic (beaconing), uniform sizes, fixed IAT.
  
  let totalPackets, avgPacketSize, packetSizeStdDev, iatMean, iatStdDev;
  let sni, ja3;

  if (isMalicious) {
    // Beaconing Characteristics
    totalPackets = Math.floor(Math.random() * 50) + 10;
    avgPacketSize = Math.floor(Math.random() * 50) + 100; // Small, fixed size C2 check-ins
    packetSizeStdDev = Math.random() * 10; // Very little variation
    
    iatMean = 30 + Math.random() * 5; // e.g. every 30 seconds
    iatStdDev = Math.random() * 1.5; // Very tight variance (perfect beacon)
    
    sni = MALICIOUS_SNI[Math.floor(Math.random() * MALICIOUS_SNI.length)];
    ja3 = MALICIOUS_JA3[Math.floor(Math.random() * MALICIOUS_JA3.length)];

  } else {
    // Normal Web Browsing Characteristics
    totalPackets = Math.floor(Math.random() * 5000) + 50;
    avgPacketSize = Math.floor(Math.random() * 1000) + 300; // Larger varied payloads
    packetSizeStdDev = Math.floor(Math.random() * 500) + 100; // High variation
    
    iatMean = Math.random() * 5 + 0.1; // Rapid but random
    iatStdDev = iatMean * (1 + Math.random()); // StdDev > Mean (Poisson-like bursty traffic)
    
    sni = BENIGN_SNI[Math.floor(Math.random() * BENIGN_SNI.length)];
    ja3 = BENIGN_JA3[Math.floor(Math.random() * BENIGN_JA3.length)];
  }

  const periodicityScore = calculatePeriodicityScore(iatMean, iatStdDev);

  // Simulated ML Risk Scoring (Combining features)
  // In reality this would be Random Forest / XGBoost
  let riskScore = 0;
  
  // 1. Periodicity heavily impacts score
  riskScore += periodicityScore * 50; 
  
  // 2. Packet size uniformity (low std dev relative to mean)
  if (packetSizeStdDev / avgPacketSize < 0.2) riskScore += 20;

  // 3. Known JA3/SNI Threat Intel Match
  if (MALICIOUS_SNI.includes(sni)) riskScore += 20;
  if (MALICIOUS_JA3.includes(ja3)) riskScore += 10;

  // Add some jitter to the score
  riskScore += (Math.random() * 5);
  riskScore = Math.min(100, Math.floor(riskScore));

  const isAnomalous = riskScore > 75;

  return {
    id: Math.random().toString(36).substring(2, 9),
    sourceIp,
    destinationIp,
    sourcePort,
    destinationPort,
    protocol: 'TCP',
    sni,
    ja3,
    totalPackets,
    totalBytes: Math.floor(totalPackets * avgPacketSize),
    avgPacketSize: Math.floor(avgPacketSize),
    packetSizeStdDev: Number(packetSizeStdDev.toFixed(2)),
    iatMean: Number(iatMean.toFixed(2)),
    iatStdDev: Number(iatStdDev.toFixed(2)),
    periodicityScore: Number(periodicityScore.toFixed(3)),
    riskScore,
    isAnomalous,
    timestamp: Date.now()
  };
}
