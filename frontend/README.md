# OpenCryptGuard - MVP Hackathon Demo

## 🛡️ Privacy-Preserving Behavioral Threat Detection Framework

**OpenCryptGuard** is a next-generation cybersecurity dashboard designed to detect Malware Command & Control (C2) communication concealed within encrypted traffic (HTTPS/TLS) **without requiring SSL decryption.**

Most traditional systems break privacy by decrypting traffic. OpenCryptGuard acts natively on traffic metadata, maintaining 100% compliance with privacy laws like the DPDP Act and GDPR.

### 🌟 Key Innovations Presented in this MVP

1. **Zero-Decryption Analysis:** Analyzes behavioral patterns including:
   - Inter-Arrival Time (IAT)
   - Packet Size Variance and Mean
   - Upload / Download Ratios
2. **Beaconing Detection Module:** Malware naturally communicates in strict periodic patterns (beacons). This engine uses autocorrelation variance math to generate a "Periodicity Score" identifying hidden C2 heartbeats.
3. **Advanced Threat Intel Matching:** Extracts and hashes TLS Handshake features natively (Server Name Indication `SNI`, and `JA3` fingerprinting) to flag known malicious clients trying to hide behind TLS layers.
4. **Real-time Threat Graphing:** Visualizes the "Entropy vs. Probability" using live React charting systems.

### 🚀 Running the Demo

Due to hackathon deployment constraints on serverless platforms (like Vercel), this MVP utilizes a **Pure-Frontend Mathematical Simulation Engine**. Deep within the React application, the `trafficSimulator.ts` perfectly mimics a C++ DPI engine aggregating 5-tuple flows, providing the identical mathematical variance and behavior required to demonstrate our detection concept live.

Start the demo:

```bash
npm install
npm run dev
```

Click **Initiate Scan** to watch the Behavioral Engine extract flows, compute periodicity limits, and flag malicious traffic based on JA3 anomalies and IAT standard deviations in real-time.

---

_Built for National Level Hackathons_
