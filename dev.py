import subprocess
import sys
import time

def main():
    print("========================================")
    print("Starting CryptGuard Services perfectly in your terminal...")
    print("Press Ctrl+C to stop all services.")
    print("========================================")

    processes = []

    # Start Frontend
    print("[1/3] Starting React Frontend...")
    frontend = subprocess.Popen("cd frontend && npm run dev", shell=True)
    processes.append(("Frontend", frontend))

    # Start Backend
    print("[2/3] Starting FastAPI Backend...")
    backend = subprocess.Popen("cd backend && call venv\\Scripts\\activate && python main.py", shell=True)
    processes.append(("Backend", backend))

    # Start DPI Engine
    print("[3/3] Starting C++ DPI Engine...")
    dpi = subprocess.Popen("cd Packet_analyzer && python generate_test_pcap.py && dpi_engine.exe test_dpi.pcap output.pcap", shell=True)
    processes.append(("DPI Engine", dpi))

    try:
        # Keep the main thread alive to catch Ctrl+C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n========================================")
        print("Shutting down CryptGuard services...")
        print("========================================")
        for name, p in processes:
            p.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
