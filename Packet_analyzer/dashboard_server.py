import subprocess
import re
import json
import http.server
import socketserver
from urllib.parse import urlparse
import threading

PORT = 8000
DIRECTORY = "."

def run_dpi_engine():
    """Runs the DPI engine and parses its output into a JSON structure."""
    try:
        # Run the DPI engine and capture the output
        result = subprocess.run(
            ['.\\dpi_engine_simple.exe', 'test_dpi.pcap', 'output.pcap'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            check=True
        )
        
        output = result.stdout
        
        # Initialize parsed data structure
        data = {
            "metrics": {
                "total_packets": 0,
                "forwarded": 0,
                "dropped": 0,
                "active_flows": 0
            },
            "application_breakdown": [],
            "detected_domains": []
        }
        
        # Parse metrics
        metrics_match = re.search(r"Total Packets:\s+(\d+).*?Forwarded:\s+(\d+).*?Dropped:\s+(\d+).*?Active Flows:\s+(\d+)", output, re.DOTALL)
        if metrics_match:
            data["metrics"]["total_packets"] = int(metrics_match.group(1))
            data["metrics"]["forwarded"] = int(metrics_match.group(2))
            data["metrics"]["dropped"] = int(metrics_match.group(3))
            data["metrics"]["active_flows"] = int(metrics_match.group(4))
            
        # Parse application breakdown
        # Find the block between APPLICATION BREAKDOWN and the next box
        app_block_match = re.search(r"APPLICATION BREAKDOWN.*?\u2560.*?\n(.*?)\u255A", output, re.DOTALL)
        if app_block_match:
            app_lines = app_block_match.group(1).strip().split('\n')
            for line in app_lines:
                # Match lines like "║ HTTPS                39  50.6% ##########            ║"
                match = re.search(r"\u2551\s+([A-Za-z/]+)\s+(\d+)\s+([\d.]+)%", line)
                if match:
                    data["application_breakdown"].append({
                        "name": match.group(1),
                        "count": int(match.group(2)),
                        "percentage": float(match.group(3))
                    })
                    
        # Parse detected domains
        domain_block_match = re.search(r"\[Detected Applications/Domains\]\n(.*?)Output", output, re.DOTALL)
        if domain_block_match:
            domain_lines = domain_block_match.group(1).strip().split('\n')
            for line in domain_lines:
                match = re.search(r"-\s+(.*?)\s+->\s+(.*)", line)
                if match:
                    data["detected_domains"].append({
                        "domain": match.group(1).strip(),
                        "app": match.group(2).strip()
                    })

        return data
    except Exception as e:
        return {"error": str(e)}

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/api/analyze':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Run engine and return JSON
            data = run_dpi_engine()
            self.wfile.write(json.dumps(data).encode('utf-8'))
        elif parsed_path.path == '/' or parsed_path.path == '/index.html':
            self.path = '/dashboard.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        else:
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

if __name__ == "__main__":
    from functools import partial
    
    Handler = partial(CustomHandler, directory=DIRECTORY)
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"DPI Dashboard Server running at http://localhost:{PORT}")
        print(f"Press Ctrl+C to stop.")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
