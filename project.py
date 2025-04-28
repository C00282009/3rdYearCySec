from flask import Flask, render_template, request
from pythonping import ping
import nmap3
import datetime
import re

def write_to_file(scan_type, ip_addr, results):
    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"scan_results_{ip_addr}.txt"
    with open(filename, "a") as f:
        f.write(f"Date: {timestamp} - ")
        f.write(f"Scan Type: {scan_type} - ")
        f.write(f"IP Address: {ip_addr}\n")
        f.write("Results:\n")
        for result in results:
            if isinstance(result, dict):
                f.write(f" Port: {result.get('port', 'N/A')} --- ")
                f.write(f" Protocol: {result.get('protocol', 'N/A')} --- ")
                f.write(f" Service: {result.get('service', 'N/A')} --- \n")
                if 'version' in result:
                    f.write(f" Version: {result.get('version', 'N/A')} --- \n")
                if 'accuracy' in result:
                    f.write(f" Accuracy: {result.get('accuracy', 'N/A')} --- \n")
                if 'details' in result:
                    f.write(f" Details: {result.get('details', 'N/A')}\n")
            else:
                f.write(f" {result}\n")
        f.write("\n")

app = Flask(__name__)
nmap = nmap3.Nmap()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/process", methods=["POST"])
def process_ping_or_scan():
    ip_addr = request.form["ip_address"]
    scan_type = request.form["scan_type"]

    if scan_type == "ping":
        response = ping(ip_addr, count=4, timeout=2)
        results = [f"Reply from {ip_addr}: time={resp.time_elapsed_ms:.2f}ms"
                   for resp in response if resp.success]
        if not results:
            results = ["No response received. Host may be unreachable."]
        write_to_file(scan_type, ip_addr, results)
        return render_template("results.html", scan_type="Ping Test",
                               ip_addr=ip_addr, results=results)

    elif scan_type == "syn":
        results = nmap.scan_top_ports(ip_addr, args="-sS")
        open_ports = process_nmap_results(results, ip_addr)
        write_to_file(scan_type, ip_addr, open_ports)
        return render_template("results.html", scan_type="SYN Scan",
                               ip_addr=ip_addr, results=open_ports)

    elif scan_type == "udp":
        results = nmap.scan_top_ports(ip_addr, args="-sU")
        open_ports = process_nmap_results(results, ip_addr)
        write_to_file(scan_type, ip_addr, open_ports)
        return render_template("results.html", scan_type="UDP Scan",
                               ip_addr=ip_addr, results=open_ports)

    elif scan_type == "version":
        try:
            results = nmap.scan_top_ports(ip_addr, args="-sV")
            open_ports = process_nmap_results(results, ip_addr, include_version=True)
            write_to_file(scan_type, ip_addr, open_ports)
            return render_template("results.html", scan_type="Version Detection Scan",
                                   ip_addr=ip_addr, results=open_ports)
        except Exception as e:
            return render_template("results.html", scan_type="Version Detection Scan",
                                   ip_addr=ip_addr, results=[{"port": "-", "protocol": "-",
                                   "service": f"Error: {str(e)}", "version": "N/A"}])

    elif scan_type == "os_detection":
        try:
            results = nmap.nmap_os_detection(ip_addr)
            os_results = process_os_detection_results(results, ip_addr)
            write_to_file(scan_type, ip_addr, os_results)
            return render_template("results.html", scan_type="OS Detection Scan",
                                   ip_addr=ip_addr, results=os_results)
        except Exception as e:
            return render_template("results.html", scan_type="OS Detection Scan",
                                   ip_addr=ip_addr, results=[{"port": "-", "protocol": "-",
                                   "service": f"Error: {str(e)}", "accuracy": "N/A"}])

    elif scan_type == "aggressive":
        try:
            results = nmap.scan_top_ports(ip_addr, args="-A")
            open_ports = process_nmap_results(results, ip_addr, include_version=True)
            write_to_file(scan_type, ip_addr, open_ports)
            return render_template("results.html", scan_type="Aggressive Scan",
                                   ip_addr=ip_addr, results=open_ports)
        except Exception as e:
            return render_template("results.html", scan_type="Aggressive Scan",
                                   ip_addr=ip_addr, results=[{"port": "-", "protocol": "-",
                                   "service": f"Error: {str(e)}", "version": "N/A"}])

    elif scan_type == "vuln":
        try:
            results = nmap.nmap_version_detection(ip_addr, args="--script=vuln")#--script-timeout 10m
            vuln_results = process_vulnerability_results(results, ip_addr)
            write_to_file(scan_type, ip_addr, vuln_results)
            return render_template("results.html", scan_type="Vulnerability Scan",
                                   ip_addr=ip_addr, results=vuln_results)
        except Exception as e:
            return render_template("results.html", scan_type="Vulnerability Scan",
                                   ip_addr=ip_addr, results=[{"port": "-", "protocol": "-",
                                   "service": f"Error: {str(e)}", "details": "N/A"}])

    elif scan_type == "vuln_cve":
        try:
            results = nmap.nmap_version_detection(ip_addr, args="-sV --script vulners --script-timeout 5m")#--script-timeout 10m
            cve_results = process_cve_results(results, ip_addr)
            write_to_file(scan_type, ip_addr, cve_results)
            return render_template("results.html", scan_type="CVE-Specific Scan",
                                   ip_addr=ip_addr, results=cve_results)
        except Exception as e:
            return render_template("results.html", scan_type="CVE-Specific Scan",
                                   ip_addr=ip_addr, results=[{"port": "-", "protocol": "-",
                                   "service": f"Error: {str(e)}", "details": "N/A"}])

def process_nmap_results(results, ip_addr, include_version=False):
    open_ports = []
    if ip_addr in results:
        for port in results.get(ip_addr, {}).get("ports", []):
            if port.get("state") == "open":
                port_info = {
                    "port": port["portid"],
                    "protocol": port["protocol"],
                    "service": port.get("service", {}).get("name", "Unknown")
                }
                if include_version:
                    port_info["version"] = port.get("service", {}).get("version", "Unknown")
                open_ports.append(port_info)
    if not open_ports:
        open_ports = [{"port": "-", "protocol": "-", "service": "No open ports found"}]
    return open_ports

def process_os_detection_results(results, ip_addr):
    os_results = []
    if ip_addr in results:
        os_info = results.get(ip_addr, {}).get("osmatch", [])
        for os in os_info:
            os_results.append({
                "port": "-",
                "protocol": "-",
                "service": os.get("name", "Unknown"),
                "accuracy": os.get("accuracy", "Unknown")
            })
    if not os_results:
        os_results = [{"port": "-", "protocol": "-", "service": "No OS detected", "accuracy": "N/A"}]
    return os_results

def process_vulnerability_results(results, ip_addr):
    vuln_results = []
    if ip_addr in results:
        for port in results.get(ip_addr, {}).get("ports", []):
            if port.get("state") == "open":
                vuln_results.append({
                    "port": port["portid"],
                    "protocol": port["protocol"],
                    "service": port.get("service", {}).get("name", "Unknown"),
                    "details": port.get("scripts", "No vulnerabilities found")
                })
    if not vuln_results:
        vuln_results = [{"port": "-", "protocol": "-", "service": "No vulnerabilities found", "details": "N/A"}]
    return vuln_results

def process_cve_results(results, ip_addr):
    cve_entries = []
    if ip_addr in results:
        for port in results[ip_addr].get("ports", []):
            if port.get("state") == "open":
                port_cves = set()
                for script in port.get("scripts", []):
                    if script.get("name") == "vulners":
                        for cpe_data in script.get("data", {}).values():
                            for entry in cpe_data.get("children", []):
                                if entry.get("type") == "cve":
                                    cve_id = entry.get("id", "")
                                    if cve_id.startswith("CVE-"):
                                        port_cves.add(cve_id)
                        output = script.get("output", "")
                        port_cves.update(re.findall(r'CVE-\d{4}-\d{4,7}', output))
                if port_cves:
                    cve_entries.append({
                        "port": port["portid"],
                        "protocol": port["protocol"],
                        "service": port.get("service", {}).get("name", "Unknown"),
                        "details": ", ".join(sorted(port_cves))
                    })
    if not cve_entries:
        cve_entries = [{"port": "-", "protocol": "-", "service": "No CVEs found", "details": "N/A"}]
    return cve_entries

if __name__ == "__main__":
    app.run(debug=True)
