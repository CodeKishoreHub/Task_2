from pdb import run
from flask import Flask, render_template, request
import nmap, requests
import socket
from regex import F
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])

def home():
    results = None
    if request.method == "POST":
        target = request.form.get("target")  
        if target:
            results = run_audit(target)  # Collect output from your function
    return render_template("index.html", results=results)


# ---------- Port Scanner ----------
def identify_open_ports(host_address):
    result = []
    port_map = nmap.PortScanner()
    port_map.scan(host_address, '1-1024')

    for endpoint in port_map.all_hosts():
        result.append(f"\n[🎯] Target IP: {endpoint} ({port_map[endpoint].hostname()})")
        result.append(f"    Status: {port_map[endpoint].state()}")
        for proto in port_map[endpoint].all_protocols():
            ports = port_map[endpoint][proto].keys()
            for p in sorted(ports):
                state = port_map[endpoint][proto][p]['state']
                result.append(f"    - {proto.upper()} Port {p}: {state}")
    return "\n".join(result)

# ---------- Header Probe ----------
def probe_service_header(ip_or_host, service_port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(4)
        client_socket.connect((ip_or_host, service_port))
        header_request = f"HEAD / HTTP/1.1\r\nHost: {ip_or_host}\r\n\r\n"
        client_socket.send(header_request.encode())
        server_reply = client_socket.recv(1024)
        client_socket.close()
        return "    - Response Header:\n" + server_reply.decode(errors='ignore').strip()
    except socket.timeout:
        return "    - Connection attempt timed out."
    except Exception as ex:
        return f"    - Error occurred: {ex}"

# ---------- Directory Listing Check ----------
def inspect_directory_listing(site_url):
    try:
        if not site_url.startswith(('http://', 'https://')):
            site_url = 'http://' + site_url
        response = requests.get(site_url, timeout=5)
        if "Index of" in response.text:
            return "    - Directory listing appears ENABLED."
        else:
            return "    - Directory listing appears DISABLED."
    except requests.RequestException as err:
        return f"    - Could not access site: {err}"

# ---------- Vulnerability Scanner ----------

def extract_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except:
        return []

def submit_form(form, url, value):
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")
    data = {}

    for i in inputs:
        name = i.get("name")
        t = i.get("type", "text")
        if name:
            data[name] = value if t == "text" else i.get("value", "")

    submit_url = urljoin(url, action)
    try:
        if method == "post":
            return requests.post(submit_url, data=data)
        else:
            return requests.get(submit_url, params=data)
    except:
        return None

def detect_sql_injection(url):
    payload = "' OR '1'='1"
    try:
        response = requests.get(url + payload)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            return True
    except:
        pass
    return False

def detect_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    forms = extract_forms(url)
    vulnerable = False
    for form in forms:
        res = submit_form(form, url, xss_payload)
        if res and xss_payload in res.text:
            vulnerable = True
    return vulnerable

def run_web_vulnerability_scan(target_url):
    messages = []
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    messages.append(f"    - Testing for SQL Injection on {target_url}...")
    if detect_sql_injection(target_url):
        messages.append("🔴 SQL Injection Vulnerability Detected!")
    else:
        messages.append("🟢 No SQL Injection Detected.")

    messages.append(f"    - Testing for XSS on {target_url}...")
    if detect_xss(target_url):
        messages.append("🔴 XSS Vulnerability Detected!")
    else:
        messages.append("🟢 No XSS Detected.")
    
    return "\n".join(messages)


# ---------- Main ----------
def start_audit():
    print("===================================")
    print("   🔍 Network Inspector Tool")
    print("===================================\n")

    target_input = input("Enter target domain or IP (e.g., example.com or 192.168.1.1): ").strip()
    clean_host = target_input.replace("http://", "").replace("https://", "").rstrip("/")

    print("\n[1] Starting Port Scanning...")
    identify_open_ports(clean_host)

    print("\n[2] Checking HTTP Service Version on Port 80...")
    probe_service_header(clean_host, 80)

    print("\n[3] Testing for Directory Listing Misconfiguration...")
    inspect_directory_listing(target_input)

    print("\n[4] Scanning for Web Vulnerabilities (SQLi, XSS)...")
    run_web_vulnerability_scan(target_input)


def run_audit(target_input):
    output = []

    clean_host = target_input.replace("http://", "").replace("https://", "").rstrip("/")

    output.append("[1] Starting Port Scanning...")
    output.append(identify_open_ports(clean_host))

    output.append("\n[2] Checking HTTP Service Version on Port 80...")
    output.append(probe_service_header(clean_host, 80))

    output.append("\n[3] Testing for Directory Listing Misconfiguration...")
    output.append(inspect_directory_listing(target_input))

    output.append("\n[4] Scanning for Web Vulnerabilities (SQLi, XSS)...")
    output.append(run_web_vulnerability_scan(target_input))

    return "\n".join(output)


if __name__ == "__main__":
    
    app.run(debug=True)
    start_audit() 
    

