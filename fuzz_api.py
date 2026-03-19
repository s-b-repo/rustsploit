import requests
import json
import time
import os

API_URL = "http://127.0.0.1:8080"
API_KEY = "fuzzingkey123"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Create dummy wordlists
with open("fuzz_users.txt", "w") as f:
    f.write("admin\nroot\nuser\n")
with open("fuzz_pass.txt", "w") as f:
    f.write("admin\npassword\n1234\n")

# Provide default prompt bypasses for modules that expect custom config keys
PROMPT_DEFAULTS = {
    "creds/generic/fortinet_bruteforce": {"port": "443", "concurrency": "10", "timeout": "10", "stop_on_success": "yes", "save_results": "no", "verbose": "no", "combo_mode": "no", "trusted_cert": "", "realm": ""},
    "creds/generic/ftp_anonymous": {"port": "21"},
    "creds/generic/ftp_bruteforce": {"port": "21", "save_results": "no", "combo_mode": "no"},
    "creds/generic/l2tp_bruteforce": {"port": "1701", "save_results": "no"},
    "creds/generic/mqtt_bruteforce": {"port": "1883", "save_results": "no", "combo_mode": "no", "tls": "no"},
    "creds/generic/pop3_bruteforce": {"port": "110", "save_results": "no", "combo_mode": "no", "tls": "no"},
    "creds/generic/rdp_bruteforce": {"port": "3389", "domain": "", "save_results": "no"},
    "creds/generic/rtsp_bruteforce": {"port": "554", "save_results": "no"},
    "creds/generic/sample_cred_check": {"save_results": "no"},
    "creds/generic/smtp_bruteforce": {"port": "25", "domain": "test.com", "save_results": "no", "combo_mode": "no", "tls": "no"},
    "creds/generic/snmp_bruteforce": {"port": "161", "version": "2c", "save_results": "no"},
    "creds/generic/ssh_bruteforce": {"port": "22", "save_results": "no", "combo_mode": "no"},
    "creds/generic/ssh_spray": {"port": "22", "save_results": "no"},
    "creds/generic/telnet_bruteforce": {"port": "23", "save_results": "no", "combo_mode": "no"},
}

def get_modules():
    try:
        r = requests.get(f"{API_URL}/api/modules", headers=HEADERS)
        if r.status_code == 200:
            return r.json().get("data", {}).get("creds", [])
    except Exception as e:
        print(f"Error getting modules: {e}")
    return []

def test_module_legitimate(module_name, results_file):
    print(f"Testing legitimate run: {module_name}")
    
    # Massive dictionary to catch all possible fallback prompts across all modules
    mega_prompts = {
        "port": "22", "concurrency": "10", "timeout": "10", "stop_on_success": "yes", 
        "save_results": "no", "combo_mode": "no", "tls": "no", "use_defaults": "no", 
        "use_username_wordlist": "yes", "use_password_wordlist": "yes", "retry_on_error": "no", 
        "max_retries": "1", "verbose": "no", "save_unknown_responses": "no", "test_anonymous": "no", 
        "client_id": "fuzz", "use_tls": "no", "use_exclusions": "yes", "threads": "10", 
        "delay_ms": "0", "version": "2c", "domain": "test", "trusted_cert": "", "realm": "",
        "auth_bypass": "no", "force_exploit": "yes", "check_only": "no", "ssl": "no",
        "mode": "1", "scan_network": "no", "payload": "id"
    }
    
    specific_prompts = PROMPT_DEFAULTS.get(module_name, {})
    mega_prompts.update(specific_prompts)
    
    payload = {
        "module": module_name,
        "target": "127.0.0.1",
        "username_wordlist": "fuzz_users.txt",
        "password_wordlist": "fuzz_pass.txt",
        "concurrency": 10,
        "stop_on_success": True,
        "prompts": mega_prompts
    }
    start = time.time()
    try:
        r = requests.post(f"{API_URL}/api/run", headers=HEADERS, json=payload, timeout=30)
        duration = time.time() - start
        res = r.json()
        status = f"SUCCESS ({r.status_code})" if res.get("success") else f"FAIL ({r.status_code}) - {res.get('error_code')} - {res.get('message')}"
        results_file.write(f"[LEGIT] Module: {module_name:30} | {status} | Time: {duration:.2f}s\n")
    except requests.exceptions.Timeout:
        results_file.write(f"[LEGIT] Module: {module_name:30} | FAIL (TIMEOUT) | Time: >30s\n")
    except Exception as e:
        results_file.write(f"[LEGIT] Module: {module_name:30} | FAIL ({str(e)})\n")

def test_fuzzing(bugs_file):
    print("Running initial security fuzzing...")
    bugs_file.write("--- API Initial Fuzzing Bugs ---\n")
    
    # Path Traversal in module name
    payload = {"module": "../../../../../etc/passwd", "target": "127.0.0.1"}
    r = requests.post(f"{API_URL}/api/run", headers=HEADERS, json=payload)
    if r.status_code == 200 or "root:x" in r.text or ("unauthorized access" not in r.text.lower() and "invalid module name" not in r.text.lower() and r.status_code == 500):
        bugs_file.write(f"BUG: /api/run potentially vulnerable to path traversal (status {r.status_code})\n")

    # Very long target
    payload = {"module": "creds/generic/ssh_bruteforce", "target": "A" * 5000}
    r = requests.post(f"{API_URL}/api/run", headers=HEADERS, json=payload)
    if r.status_code >= 500:
         bugs_file.write("BUG: /api/run returned 500 on very long target string\n")

    # Command Injection in target
    payload = {"module": "creds/generic/ssh_bruteforce", "target": "127.0.0.1; touch /tmp/pwned"}
    r = requests.post(f"{API_URL}/api/run", headers=HEADERS, json=payload)
    if os.path.exists("/tmp/pwned"):
        bugs_file.write("CRITICAL BUG: command injection in target parameter (/tmp/pwned created)\n")
        
    # Exec Endpoint Command Injection Chain
    payload = {"command": "help & echo 'injection_test'"}
    r = requests.post(f"{API_URL}/api/exec", headers=HEADERS, json=payload)
    if r.status_code == 200 and "injection_test" in r.text:
         bugs_file.write("BUG: /api/exec executes raw shell commands instead of mapping them\n")

def test_portswigger_vulnerabilities(bugs_file):
    print("Running PortSwigger API Security Top 10 tests...")
    bugs_file.write("\n--- PortSwigger API Security Findings ---\n")
    
    # 1. Broken Authentication (BOLA/Authentication)
    print("  Testing Broken Authentication...")
    r = requests.post(f"{API_URL}/api/run", json={"module": "creds/generic/ssh_bruteforce", "target": "127.0.0.1"})
    if r.status_code != 401:
        bugs_file.write(f"BUG (Broken Auth): /api/run accessible without Auth header (Status: {r.status_code})\n")
    
    bad_headers = {"Authorization": "Bearer BADKEY", "Content-Type": "application/json"}
    r = requests.post(f"{API_URL}/api/run", headers=bad_headers, json={"module": "creds/generic/ssh_bruteforce", "target": "127.0.0.1"})
    if r.status_code != 401:
        bugs_file.write(f"BUG (Broken Auth): /api/run accessible with BAD token (Status: {r.status_code})\n")
        
    # 2. HTTP Method Tampering (Security Misconfiguration)
    print("  Testing HTTP Method Tampering...")
    r = requests.get(f"{API_URL}/api/run", headers=HEADERS)
    if r.status_code not in [404, 405]:
        bugs_file.write(f"BUG (Method Tampering): /api/run accepted a GET request (Status: {r.status_code})\n")
        
    r = requests.put(f"{API_URL}/api/honeypot-check", headers=HEADERS, json={"target": "127.0.0.1"})
    if r.status_code not in [404, 405]:
        bugs_file.write(f"BUG (Method Tampering): /api/honeypot-check accepted a PUT request (Status: {r.status_code})\n")
        
    # 3. Content-Type Manipulation (Security Misconfiguration)
    print("  Testing Content-Type Manipulation...")
    xml_data = "<xml><module>creds/generic/ssh_bruteforce</module><target>127.0.0.1</target></xml>"
    ct_headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/xml"}
    r = requests.post(f"{API_URL}/api/run", headers=ct_headers, data=xml_data)
    if r.status_code not in [400, 415]:
        bugs_file.write(f"BUG (Content-Type): /api/run accepted XML incorrectly formatted instead of JSON returning 400/415 (Status: {r.status_code})\n")
        
    # 4. Mass Assignment
    print("  Testing Mass Assignment...")
    payload = {
        "module": "creds/generic/ssh_bruteforce",
        "target": "127.0.0.1",
        "is_admin": True,
        "role": "admin",
        "api_key": "overwritten"
    }
    r = requests.post(f"{API_URL}/api/run", headers=HEADERS, json=payload)
    if r.status_code == 200:
        bugs_file.write("INFO: Server ignores extra fields (Mass Assignment mitigated contextually)\n")
    elif r.status_code == 500:
        bugs_file.write("BUG (Mass Assignment/Error Handling): Server crashed on extra unexpected JSON fields (Status: 500)\n")
        
    # 5. Lack of Resources / Rate Limiting (DoS)
    print("  Testing Rate Limiting...")
    successes = 0
    start = time.time()
    for _ in range(50):
        try:
             res = requests.get(f"{API_URL}/api/modules", headers=HEADERS, timeout=2)
             if res.status_code == 200:
                 successes += 1
        except:
             pass
    duration = time.time() - start
    if successes == 50:
         bugs_file.write(f"BUG (Lack of Resources/Rate Limiting): Server allowed 50 requests in {duration:.2f} seconds with no rate limiting applied\n")

    # 6. Server-Side Request Forgery (SSRF)
    print("  Testing SSRF (Server-Side Request Forgery)...")
    payload = {"target": "169.254.169.254"}
    r = requests.post(f"{API_URL}/api/honeypot-check", headers=HEADERS, json=payload, timeout=5)
    if r.status_code == 200:
         bugs_file.write("BUG (SSRF): API allows scanning internal/cloud metadata IP (169.254.169.254)\n")
    else:
         bugs_file.write("INFO (SSRF): Local/cloud metadata request was rejected or failed as expected.\n")

    payload = {"target": "127.0.0.1"} 
    r = requests.post(f"{API_URL}/api/honeypot-check", headers=HEADERS, json=payload, timeout=5)
    if r.status_code == 200:
         bugs_file.write("INFO (SSRF): API legitimately allows scanning localhost/127.0.0.1 by its design.\n")

def main():
    print("Fetching modules...")
    modules = get_modules()
    if not modules:
        print("No creds modules found or API not running.")
        return

    print(f"Found {len(modules)} creds modules.")
    
    with open("results.txt", "w") as results_file:
        for mod in modules:
            test_module_legitimate(mod, results_file)
            
    with open("bugs.txt", "w") as bugs_file:
        test_fuzzing(bugs_file)
        test_portswigger_vulnerabilities(bugs_file)
        
    print("Testing complete. Check results.txt and bugs.txt")

if __name__ == "__main__":
    main()
