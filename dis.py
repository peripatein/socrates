import argparse
import hashlib
import nmap
from os import system
from queue import Queue
import requests
import socket
import sys
import threading
import time
print('''
      _______  ______ _____ _______  _____ 
      |       |_____/   |      |    |     |
      |_____  |    \_ __|__    |    |_____|
      
      hd) Hash Decryptor
      ip) Host2IP
      ps) PScan\n\n
      
      Made with love by Finn Tachyen''')
parser = argparse.ArgumentParser(description='menu')
parser.add_argument('-hd',
    action='store_true',
    help='Decrypt Hash' )
parser.add_argument('-ip',
    action='store_true',
    help='Host2IP' )
parser.add_argument('-ps',
    action='store_true',
    help='Port Scan' )
args = parser.parse_args()

if args.hd:
    os.system('cls')
    try:
        type_hash = sys.argv[1]
        hash_a=sys.argv[2]
    except:
        print(f'''
              _______  ______ _____ _______  _____ 
              |       |_____/   |      |    |     |
              |_____  |    \_ __|__    |    |_____|\n\n
              [*]USAGE: {sys.argv[0]} type_hash(md5, sha256, sha512) hash
              ''')
        so = input("Enter Hash >>> ")
        for password in so:
            password = password.strip()
            if type_hash == "md5":
                hash_b = hashlib.md5(password).hexdigest()
            elif type_hash == "sha256":
                hash_b = hashlib.sha256(password).hexdigest()
            elif type_hash == "sha512":
                hash_b = hashlib.sha215(password).hexdigest()
                if hash_a == hash_b:
                    print(f"[+]Password : {password}")
else:
    print("There was an error somewhere")


if args.ip:
    os.system('cls')
    print('''
    _______  ______ _____ _______  _____ 
    |       |_____/   |      |    |     |
    |_____  |    \_ __|__    |    |_____|
    ''')
    server = input(">>>")
    print("Specify Port")
    port = int(input(">>>"))
    server_ip = socket.gethostbyname(server)
    print(f"The sites IP address is : {server_ip}")
    request = f"GET / HTTP/1.1\nHost: {server}\n\n"
    s.connect((server, port))
    s.send(request.encode())
    results = s.recv(1024)
    print(results)
else:
    print("There was an Error Somewhere")


if args.ps:
    os.system('cls')
    s = nmap.PortScanner()
    print('''
          _______  ______ _____ _______  _____ 
          |       |_____/   |      |    |     |
          |_____  |    \_ __|__    |    |_____|
          ''')
    ip_addr = input("IP Address >>> ")
    type(ip_addr)
    resp = input(f'''\nPlease enter the type of scan to intiate on {ip_addr}
                 1)SYN-ACK Scan
                 2)UDP Scan
                 3)Comprehensive Scan\n''')
    os.system('cls')
    print(f"Commencing Number {resp}")
    os.system('cls')
    if resp == '1':
        print(f"Nmap Ver: {s.nmap_version()}")
        s.scan(ip_addr, '1-1024', '-v -sS')
        print(s.scaninfo())
        print(f"IP Stats : {s[ip_addr].state()}")
        print(s[ip_addr].all_protocols())
        print(f"Open Ports: {s[ip_addr]['tcp'].keys()}")
    elif resp == '2':
        print(f"Nmap Ver: {s.nmap_version()}")
        s.scan(ip_addr, '1-1024', '-v -sU')
        print(s.scaninfo())
        print(f"IP Stats : {s[ip_addr].state()}")
        print(s[ip_addr].all_protocols())
        print(f"Open Ports: {s[ip_addr]['udp'].keys()}")
    elif resp == '3':
        print(f"Nmap Ver: {s.nmap_version()}")
        s.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
        print(s.scaninfo())
        print(f"IP Stats : {s[ip_addr].state()}")
        print(s[ip_addr].all_protocols())
        print(f"Open Ports: {s[ip_addr].state()}")
    elif resp >= '4':
        print("Please Enter valid option")
else:
    print("There was an error somewhere")
