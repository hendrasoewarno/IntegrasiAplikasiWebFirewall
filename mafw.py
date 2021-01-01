#!/usr/bin/python
import time
import subprocess
import select
import json

from datetime import datetime
								
jail = []
ignoreIP = ["127.0.0.1","::1"]

#ip = IP Address yang akan diblacklist
#reason = Keterangan alasan diblacklist
def blacklist(ip, reason):
	now = datetime.now()
	if ip not in jail and ip not in ignoreIP:
		fwcmd = '/sbin/iptables -A INPUT -s ' + ip + ' -j DROP'
		subprocess.call(fwcmd, shell=True)
		jail.append(ip)
		with open('/var/log/jail/' + now.strftime("%Y%m%d") + ".log",'a+') as flog:
			flog.write(ip + " -> " + reason + "@" + now.strftime("%H:%M:%S"))
			flog.write("\n")


suspect = {}
failedlimit = 4

#Tail -F /var/log/mail.log
f = subprocess.Popen(['tail','-F', '/var/log/mail.log'], \
	stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)

while True:
	if p.poll(1):
		line = f.stdout.readline()		
        if "authentication failed: authentication failure" in line:
            parts = line.split()		
            ipaddress = (parts[6].split('[', 1)[-1]).split(']',1)[0]
            if ipaddress not in suspect.keys():
                suspect[ipaddress]=1
            else:
                suspect[ipaddress]+=1
            if suspect[ipaddress] > failedlimit:
                blacklist(ipaddress, "SASL Authentication Failed")
            
                
        elif "pop3-login: Aborted login (auth failed, 1 attempts):" in line:
            parts = line.split()
            ipaddress = (parts[14].split('rip=', 1)[-1]).split(',',1)[0]
            if ipaddress not in suspect.keys():
                suspect[ipaddress]=1
            else:
                suspect[ipaddress]+=1

                elif "NOQUEUE: reject: RCPT from unknown" in line:
                    parts = line.split()
                    ipaddress = (parts[9].split('unknown[', 1)[-1]).split(']',1)[0]
                    if ipaddress not in suspect.keys():
                        suspect[ipaddress]=1
                    else:
                        suspect[ipaddress]+=1
            
            if suspect[ipaddress] > failedlimit:
                blacklist(ipaddress, "POP3 Login Failed")

	time.sleep(0.001)
