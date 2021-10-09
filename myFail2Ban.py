#!/usr/bin/python
import time
import subprocess
import select
import json
import re

from datetime import datetime

#detector class
class Detector:

	#pattern = pattern yang ingin diawasi pada log
	#errorCode = alasan diblacklist terkait pattern
	#limit = batasan jumlah penemuan terhadap pattern untuk tindakan pemblokiran
	def __init__(self, chain, limit):
		#pembuatan chain baru
		fwcmd = '/sbin/iptables -N ' + chain
		print(fwcmd)
		#subprocess.call(fwcmd, shell=True)  
		fwcmd = '/sbin/iptables -A ' + chain + ' -j RETURN'
		print(fwcmd)		
		#subprocess.call(fwcmd, shell=True)
		self.chain = chain
		self.limit = limit
		self.patterns = {}
		self.suspects = {}
	
	#menambah pola dan bobot
	def addPattern(self, pattern, data):
		self.patterns[pattern]=data

	#line = baris pada log untuk dideteksi keberadaan pattern
	def detect(self, line):
		retVal=0
		ipaddr=None
		score=0
		desc=""
		#jika ada pattern
		for pattern in self.patterns:
			found = re.search(pattern, line)
			if found:
				ipaddr = found.group(1)
				score += self.patterns[pattern]["score"]
				desc += self.patterns[pattern]["name"] + "(" + str(self.patterns[pattern]["score"]) + ")\n"
			
		if ipaddr and score>0:
			#jika IP Address pernah suspect
			if ipaddr in self.suspects:
				state = self.suspects[ipaddr]
				state["score"]+= score
				state["desc"]+= desc
				self.suspects[ipaddr]=state
			else:
				state = {"score":score, "desc":desc}
				self.suspects[ipaddr]=state

			print(self.suspects)	
			#jika State dari IP Address tercatat melampaui limit					
			if state["score"] >= self.limit:
				blacklist(ipaddr, self.chain, state["desc"])
				del self.suspects[ipaddr]
				retVal=1

		return retVal

#LogFilePoll
class LogFilePoll:
		def __init__(self, detector):
			self.polls = []
			self.files = {}
			self.detector = detector

		def addFile(self, file):
			#Tail -F /var/log/apache2/ssl_access.log
			f = subprocess.Popen(['tail','-F', file], \
					stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			p = select.poll()
			p.register(f.stdout)
			self.polls.append(p)
			self.files[id(p)] = f

		def detect(self):
			for p in self.polls:
				if p.poll(1):
					line = self.files[id(p)].stdout.readline()
					#print line
					if detector.detect(line) > 0:
						print "detected WebAttack"
									
jailed = []
ignoreIP = ["127.0.0.1","::1"]

def ipToBinary(ip):
        octet_list_int = ip.split(".")
        octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
        binary = ("").join(octet_list_bin)
        return binary

def getAddrNetwork(address, net_size):
        #Convert ip address to 32 bit binary
        ip_bin = ipToBinary(address)
        #Extract Network ID from 32 binary
        network = ip_bin[0:32-(32-net_size)]
        return network

def ipInPrefix(ip_address, prefix):
        #CIDR based separation of address and network size
        [prefix_address, net_size] = prefix.split("/")
        #Convert string to int
        net_size = int(net_size)
        #Get the network ID of both prefix and ip based net size
        prefix_network = getAddrNetwork(prefix_address, net_size)
        ip_network = getAddrNetwork(ip_address, net_size)
        return ip_network == prefix_network

def isIgnoreIP(ipaddr):
        for ip in ignoreIP:
                if "/" in ip:
                        if ipInPrefix(ipaddr, ip):
                                return True
                else:
                        if ipaddr==ip:
                                return True
        return False

#ipaddr = IP Address yang akan diblacklist
#chain = Chain iptables
def blacklist(ipaddr, chain, description):
	now = datetime.now()
	if isIgnoreIP(ipaddr):
		print("ignoreIP " + ipaddr)
	elif ipaddr in jailed:
		print("jailed " + ipaddr)
	else:
		fwcmd = '/sbin/iptables -I ' + chain + ' 1 -s ' + ipaddr + ' -j DROP'
		print(fwcmd)
		print(description)
		#subprocess.call(fwcmd, shell=True)
		jailed.append(ipaddr)
		#with open('/var/log/jail/' + now.strftime("%Y%m%d") + ".log",'a+') as flog:
		#	flog.write(ipaddr + " -> " + chain + "@" + now.strftime("%H:%M:%S"))
		#	flog.write("\n")
		#	flog.write(description)
		#	flog.write("\n")

#define kind of detector or anti detector
detector = Detector("WebAttack", 2)	
detector.addPattern(".*UDP flood.*SRC=(.*?) DST=.*", {"name":"UDP Flood", "score":2})
detector.addPattern(".*Suspected Win exploit.*SRC=(.*?) DST=.*", {"name":"Win Exploit", "score":2})
detector.addPattern(".*Suspected RST ACK FLAGS.*SRC=(.*?).*", {"name":"Suspected RST ACK", "score":2})

#define log file to be detect
logFilePoll = LogFilePoll(detector)
logFilePoll.addFile('/var/log/kern.log')
logFilePoll.addFile('/var/log/apache2/ssl_access.log')

while True:
	logFilePoll.detect()
	time.sleep(0.001)
