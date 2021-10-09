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
	def addPattern(self, pattern, weight):
		self.patterns[pattern]=weight

	#line = baris pada log untuk dideteksi keberadaan pattern
	def detect(self, line):
		retVal=0
		ipaddr=None
		score=0
		#jika ada pattern
		for pattern in self.patterns:
			found = re.search(pattern, line)
			if found:
				ipaddr = found.group(1)
				score += self.patterns[pattern]
			
		if ipaddr and score>0:
			#jika IP Address pernah suspect
			if ipaddr in self.suspects:
				self.suspects[ipaddr]+=score
			else:
				self.suspects[ipaddr]=score
				
			#jika IP Address tercatat melampaui limit					
			if self.suspects[ipaddr] >= self.limit:
				blacklist(ipaddr, self.chain)
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

#ipaddr = IP Address yang akan diblacklist
#chain = Chain iptables
def blacklist(ipaddr, chain):
	now = datetime.now()
	if ipaddr in ignoreIP:
		print("ignoreIP " + ipaddr)
	elif ipaddr in jailed:
		print("jailed " + ipaddr)
	else:
		fwcmd = '/sbin/iptables -I ' + chain + ' 1 -s ' + ipaddr + ' -j DROP'
		print(fwcmd)
		#subprocess.call(fwcmd, shell=True)
		jailed.append(ipaddr)
		#with open('/var/log/jail/' + now.strftime("%Y%m%d") + ".log",'a+') as flog:
		#	flog.write(ipaddr + " -> " + chain + "@" + now.strftime("%H:%M:%S"))
		#	flog.write("\n")

#define kind of detector or anti detector
detector = Detector("WebAttack", 3)	
detector.addPattern(".*UDP flood.*SRC=(.*?) DST=.*",2)
detector.addPattern(".*Suspected Win exploit.*SRC=(.*?) DST=.*",2)
detector.addPattern(".*Suspected RST ACK FLAGS.*SRC=(.*?).*",2)

#define log file to be detect
logFilePoll = LogFilePoll(detector)
logFilePoll.addFile('/var/log/kern.log')
logFilePoll.addFile('/var/log/apache2/ssl_access.log')

while True:
	logFilePoll.detect()
	time.sleep(0.001)