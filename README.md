# ApachePHPFirewall
Integrasi Apache2, PHP dengan sistem IPTables, sehingga dapat mendeteksi dan memblokir upaya serangan Brute Force
```
import time
import subprocess
import select
import json

from datetime import datetime

#detector class
class Detector:
	def __init__(self, pattern, errorCode, limit):
		self.pattern = pattern
		self.errorCode = errorCode
		self.limit = limit
		self.suspect = {}

	def detect(self, line):
		retVal=0
		if line.find(self.pattern) > -1:
			parts = line.split()
			if parts[0] in self.suspect:
				self.suspect[parts[0]]+=1
			else:
				self.suspect[parts[0]]=1
			if self.suspect[parts[0]] > self.limit:
				blacklist(parts[0], self.errorCode)

			retVal=1
		return retVal
									
jail = []

#firewall activation
def blacklist(ip, reason):
	now = datetime.now()
	if ip not in jail:
		fwcmd = '/sbin/iptables -A INPUT -s ' + ip + '1 -j DROP'
		subprocess.call(fwcmd, shell=True)
		jail.append(ip)
		with open('/var/log/jail/' + now.strftime("%Y%m%d") + ".log",'a+') as flog:
			flog.write(ip + " -> " + reason + "@" + now.strftime("%H:%M:%S"))
			flog.write("\n")


#define kind of detector
detector401 = Detector("\" 401 ", "401", 20)	#401 Unauthorized
detector404 = Detector("\" 404 ", "401", 200)	#404 Not Found

#202 dicustom untuk aplikasi yang submit form bebas untuk ditindak
#lanjuti seperti Keluhan konsumen dan Lamaran Kerja
detector202 = Detector("\" 202 ", "202", 4)	#202 Accepted 

#203 dicustom untuk aplikasi jika gagal login
detector203 = Detector("\" 203 ", "203", 30)	#203 Non-Authoritative Information

#Tail -F /var/log/apache2/ssl_access.log
f = subprocess.Popen(['tail','-F', '/var/log/apache2/ssl_access.log'], \
	stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)

while True:
	if p.poll(1):
		line = f.stdout.readline()		
		print line
		if detector401.detect(line) > 0:
			print "detected 401"
		elif detector404.detect(line) > 0:
			print "detected 404"
		elif detector202.detect(line) > 0:
			print "detected 202"
		elif detector203.detect(line) > 0:
			print "detected 203"

	time.sleep(0.001)
```

dan untuk menjalankan aplikasi diatas dibackground:
```
python apfw.py > /dev/null &
```
Untuk menampilkan process id aplikasi dibackground:
```
ps ax | grep apfw
```
untuk menghentikan aplikasi dibackground:
```
pkill -F apfw.py
```
