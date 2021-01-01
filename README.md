# Apache & PHP Firewall Integration
Tulisan ini menunjukan ide bagaimana cara melakukan integrasi antara Apache2, PHP dengan sistem IPTables menjadi Intrussion Prevention System, sehingga memungkinkan upaya pendeteksian dan pemblokiran secara realtime terhadap serangan Brute Force.<br>
<br>
Pada umumnya pada aplikasi WEB dapat melakukan upaya intruder logout dengan menggunakan sesi maupun pencatatan pada log database, tetapi pada tulisan ini kami ingin menunjukkan potensi untuk melakukan pemblokiran yang terintegrasi dengan firewall. Pada PHP kita dapat mengatur HTTP Response Code yang nantinya akan tercatat pada /var/log/apache2/access.log (HTTP) atau /var/log/apache2/ssl_access.log (HTTPS), sebagai berikut:
```
if ($gagalLogin) {
	http_response_code (203) //203 Non-Authoritative Information untuk dicatat pada Log
	//perintah PHP lainnya
}
```
Setelah kode kegagalan tersebut tercatat pada log, maka berikutnya adalah membuat Python Script yang secara realtime mengawasi isi file /var/log/apache2/ssl_access, dan menambahkan iptables rule pada chain INPUT untuk memblokir IP Address yang diprediksi melakukan upaya eksploitasi terhadap aplikasi WEB.
```
#!/usr/bin/python
import time
import subprocess
import select
import json

from datetime import datetime

#detector class
class Detector:

	#pattern = pattern yang ingin diawasi pada log
	#errorCode = alasan diblacklist terkait pattern
	#limit = batasan jumlah penemuan terhadap pattern untuk tindakan pemblokiran
	def __init__(self, pattern, errorCode, limit):
		self.pattern = pattern
		self.errorCode = errorCode
		self.limit = limit
		self.suspect = {}

	#line = baris pada log untuk dideteksi keberadaan pattern
	def detect(self, line):
		retVal=0
		#jika ada pattern
		if line.find(self.pattern) > -1:
			parts = line.split()
			#jika IP Address pernah suspect
			if parts[0] in self.suspect:
				self.suspect[parts[0]]+=1
			else:
				self.suspect[parts[0]]=1
				
			#jika IP Address tercatat melampaui limit
			if self.suspect[parts[0]] > self.limit:
				blacklist(parts[0], self.errorCode)

			retVal=1
		return retVal
									
jail = []

#ip = IP Address yang akan diblacklist
#reason = Keterangan alasan diblacklist
def blacklist(ip, reason):
	now = datetime.now()
	if ip not in jail:
		fwcmd = '/sbin/iptables -A INPUT -s ' + ip + ' -j DROP'
		subprocess.call(fwcmd, shell=True)
		jail.append(ip)
		with open('/var/log/jail/' + now.strftime("%Y%m%d") + ".log",'a+') as flog:
			flog.write(ip + " -> " + reason + "@" + now.strftime("%H:%M:%S"))
			flog.write("\n")


#define kind of detector
detector401 = Detector("\" 401 ", "401 Unauthorized > 20times", 20)	
detector404 = Detector("\" 404 ", "404 Not Found > 200times", 200)	

#202 dicustom untuk aplikasi yang submit form bebas untuk ditindak
#lanjuti seperti Keluhan konsumen dan Lamaran Kerja
detector202 = Detector("\" 202 ", "202 Accepted > 4times", 4)

#203 dicustom untuk aplikasi jika gagal login
detector203 = Detector("\" 203 ", "203 Non-Authoritative Information > 30times", 30)

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
Atau alternatif script untuk teknik pembacaan logfile
```
#!/usr/bin/python
import time
import subprocess
import select
import json

from datetime import datetime

#detector class
class Detector:

        #pattern = pattern yang ingin diawasi pada log
        #errorCode = alasan diblacklist terkait pattern
        #limit = batasan jumlah penemuan terhadap pattern untuk tindakan pemblokiran
        def __init__(self, pattern, errorCode, limit):
                self.pattern = pattern
                self.errorCode = errorCode
                self.limit = limit
                self.suspect = {}

        #line = baris pada log untuk dideteksi keberadaan pattern
        def detect(self, line):
                retVal=0
                #jika ada pattern
                if line.find(self.pattern) > -1:
                        parts = line.split()
                        #jika IP Address pernah suspect
                        if parts[0] in self.suspect:
                                self.suspect[parts[0]]+=1
                        else:
                                self.suspect[parts[0]]=1

                        #jika IP Address tercatat melampaui limit
                        if self.suspect[parts[0]] > self.limit:
                                blacklist(parts[0], self.errorCode)

                        retVal=1
                return retVal

jail = []

#ip = IP Address yang akan diblacklist
#reason = Keterangan alasan diblacklist
def blacklist(ip, reason):
        now = datetime.now()
        if ip not in jail:
                fwcmd = '/sbin/iptables -A INPUT -s ' + ip + ' -j DROP'
                subprocess.call(fwcmd, shell=True)
                jail.append(ip)
                with open('/var/log/jail/' + now.strftime("%Y%m%d") + ".log",'a+') as flog:
                        flog.write(ip + " -> " + reason + "@" + now.strftime("%H:%M:%S"))
                        flog.write("\n")

def getLine(file):
        file.seek(0,2)
        while True:
                line = file.readline()
                if not line:
                        time.sleep(0.001)
                        continue
                yield line

#define kind of detector
detector401 = Detector("\" 401 ", "401 Unauthorized > 20times", 20)
detector404 = Detector("\" 404 ", "404 Not Found > 200times", 200)

#202 dicustom untuk aplikasi yang submit form bebas untuk ditindak
#lanjuti seperti Keluhan konsumen dan Lamaran Kerja
detector202 = Detector("\" 202 ", "202 Accepted > 4times", 4)

#203 dicustom untuk aplikasi jika gagal login
detector203 = Detector("\" 203 ", "203 Non-Authoritative Information > 30times", 30)

f = open('/var/log/apache2/access.log', 'r')

loglines = getLine(f)
for line in loglines:
        print line
        if detector401.detect(line) > 0:
                print "detected 401"
        elif detector404.detect(line) > 0:
                print "detected 404"
        elif detector202.detect(line) > 0:
                print "detected 202"
        elif detector203.detect(line) > 0:
                print "detected 203"
```
Agar aplikasi tersebut dapat dijalankan, maka kita perlu membuat folder /var/log/jail yang nantinya akan menampung log file
```
mkdir /var/log/jail
```
dan aplikasi tersebut perlu dijalankan aplikasi secara dibackground:
```
python apfw.py > /dev/null &
```
Untuk menampilkan process id aplikasi dibackground:
```
ps ax | grep apfw
```
untuk menghentikan aplikasi dibackground:
```
kill -9 <pid>
```
atau
```
pkill -f apfw.py
```
