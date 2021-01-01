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
                fwcmd = '/sbin/iptables -A INPUT -s ' + ip + '1 -j DROP'
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