import os
import math
import sys
import re
import subprocess as sp
import numpy as np
import time
import datetime

target = sys.argv[1]
network_interface = sys.argv[2]

tcpPorts = map(str, range(1,65535))
rate = 5000
percentage =  1
saveDir = 'scans_'+str(target)

closedPorts = []
openPorts = []
unknownPorts = []
noResponsePorts = []

if (len(sys.argv) != 3):
    print ("argv[1] = target, argv[2] = network adapter")
    print ("Example: python portscan.py 10.10.10.10 tun1")
    sys.exit()

try:
    os.makedirs(saveDir)
except:
    print("directory probably already made")

global remainingPorts

def fullScan(portsToScan, speed, netint, target):
    sp.call(["sudo masscan -p " + str(portsToScan) + " --rate " + str(speed) + " --wait 0 " + str(target) + " -oG " + str(saveDir) + "/tmp.grep -e " + str(netint) + " --show closed | tee tcp_masscan.txt"], shell=True)
    scanOutput = sp.check_output(["cat " + str(saveDir) + "/tmp.grep | awk '{print $7}' | grep /closed/ |  grep -o '[0-9]\+' | sort -n | uniq"], shell=True)
    for line in scanOutput.splitlines():
        closedPorts.append(line)
    #closedPorts = sorted(closedPorts)

    scanOutput = sp.check_output(["cat " + str(saveDir) + "/tmp.grep | awk '{print $7}' | grep /open/ | grep -o '[0-9]\+' | sort -n | uniq"], shell=True)
    for line in scanOutput.splitlines():
        openPorts.append(line)
    #openPorts = sorted(openPorts)
     
    noResponsePorts = set(tcpPorts) - set(closedPorts)
    noResponsePorts = set(noResponsePorts) - set(openPorts)
    noResponsePorts = sorted(noResponsePorts)

    print ('[+]Number of Closed Ports: ' + str(len(closedPorts)))
    print ('[+]Number of No Response Ports: ' + str(len(noResponsePorts)))
    print ('[+]openPorts:(' + str(len(openPorts)) + ') ' + str(openPorts))
    remainingPorts = ','.join(noResponsePorts)
    return remainingPorts

remainingPorts = '1-65535'
numScans = 1
firstScan = True
startScan = datetime.datetime.now()
print('[+] Full TCP Masscan started at ' + str(startScan))

while (remainingPorts):
    lastscan = remainingPorts

#working area

    if (remainingPorts.count(",")+1 > 20000): #somewhere between 20k-25k is the maximum number of specific ports masscan can take in as input
        val = -1
        for i in range(0,20000):
            val = remainingPorts.find(",", val + 1)
            truncatedPorts = remainingPorts[:val]
        print ("[+] More than 20k ports to scan, truncating to the first 20k in our list due to masscan limitations ")
        if (remainingPorts.count(",")+1 < 10000):
            print ("===================== LESS THAN 5K PORTS")
            rate = 200
        remainingPorts = fullScan(truncatedPorts, rate, network_interface, target)
    else:
        if (remainingPorts.count(",")+1 < 10000 and firstScan == False):
            rate = 500
        if (remainingPorts.count(",")+1 < 1000 and firstScan == False):
            rate = 200
        remainingPorts = fullScan(remainingPorts, rate, network_interface, target)
        firstScan = False
    
#working area
    print ('[+]Number of scans: ' + str(numScans))
    rate = rate*percentage
    if (rate < 100):
        rate = 100
        print ('[+]Rate modified from ' + str(rate) + ' to ' + str(rate) + ' for next scan.')
    else:
        print ('[+]Rate modified from ' + str(rate) + ' to ' + str(rate*percentage) + ' for next scan.')
    numScans += 1
    if (lastscan == remainingPorts):
        print("[+]Encountered a number of ports that will not decrement, investigate manually. Breaking scan loop.")
        print("[+]Remaining Ports: " + str(remainingPorts))
        break
    

endDiscovery = datetime.datetime.now()
discoveryTime = endDiscovery - startScan
print ('[+]All 65535 TCP ports scanned in ' + str(discoveryTime.seconds) + ' seconds.')

print ("\n\n[+]Starting Service Enumeration")
openPorts = ','.join(openPorts)
nmapScan = 'nmap -sV -A -p ' + str(openPorts) + ' ' + str(target) + ' -oA ' + str(saveDir) + '/nmapresults | tee ' + str(saveDir) + '/nmapresults.txt'
print("[+]\n" + str(nmapScan) + "\n[+]")
sp.call([nmapScan], shell=True)
endEnumeration = datetime.datetime.now()
enumerationTime = endEnumeration - endDiscovery
endScan = endEnumeration - startScan
print ('\n\n[+]TCP Service Discovery: All 65535 TCP port status confirmed in ' + str(discoveryTime.seconds) + ' seconds.')
print ('[+]TCP Version Enumeration performed in ' + str(enumerationTime.seconds) + ' seconds.')
print ('[+]Total time: ' + str(endScan.seconds) + ' seconds.')
