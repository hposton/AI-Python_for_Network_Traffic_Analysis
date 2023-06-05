from scapy.all import *
from scapy.layers.http import *

def loadBlocklist(filename):
	with open(filename,"r") as f:
		hosts = f.read().splitlines()
	return hosts

def checkBlocklist(host, blocklist):
	return host in blocklist

def extractHTTPHost(p):
	if p.haslayer(HTTPRequest):
		serverIP = p[IP].dst
		domain = p[HTTPRequest].Host.decode('utf-8')
		return [serverIP,domain]
	else:
		serverIP = p[IP].src
		return [serverIP]

def processPCAP(filename,blocklist):
	packets = rdpcap(filename)
	for packet in packets:
		if packet.haslayer(HTTP):
			hosts = extractHTTPHost(packet)
			for host in hosts:
				if checkBlocklist(host,blocklist):
					print("Suspicious connection to %s detected" % host)

blocklist = loadBlocklist("blocklist.txt")
processPCAP('http.cap',blocklist)