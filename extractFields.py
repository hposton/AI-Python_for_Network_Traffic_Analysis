from scapy.all import *

def extractFields(p):
	src = p[IP].src
	dst = p[IP].dst
	if p.haslayer(TCP):
		sport = p[TCP].sport
		dport = p[TCP].dport
		summary = "%s:%d->%s:%d TCP" % (src,sport,dst,dport)
	elif p.haslayer(UDP):
		sport = p[UDP].sport
		dport = p[UDP].dport
		summary = "%s:%d->%s:%d UDP" % (src,sport,dst,dport)
	else:
		summary = "%s->%s" % (src,dst)
	return summary

packets = rdpcap('http.cap')
for packet in packets:
	print(extractFields(packet))