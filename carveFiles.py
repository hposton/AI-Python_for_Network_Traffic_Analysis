from scapy.all import *
from scapy.layers.http import *

openConns = []
def carveHTTPFiles(p):
    src = p[IP].src
    dst = p[IP].dst
    sport = p[TCP].sport
    dport = p[TCP].dport
    n = "%s:%d->%s:%d" % (src,sport,dst,dport)
    if p.haslayer(HTTPResponse):
        openConns.append(n)
    elif n not in openConns:
        return
    if p.haslayer(Raw):
        data = p[Raw].load
        with open(n+".file","ab") as f:
            f.write(data)

def processPCAP(filename):
    packets = rdpcap(filename)
    for packet in packets:
        if packet.haslayer(TCP):
            if packet[TCP].sport == 80 or packet[TCP].sport == 443:
                carveHTTPFiles(packet)

processPCAP('http.cap')