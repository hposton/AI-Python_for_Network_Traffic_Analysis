from scapy.all import *
from scapy.layers.http import *

def parseHTTP(p):
    summary = ""
    src = p[IP].src
    dst = p[IP].dst
    sport = p[TCP].sport
    dport = p[TCP].dport
    if p.haslayer(HTTPRequest):
        fields = p[HTTPRequest].fields
        method = fields["Method"].decode('utf-8')
        version = fields["Http_Version"].decode('utf-8')
        url = (fields["Host"]+p[HTTPRequest].Path).decode('utf-8')
        accept = p[HTTPRequest].fields["Accept"].decode('utf-8')
        agent = fields["User_Agent"].decode('utf-8')
        summary = "%s:%d->%s:%d %s %s %s \n\tAccept: %s\n\tAgent: %s\n" % (src,sport,dst,dport,version,method,url,accept,agent)
    elif p.haslayer(HTTPResponse):
        status = p[HTTPResponse].Status_Code.decode('utf-8')
        version = p[HTTPResponse].Http_Version.decode('utf-8')
        content = p[HTTPResponse].Content_Type.decode('utf-8')
        summary = "%s:%d->%s:%d %s %s\n\tContent: %s" % (src,sport,dst,dport,version,status,content)
        if p.haslayer(Raw):
            data = len(p[Raw].load)
            summary += "\n\t%d bytes transfered"%data
    return summary

packets = rdpcap('http.cap')
for packet in packets:
    if packet.haslayer(HTTP):
        print(parseHTTP(packet))