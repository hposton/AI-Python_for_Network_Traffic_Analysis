from scapy.all import *

def updateRecord(rec,client, server,l,d,flags):
    if rec["flags"] is not None and flags is not None:
        if flags not in rec["flags"]:
            rec["flags"].append(flags)
    if d == "cs":
        rec["csdata"] += l
    else:
        rec["scdata"] += l
    return rec

def genFlows(filame):
    packets = rdpcap(filame)
    flows = {}
    for packet in packets:
        src = packet[IP].src
        dst = packet[IP].dst
        l = packet[IP].len
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto = "tcp"
            flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto = "udp"
            flags = None
        else:
            continue
        source = ':'.join([src,str(sport)])
        dest = ':'.join([dst,str(dport)])
        if not source in flows and not dest in flows: # New connection
            flows[source] = {}
        if source in flows: # Likely client -> server
            if not dest in flows[source]:
                rec = {"csdata":0,"scdata":0,"flags":[],"proto":proto}
            else:
                rec = flows[source][dest]
            flows[source][dest] = updateRecord(rec,source,dest,l,"cs",flags)
        elif dest in flows:
            if not source in flows[dest]:
                rec = {"csdata":0,"scdata":0,"flags":None,"proto":proto}
            else:
                rec = flows[dest][source]
            flows[dest][source] = updateRecord(rec,dest,source,l,"sc",flags)
    return flows

def printFlows(flows):
    for client in flows:
        for server in flows[client]:
            flow = flows[client][server]
            if flow["proto"] == "tcp":
                flags = "/".join(flow["flags"])
                print("%s->%s %s [%s] C->S:%d S->C:%d" % (client,server,flow["proto"],flags,flow["csdata"],flow["scdata"]))
            else:
                print("%s->%s %s C->S:%d S->C:%d" % (client,server,flow["proto"],flow["csdata"],flow["scdata"]))

flows = genFlows('http.cap')
printFlows(flows)