import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import *

def processPCAP(filename):
    packets = rdpcap(filename)
    conns = {}
    ips = []
    for p in packets:
        if p.haslayer(IP):
            src = p[IP].src
            dst = p[IP].dst
            if src not in ips:
                ips.append(src)
            if dst not in ips:
                ips.append(dst)
            if src in conns:
                if dst not in conns[src]:
                    conns[src].append(dst)
            else:
                conns[src] = [dst]
    return [ips,conns]

def buildGraph(ips,conns):
    G = nx.Graph()
    for ip in ips:
        print(ip)
        G.add_node(ip)
    for src in conns:
        for dst in conns[src]:
            G.add_edge(src,dst)
    nx.draw(G,with_labels=True)
    plt.show()
    return G

ips,conns = processPCAP('http.cap')
G = buildGraph(ips,conns)