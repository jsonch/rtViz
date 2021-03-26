from queue import Queue
from threading import Thread, Event

import subprocess
import time
import re
import copy
import argparse
import dpkt
import socket
import os.path
import pickle as pkl

import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from matplotlib import animation
import matplotlib.patches as mpatch


parser = argparse.ArgumentParser()
# parameters that MUST be set.
parser.add_argument("--cmd", default = "id_drones")
parser.add_argument("--drone", default = None)
parser.add_argument("--pcap", default = None)


def main():
  args = parser.parse_args()
  if (args.cmd == "id_drones"):
    id_drones(args.drone, args.pcap)


def print_subnets(src_cts):
  for (ip, bytect) in src_cts:
    print ("%s : %s"%(ip, bytect))

def id_drones(drone_subnet, pcapfn):
  f = open(pcapfn, "rb")
  pcap = dpkt.pcap.Reader(f)
  src_tbl = {}
  startTs = None
  for ts, buf in pcap:
    if (startTs == None):
      startTs = ts
      ts = 0
    else: 
      ts = ts - startTs
    eth = dpkt.ethernet.Ethernet(buf)
    if (type(eth.data) == dpkt.ip.IP):
      ip = eth.data
      src = socket.inet_ntoa(ip.src)      
      if (drone_subnet in src):
        if (src not in src_tbl):
          src_tbl[src] = 0
          print ("number of sources in subnet: %s"%len(src_tbl))
          print_subnets(src_tbl.items())
        src_tbl[src] += ip.len
  src_cts = sorted(list(src_tbl.items()), key = lambda tup : tup[1])

if __name__ == '__main__':
    main()