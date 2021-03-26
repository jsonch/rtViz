# offline visualization from pcap
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
parser.add_argument("--client", default = None)
parser.add_argument("--attacker", default = None)
parser.add_argument("--pcap", default = None)
# parameters that should not have to be set for current demo.
parser.add_argument("--out_fn", default = "topoPlot.html")
parser.add_argument("-i", default = .2, type = float)
parser.add_argument("--max", default = 10.0, type = float, help = "maximum expected traffic rate, in Gb/s")
parser.add_argument("--thresh", default = 6.0, type = float, help = "threshold to consider an attack, in Gb/s")
# parameters that should never have to change.
parser.add_argument("--min", default = 0.0, type = float, help = "minimum expected traffic rate (gb/s)")
parser.add_argument("--min_arrow_width", default = 1.0, type = float)
parser.add_argument("--max_arrow_width", default = 5.0, type = float)
parser.add_argument("--interval_rec_temp", default = "intervalrecs.tmp.pkl")


def main():
  args = parser.parse_args()
  if (((args.client == None) or (args.attacker == None))):
    print ("error: you must either run in testmode (--test) or provide client (--client) and attacker (--attacker) IP address.")
    quit()
  if (args.pcap == None):
    print ("please provide a pcap (--pcap)")
    quit()
  print ("arguments: ")
  print ("client   IP: %s"%args.client)
  print ("attacker IP: %s"%args.attacker)
  print ("frame interval: %ss"%args.i)
  print ("maximum rate (for graph scaling): %s Gb/s"%args.max)
  print ("attack threshold: %s Gb/s"%args.thresh)
  print ("pcap input: %s"%args.pcap)
  args.max = args.max * 10**9
  args.thresh = args.thresh * 10**9
  intervalrecs = measIntervals(args)
  plotIntervals(args, intervalrecs)

def measIntervals(args):
  client, attacker, idur, interval_rec_temp, pcapfn\
  = args.client, args.attacker, args.i, args.interval_rec_temp, args.pcap
  if(os.path.isfile(interval_rec_temp)):
    print ("loading interval records from: %s"%interval_rec_temp)
    irecs = pkl.load(open(interval_rec_temp, "rb"))
    irecs[0]['ts'] = 0
    return irecs
  else:
    print ("generating interval records and saving to: %s"%interval_rec_temp)
  # parse the pcap and convert it into interval counter records of attack and drone traffic
  intervalrecs = []
  last_interval = 0
  cur_rec = {"ts":0, "client":0, "attacker":0}
  f = open(pcapfn, "rb")
  pcap = dpkt.pcap.Reader(f)
  startTs = None
  for ts, buf in pcap:
    if (startTs == None):
      startTs = ts
      ts = 0
    else: 
      ts = ts - startTs
    interval = int(ts / idur)
    if (interval != last_interval):
      print ("interval %s complete: %s"%(len(intervalrecs), str(cur_rec)))
      intervalrecs.append(cur_rec)
      cur_rec = {"ts":ts, "client":0, "attacker":0}
      last_interval = interval
    eth = dpkt.ethernet.Ethernet(buf)
    if (type(eth.data) == dpkt.ip.IP):
      ip = eth.data
      src = socket.inet_ntoa(ip.src)
      iplen = ip.len
      if (src == client):
        cur_rec["client"] += iplen
      elif (src == attacker):
        cur_rec["attacker"]+= iplen
  pkl.dump(intervalrecs, open(interval_rec_temp, "wb"))
  return intervalrecs


### Plotting 

next_hop = {
  "Attacker":"Switch",
  "Client":"Switch",
  "Switch":"Server"
}
node_pos = {
  "Attacker":[-.75, -.75],
  "Client":[-.75, .75],
  "Switch":[0, 0],
  "Server":[.75, 0]
}
flow_offset = {
  "good":0,
  "bad":0
}
flow_align_offset = {
  "good":0,
  "bad":-.1
}
flow_color = {
  "good":"blue",
  "bad":"red"
}

def plotIntervals(args, intervalrecs):
  print ("plotting %s intervals"%len(intervalrecs))
  drawTopoAnimation(args, intervalrecs)
  # left off here. do the plot

# todo: add the rate plot in the same frame
def drawTopoAnimation(args, intervalrecs):
  # Create a graph
  G = nx.MultiDiGraph()
  G.add_node('Attacker', color = 'red')
  G.add_node('Switch', color = 'grey')
  G.add_node('Client', color = 'blue')
  G.add_node('Server', color = 'blue')
  G.add_edge('Client', 'Switch', color = 'blue', flow='good')
  G.add_edge('Attacker', 'Switch', color = 'red', flow='bad')
  G.add_edge('Switch', 'Server', rad = .1, color = 'blue', flow='good')
  G.add_edge('Switch', 'Server', rad = .4, color = 'red', flow='bad')

  # initialize plot
  fig, ax = plt.subplots(figsize=(6,6))
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))
  plt.axis('off')

  # call animator
  ani = animation.FuncAnimation(fig, animateTopoPlot,
    frames=len(intervalrecs), 
    # frames=10,
    interval = int(args.i*1000), blit = True, fargs=(args, intervalrecs, G, ax, fig))
  print ("saving to file: %s"%args.out_fn)
  matplotlib.rcParams["animation.bitrate"]=1000
  open(args.out_fn, "w").write(ani.to_html5_video())
  # ani.save(args.out_fn, writer = "imagemagick")
  # plt.show() # don't show the plot in real time.
  return

def animateTopoPlot(fnum, args, intervalrecs, G, ax, fig):
  print ("FRAME %s"%fnum)
  curtime, rates = get_time_and_rates_from_intervalrecs(fnum, args, intervalrecs)
  ax.clear()
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))
  artists = []
  edge_artists = plot_edges(args, fig, ax, G, rates, fnum)
  node_artists = plot_nodes(args, fig, ax, G)
  stat_artists  = plot_stats(args, fig, ax, rates)
  artists+=stat_artists
  artists+=edge_artists
  artists+=node_artists
  if (rates[frozenset(("Attacker", "Server"))] > args.thresh):
    alert_artists = plot_alert(args, fig, ax)
    artists+=alert_artists
  return artists



lasttime = 0
def get_time_and_rates_from_intervalrecs(fnum, args, intervalrecs):
  global lasttime
  rec = intervalrecs[fnum]
  curtime = rec['ts'] + args.i
  print ("curtime: %s lasttime: %s"%(curtime, lasttime))
  dur = curtime - lasttime  
  lasttime = rec['ts']

  cli_to_switch = (rec["client"]*8.0)/dur
  cli_to_server = cli_to_switch
  atk_to_switch = (rec["attacker"]*8.0)/dur
  atk_to_server = atk_to_switch
  print ("curtime: %s cli_to_switch: %s, atk_to_switch: %s, cli_to_server: %s, atk_to_server: %s"%
  (curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server))
  rates = {
  frozenset(("Client", "Switch")):cli_to_switch,
  frozenset(("Attacker", "Switch")):atk_to_switch,
  frozenset(("Client", "Server")):cli_to_server,
  frozenset(("Attacker", "Server")):atk_to_server
  }
  return curtime, rates

def plot_stats(args, fig, ax, rates):
  cli_rate = rates[frozenset(("Client", "Switch"))]/float(10**6)
  atk_rate = rates[frozenset(("Attacker", "Switch"))]/float(10**6)
  rectangles = {
    "Client rate:\n%.2f Mb/s"%cli_rate : mpatch.Rectangle((-.26, .75), .5, .25, linewidth=1, edgecolor='k', color="grey"),
    "Attack rate:\n%.2f Mb/s"%atk_rate : mpatch.Rectangle((.25, .75), .5, .25, linewidth=1, edgecolor='k', color="grey")
  }
  return plot_rectangles(ax, rectangles, "k")

def plot_alert(args, fig, ax):
  rectangles = {'Attack!' : mpatch.Rectangle((.25, -.5), .5, .20, linewidth=1, edgecolor='r', color='r')}
  return plot_rectangles(ax, rectangles, "w")


def plot_rectangles(ax, rectangles, fontcolor):
  artists = []
  for r in rectangles:
    a = ax.add_artist(rectangles[r])
    rx, ry = rectangles[r].get_xy()
    cx = rx + rectangles[r].get_width()/2.0
    cy = ry + rectangles[r].get_height()/2.0
    an = ax.annotate(r, (cx, cy), color=fontcolor, weight='bold', 
          fontsize=12, ha='center', va='center')
    artists.append(a)
    artists.append(an)
  return artists


def plot_nodes(args, fig, ax, G):
  artists = []
  for node in G.nodes(data=True):
    a = nx.draw_networkx_nodes(
      G, 
      node_pos, 
      [node[0]], 
      # node_color=node[1]['color'], 
      linewidths=5,
      edgecolors=node[1]['color'],
      node_color="white",
      ax = ax, 
      node_size=2500,
      node_shape = "s"
    )
    artists.append(a)
  ldict = nx.draw_networkx_labels(G, pos=node_pos, ax=ax)
  return (artists+list(ldict.values()))
  # for pt in artists+list(ldict.values()):
  #     ax.draw_artist(pt)


def plot_edges(args, fig, ax, G, rates, framenum):
  # draw each edge individually. 
  all_artists = []
  for edge in G.edges(data=True):
    edge_key = frozenset((edge[0], edge[1]))
    if (edge[0]=='Switch' and edge[1] == 'Server'):
      if (edge[2]['flow']=='bad'):
        edge_key = frozenset(("Attacker", "Server"))
      else:
        edge_key = frozenset(("Client", "Server"))
    rate = rates[edge_key]
    artists = plot_edge(args, ax, edge, rate, (framenum%2*.5))
    all_artists += artists
  return all_artists
  # draw new points
  # for pt in all_pts:
  #   ax.draw_artist(pt)


def plot_edge(args, ax, edge, rate, frame_offset):
  if (rate == 0):
    return [] # don't plot edges with rate of 0
  name = edge[0]
  flowtype = edge[2]['flow']
  flow_rate = rate
  cur_pos = copy.copy(node_pos[name])
  next_pos = copy.copy(node_pos[next_hop[name]] )   
  cur_pos[1] = cur_pos[1] + flow_align_offset[flowtype]
  next_pos[1] = next_pos[1] + flow_align_offset[flowtype]

  cur_pos = np.array(cur_pos)
  next_pos = np.array(next_pos)

  direction = direction_of(cur_pos, next_pos)
  # if rate is over 5, draw more arrows
  num_pts = 5
  if (rate > 5):
    num_pts = 5
  pt_width = bps_to_arrow_width(args, rate)
  vec = interp_vec_of(cur_pos, next_pos, flow_offset[flowtype] + frame_offset, num_pts)
  artists = []
  for pt in vec:
    artists.append(ax.quiver(pt[0], pt[1], direction[0], direction[1], 
      color = flow_color[flowtype], 
      scale =  10,
      width = pt_width
    ))
  return artists

def direction_of(cur_pos, next_pos): 
  direction = [next_pos[i] - cur_pos[i] for i in range(len(cur_pos))]
  return direction

def interp_vec_of(cur_pos, next_pos, offset, n):
  total_delta = np.array(direction_of(cur_pos, next_pos))
  vec = []
  delta = total_delta/float(n)
  for i in range(n):      
    vec.append(cur_pos + (i+offset)*delta)
  return vec
      
def bps_to_arrow_width (args, rate):
  pt_width = ((float(rate) / args.max) * (args.max_arrow_width - args.min_arrow_width)) + args.min_arrow_width
  pt_width = (pt_width) * .005
  return pt_width







if __name__ == '__main__':
  main()