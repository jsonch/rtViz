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
parser.add_argument("--client", default = None)
parser.add_argument("--attacker", default = None)
parser.add_argument("-i", default = .2)
parser.add_argument("--max", default = 10, help = "maximum expected traffic rate, in Gb/s")
parser.add_argument("--thresh", default = 6, help = "threshold to consider an attack, in Gb/s")
parser.add_argument("--pcap", default = None)

intervalRecTmp = "intervalRecs.tmp.pkl"

# how many b/s to observe before drawing the "attack!" box
attack_threshold = 8**8 # 800 Mb/s

# arrow scaling parameters
min_arrow_width = 1.0
max_arrow_width = 5.0
min_flow_rate = 0
max_flow_rate = 10**9 # 1 Gb/s

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
  print ("interval: %s"%args.i)
  print ("maximum rate (for graph scaling): %s Gb/s"%args.max)
  print ("attack threshold: %s Gb/s"%args.thresh)
  print ("pcap input: %s"%args.pcap)
  global max_flow_rate
  max_flow_rate = 10**9 * float(args.max)
  global attack_threshold
  attack_threshold = 10**9 * float(args.thresh)

  intervalRecs = measIntervals(args.pcap, args.client, args.attacker, args.i)
  plotIntervals(intervalRecs)

def measIntervals(pcapfn, client, attacker, idur):
  if(os.path.isfile(intervalRecTmp)):
    print ("loading interval records from: %s"%intervalRecTmp)
    irecs = pkl.load(open(intervalRecTmp, "rb"))
    irecs[0]['ts'] = 0
    return irecs
  else:
    print ("generating interval records and saving to: %s"%intervalRecTmp)
  # parse the pcap and convert it into interval counter records of attack and drone traffic
  intervalRecs = []
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
      print ("interval %s complete: %s"%(len(intervalRecs), str(cur_rec)))
      intervalRecs.append(cur_rec)
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
  pkl.dump(intervalRecs, open(intervalRecTmp, "wb"))
  return intervalRecs


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

def plotIntervals(intervalRecs):
  print ("plotting %s intervals"%len(intervalRecs))
  drawTopoAnimation(intervalRecs)
  # left off here. do the plot

# todo: add the rate plot in the same frame
def drawTopoAnimation(intervalRecs):
  # Build plot
  fig, ax = plt.subplots(figsize=(6,6))
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))

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

  fig.canvas.draw()
  bg = fig.canvas.copy_from_bbox(ax.bbox)

  ani = animation.FuncAnimation(fig, animateTopoPlot, 
    frames=100, fargs=(intervalRecs, G, ax, fig, bg))
  ani.save("topoPlotOffline.gif", writer = "imagemagick")
  plt.show()


def animateTopoPlot(fnum, intervalRecs, G, ax, fig, bg):
  curtime, rates = get_time_and_rates_from_intervalRecs(fnum, intervalRecs)

  fig.canvas.restore_region(bg)
  plot_edges(bg, fig, ax, G, rates, fnum)
  plot_nodes(bg, fig, ax, G)

  if (rates[frozenset(("Attacker", "Server"))] > attack_threshold):
    plot_alert(bg, fig, ax)

  # fill in the axes rectangle
  # fig.canvas.draw()
  fig.canvas.blit(ax.bbox)


lasttime = 0
def get_time_and_rates_from_intervalRecs(fnum, intervalRecs):
  global lasttime
  rec = intervalRecs[fnum]
  curtime = rec['ts'] + .2
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



def runTopoPlot(measQ, G, ax, fig):
  # get the static background.
  fig.canvas.draw()
  bg = fig.canvas.copy_from_bbox(ax.bbox)
  plt.show(block=False)

  # plot-update loop.
  fnum = 0
  while (True):
    curtime, rates = get_time_and_rates(measQ)
    # reset background. 
    fig.canvas.restore_region(bg)
    plot_edges(bg, fig, ax, G, rates, fnum)
    plot_nodes(bg, fig, ax, G)

    # 400 MB/s
    if (rates[frozenset(("Attacker", "Server"))] > attack_threshold):
      plot_alert(bg, fig, ax)


    # fill in the axes rectangle
    # fig.canvas.draw()
    fig.canvas.blit(ax.bbox)
    fnum += 1
  return 


last_plottime = None
def get_time_and_rates(measQ):
  global last_plottime
  data_in = measQ.get()
  if (last_plottime == None):
    curtime = data_in["ts"]
  else:
    curtime = last_plottime+data_in["ts"]
  last_plottime = curtime

  seconds_elapsed = data_in["ts"]/1000.0
  cli_to_switch = (data_in["client_bytes"]*8.0)/seconds_elapsed
  cli_to_server = cli_to_switch
  atk_to_switch = (data_in["attack_bytes"]*8.0)/seconds_elapsed
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


def plot_nodes(bg, fig, ax, G):
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
  for pt in artists+list(ldict.values()):
      ax.draw_artist(pt)


def plot_alert(bg, fig, ax):
  rectangles = {'Attack!' : mpatch.Rectangle((.25, -.5), .5, .25, linewidth=1, edgecolor='r', color='r')}
  artists = []
  for r in rectangles:
    a = ax.add_artist(rectangles[r])
    rx, ry = rectangles[r].get_xy()
    cx = rx + rectangles[r].get_width()/2.0
    cy = ry + rectangles[r].get_height()/2.0

    an = ax.annotate(r, (cx, cy), color='w', weight='bold', 
          fontsize=12, ha='center', va='center')
    artists.append(a)
    artists.append(an)

  for pt in artists:
    ax.draw_artist(pt)




def plot_edges(bg, fig, ax, G, rates, framenum):
  # draw each edge individually. 
  all_pts = []
  for edge in G.edges(data=True):
    edge_key = frozenset((edge[0], edge[1]))
    if (edge[0]=='Switch' and edge[1] == 'Server'):
      if (edge[2]['flow']=='bad'):
        edge_key = frozenset(("Attacker", "Server"))
      else:
        edge_key = frozenset(("Client", "Server"))
    rate = rates[edge_key]
    pts = plot_edge(ax, edge, rate, (framenum%2*.5))
    all_pts += pts
  # draw new points
  for pt in all_pts:
    ax.draw_artist(pt)


def plot_edge(ax, edge, rate, frame_offset):
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
  pt_width = bps_to_arrow_width(rate)
  vec = interp_vec_of(cur_pos, next_pos, flow_offset[flowtype] + frame_offset, num_pts)
  pts = []
  for pt in vec:
    pts.append(ax.quiver(pt[0], pt[1], direction[0], direction[1], 
      color = flow_color[flowtype], 
      scale =  10,
      width = pt_width
    ))
  return pts

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
      
def bps_to_arrow_width (rate):
  pt_width = ((float(rate) / max_flow_rate) * (max_arrow_width - min_arrow_width)) + min_arrow_width
  pt_width = (pt_width) * .005
  return pt_width







if __name__ == '__main__':
  main()