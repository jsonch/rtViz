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
import matplotlib.image as mpimg
from matplotlib import gridspec
from matplotlib.ticker import MaxNLocator

import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from matplotlib import animation
import matplotlib.patches as mpatch
import pandas as pd

parser = argparse.ArgumentParser()
# parameters that MUST be set.
parser.add_argument("--drones", nargs=5, default = ['10.250.253.248', '10.250.253.249', '10.250.253.250', '10.250.253.251', '10.250.253.252'])
parser.add_argument("--attacker", default = '10.64.5.130')
parser.add_argument("--pcap", default = None)
# parameters that should not have to be set for current demo.
parser.add_argument("-i", default = .2, type = float)
parser.add_argument("--max", default = 5.0, type = float, help = "maximum expected traffic rate, in Gb/s")
parser.add_argument("--thresh", default = 4.0, type = float, help = "threshold to consider an attack, in Gb/s")
# parameters that should never have to change.
parser.add_argument("--min", default = 0.0, type = float, help = "minimum expected traffic rate (gb/s)")
parser.add_argument("--min_arrow_width", default = 1.0, type = float)
parser.add_argument("--max_arrow_width", default = 5.0, type = float)
parser.add_argument("--recalc", default = False, action = "store_true",  help = "recalculate counters?")


def check_args():
  args = parser.parse_args()
  if (len(args.drones) != 5):
    print ("error: must provide the ip of all 5 drones")
    quit()
  if (args.attacker == None):
    print ("error: must provide ip of attacker.")
  if (args.pcap == None):
    print ("error: must provide pcap")
    quit()
  print ("---- arguments ---- ")
  print ("drone   IPs: %s"%args.drones)
  print ("attacker IP: %s"%args.attacker)
  print ("frame interval: %ss"%args.i)
  print ("maximum rate (for graph scaling): %s Gb/s"%args.max)
  print ("attack threshold: %s Gb/s"%args.thresh)
  print ("pcap trace: %s"%args.pcap)  
  args.max = args.max * 10**9
  args.thresh = args.thresh * 10**9
  return  args

def main():
  args = check_args()
  intervalrecs, iats, rtts= measIntervals(args)
  plotIntervals(args, intervalrecs, iats, rtts)

def newRec(ts, drone_ips, attacker_ip):
  rec = {ip:0 for ip in drone_ips}
  rec[attacker_ip] = 0
  rec['ts']=ts
  return rec

def printIntervalRec(intervalrec, iats):
  for (ip, stat) in intervalrec.items():
    print("%s: %s"%(ip, stat))
  # print ("---iat standard deviation ----")
  # for (ip, pts) in iats.items():
  #   tses, iatlist = zip(*pts)
  #   print("%s: %s"%(ip, np.std(iatlist[-10::])))
  # print ("-------")


send_times = {}

def calc_rtt(args, ip_pkt, ts):
  global send_times
  src = socket.inet_ntoa(ip_pkt.src)
  dst = socket.inet_ntoa(ip_pkt.dst)

  if (send_times == {}):
    send_times = {ip:[] for ip in args.drones}
  if (type(ip_pkt.data) == dpkt.tcp.TCP):
    tcp = ip_pkt.data
    if (dst in args.drones):
        send_times[dst].append((ts, tcp.seq))
    if (src in args.drones):
        results = []
        remaining = []
        for (send_ts, seq) in send_times[src]:
          if (tcp.ack > seq):
            rtt = ts - send_ts
            results.append((ts, rtt))
          else:
            remaining.append((send_ts, seq))
        send_times[src] = remaining
        return results
  return []



def measIntervals(args):
  drones, attacker, idur, pcapfn\
  = args.drones, args.attacker, args.i, args.pcap
  interval_rec_temp = args.pcap+".recs.pkl"
  if( (not args.recalc) and ((os.path.isfile(interval_rec_temp)))):
    print ("loading interval records and iats from: %s"%interval_rec_temp)
    intervalrecs, iats, rtts = pkl.load(open(interval_rec_temp, "rb"))
    return intervalrecs, iats, rtts
  else:
    print ("generating interval records and iats and saving to: %s"%interval_rec_temp)
  # parse the pcap and convert it into interval counter records of attack and drone traffic
  intervalrecs = []
  last_interval = 0
  cur_rec = newRec(0, drones, attacker)
  f = open(pcapfn, "rb")
  pcap = dpkt.pcap.Reader(f)
  startTs = None

  lastArrivals = {ip:0 for ip in args.drones}
  lastArrivals[args.attacker] = 0
  # (timestamp, iat)
  iats = {ip:[] for ip in args.drones}
  # (rtt, iat)
  rtts = {ip:[] for ip in args.drones}

  for ts, buf in pcap:    
    if (startTs == None):
      startTs = ts
      ts = 0
    else: 
      ts = ts - startTs
    interval = int(ts / idur)
    if (interval != last_interval):
      rtts_len = 0
      for (k, v) in rtts.items():
        rtts_len += len(v)
      print ("rtts_len: %s"%rtts_len)
      print ("t: %s"%ts)
      printIntervalRec(cur_rec, iats)
      intervalrecs.append(cur_rec)
      cur_rec = newRec(ts, drones, attacker)
      last_interval = interval
    eth = dpkt.ethernet.Ethernet(buf)
    if (type(eth.data) == dpkt.ip.IP):
      ip = eth.data
      src = socket.inet_ntoa(ip.src)

      new_rtts = calc_rtt(args, ip, ts)
      if new_rtts != []:
        rtts[src]+=new_rtts
      iplen = ip.len
      if (src in drones):
        cur_rec[src] += iplen
        iat = ts - lastArrivals[src]
        iats[src].append((ts, iat))
        lastArrivals[src] = ts
      elif (src == attacker):
        cur_rec[src] += iplen
  print ("saving output to: %s"%interval_rec_temp)

  pkl.dump((intervalrecs, iats, rtts), open(interval_rec_temp, "wb"))
  return intervalrecs, iats, rtts


### Plotting 

# network graph
G = nx.MultiDiGraph()
G.add_node('Attacker', color = 'red')
G.add_node('Switch', color = 'grey')
G.add_node('Drones', color = 'blue')
G.add_node('Server', color = 'blue')
G.add_edge('Drones', 'Switch', color = 'blue', flow='good')
G.add_edge('Attacker', 'Switch', color = 'red', flow='bad')
G.add_edge('Switch', 'Server', color = 'blue', flow='good')
G.add_edge('Switch', 'Server', color = 'red', flow='bad')

next_hop = {
  "Attacker":"Switch",
  "Drones":"Switch",
  "Switch":"Server"
}

# for i in range(5):
#   G.add_node("Drone%s"%i, color = 'blue')
#   next_hop["Drone%s"%i] = "Switch"

node_pos = {
  "Attacker":[-.75, -.75],
  "Drones":[-.75, .75],
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


def agg_bps_at(fnum, intervalrecs, interval, nodes):
  return 8 * (sum([intervalrecs[fnum][dip] for dip in nodes])) / interval


lasttime = 0
def get_time_and_rates_from_intervalrecs(fnum, args, intervalrecs):
  global lasttime
  rec = intervalrecs[fnum]
  print (rec)
  curtime = rec['ts'] + args.i
  print ("curtime: %s lasttime: %s"%(curtime, lasttime))
  dur = curtime - lasttime  
  lasttime = rec['ts']

  cli_to_switch = agg_bps_at(fnum, intervalrecs, args.i, args.drones)
  cli_to_server = cli_to_switch

  atk_to_switch = agg_bps_at(fnum, intervalrecs, args.i, [args.attacker])
  atk_to_server = atk_to_switch

  print ("curtime: %s cli_to_switch: %s, atk_to_switch: %s, cli_to_server: %s, atk_to_server: %s"%
  (curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server))
  rates = {
  frozenset(("Drones", "Switch")):cli_to_switch,
  frozenset(("Attacker", "Switch")):atk_to_switch,
  frozenset(("Drones", "Server")):cli_to_server,
  frozenset(("Attacker", "Server")):atk_to_server
  }
  return curtime, rates


def iats_to_dataframe(iats):
  recs = []
  for (key, vals) in iats.items():
    for (ts, iat) in vals:
      recs.append({
        "ts":ts,
        "iat":iat,
        "drone":key
        })
  return pd.DataFrame(recs)

def rtts_to_dataframe(rtts):
  recs = []
  for (key, vals) in rtts.items():
    for (ts, rtt) in vals:
      recs.append({
        "ts":ts,
        "rtt":rtt,
        "drone":key
        })
  return pd.DataFrame(recs)


def plotIntervals(args, intervalrecs, iats, rtts):
  print ("plotting %s intervals"%len(intervalrecs))
  iat_df = iats_to_dataframe(iats)
  rtt_df = rtts_to_dataframe(rtts)
  drawTopoAnimation(args, intervalrecs, iat_df, rtt_df)

# todo: add the rate plot in the same frame
def drawTopoAnimation(args, intervalrecs, iat_df, rtt_df):
  # left pane: ax_topo
  # right pane, top: ax_drones
  # right pane, bottom: ax_agg
  fig = plt.figure(figsize=(12, 6)) 
  gs = gridspec.GridSpec(2, 10)

  ax_topo = plt.subplot(gs[:, 0:5])
  ax_topo.axis('off')

  ax_drones = plt.subplot(gs[0, 5:10])
  ax_drones.set_ylim((0, 20))
  ax_drones.set_xlim((0, 500))
  ax_drones.plot([1, 2, 3], [2, 2, 2])

  ax_agg = plt.subplot(gs[1, 5:10])
  drone_line,  = ax_agg.plot([], [], label = "drones", color = "b")
  attack_line,  = ax_agg.plot([], [], label = "attacker", color = "r", linestyle = "-.")
  ax_agg.set_yscale("log")
  ax_agg.legend(loc = "upper left")
  ax_agg.set_xlabel("time (seconds)")
  ax_agg.set_ylabel("(log) bit rate")
  agg_lines = (drone_line, attack_line)
  ax_agg.set_ylim((.5, 5*(10**9)+10**10))

  plt.tight_layout()

  axes = (ax_topo, ax_drones, ax_agg)

  # call animator
  ani = animation.FuncAnimation(fig, animateFig,
    frames=len(intervalrecs), 
    # frames=10,
    interval = int(args.i*1000), blit = True, fargs=(args, intervalrecs, G, axes, fig, agg_lines, iat_df, rtt_df))
  out_fn = args.pcap+".plot.html"
  print ("saving to file: %s"%out_fn)
  matplotlib.rcParams["animation.bitrate"]=1000
  open(out_fn, "w").write(ani.to_html5_video())
  # ani.save(args.out_fn, writer = "imagemagick")
  # plt.show() # don't show the plot in real time.
  return

def animateFig(fnum, args, intervalrecs, G, axes, fig, agg_lines, iat_df, rtt_df):
  print ("FRAME %s"%fnum)
  (ax_topo, ax_drones, ax_agg) = axes
  topo_artists = animateTopoAx(fnum, args, intervalrecs, G, ax_topo, fig)
  agg_artists = animateAggAx(fnum, args, intervalrecs, G, ax_agg, fig, agg_lines)
  drone_artists = animateDroneAx(fnum, args, intervalrecs, G, ax_drones, fig, iat_df, rtt_df)
  return topo_artists + agg_artists

def animateTopoAx(fnum, args, intervalrecs, G, ax, fig):
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


# animate a plot that shows drone connection quality. 
def animateDroneAx(fnum, args, intervalrecs, G, ax, fig, iat_df, rtt_df):
  iat_window = 100
  cur_ts = fnum * args.i
  ax.clear()
  # samples = iat_df[iat_df["ts"]<cur_ts]["iat"][-20:]
  # ax.hist(samples*1000)
  # ax.set_ylim((0, 20))
  # ax.yaxis.set_major_locator(MaxNLocator(integer=True))
  # ax.set_xlim((0, 500))
  # ax.set_xlabel("drone packet inter-arrival time (ms)")
  # ax.set_ylabel("count")



  samples = rtt_df[rtt_df["ts"]<cur_ts]["rtt"][-20:]
  ax.hist(samples*1000)
  ax.set_ylim((0, 20))
  ax.yaxis.set_major_locator(MaxNLocator(integer=True))
  ax.set_xlim((0, 500))
  ax.set_xlabel("drone control round trip time (ms)")
  ax.set_ylabel("count")

  return []



# animate aggregate throughput plot. 
agg_x = []
agg_drone_y = []
agg_attack_y = []
def animateAggAx(fnum, args, intervalrecs, G, ax, fig, agg_lines):
  global agg_x, agg_drone_y, agg_attack_y
  (drone_line, attack_line) = agg_lines

  drone_agg_rate = agg_bps_at(fnum, intervalrecs, args.i, args.drones)
  attack_rate = agg_bps_at(fnum, intervalrecs, args.i, [args.attacker]) +1
  print ("AGG -- drone: %s attacker: %s"%(drone_agg_rate, attack_rate))

  if (agg_x == []):
    agg_x = [args.i]
  else:
    agg_x.append(agg_x[-1]+args.i)
  agg_drone_y.append(drone_agg_rate)
  agg_attack_y.append(attack_rate)

  drone_line.set_data(agg_x, agg_drone_y)
  attack_line.set_data(agg_x, agg_attack_y)
  ax.autoscale()
  ax.relim()
  ax.set_ylim((.5, 5*(10**9)+10**10))

  return [drone_line, attack_line]


def plot_stats(args, fig, ax, rates):
  cli_rate = rates[frozenset(("Drones", "Switch"))]/float(10**6)
  atk_rate = rates[frozenset(("Attacker", "Switch"))]/float(10**6)
  rectangles = {
    "Drones rate:\n%.2f Mb/s"%cli_rate : mpatch.Rectangle((-.26, .75), .5, .25, linewidth=1, edgecolor='k', color="grey"),
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
        edge_key = frozenset(("Drones", "Server"))
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
  num_pts = bps_to_num_pts(args, rate)

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

def bps_to_num_pts (args, rate):
  min_log_rate = 4
  max_log_rate = 10
  min_num_pts = 2
  max_num_pts = 8

  # rates in log scale:
  # normal: 5
  # bad: 4
  # attack: 9.6
  num_pts = 4
  if (rate < 25000):
    num_pts = num_pts / 2
  elif (rate > 100000000):
    num_pts = num_pts * 2

  return int(num_pts)




if __name__ == '__main__':
  main()