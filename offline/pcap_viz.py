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
# plt.rcParams['figure.constrained_layout.use'] = True

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
parser.add_argument("--node1_pcap", default=None)

num_frames = 100
fnum_offset = 515

# num_frames = 100000
# fnum_offset = 0


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
  intervalrecs, rtt_df = processPcap(args)
  drawDashboard(args, intervalrecs, rtt_df)

def newRec(ts, drone_ips, attacker_ip):
  rec = {ip:0 for ip in drone_ips}
  rec[attacker_ip] = 0
  rec['ts']=ts
  return rec

def printIntervalRec(intervalrec):
  for (ip, stat) in intervalrec.items():
    print("%s: %s"%(ip, stat))


class RttCalc(object):
  def __init__(self, monitored_ips):
    self.monitored_ips = monitored_ips
    self.send_times = {ip:[] for ip in self.monitored_ips}
    self.rtt_trace = []

  def calc_rtt(self, ip_pkt, ts):
    src = socket.inet_ntoa(ip_pkt.src)
    dst = socket.inet_ntoa(ip_pkt.dst)
    if (type(ip_pkt.data) == dpkt.tcp.TCP):
      tcp = ip_pkt.data
      if (dst in self.monitored_ips):
          self.send_times[dst].append((ts, tcp.seq))
      if (src in self.monitored_ips):
          remaining = []
          for (send_ts, seq) in self.send_times[src]:
            if (tcp.ack > seq):
              rtt = ts - send_ts
              self.rtt_trace.append({
                "ts":ts,
                "rtt":rtt,
                "drone":src
                })
            else:
              remaining.append((send_ts, seq))
          self.send_times[src] = remaining
  def get_df(self):
    print("returning RTT dataframe with %i entries"%(len(self.rtt_trace)))
    return pd.DataFrame(self.rtt_trace)


# get the first attack timestamp from the pcap.
def get_first_attack_timestamp(args, pcapfn):
  f = open(pcapfn, "rb")
  pcap = dpkt.pcap.Reader(f)
  startTs = None
  for ts, buf in pcap:   
    orig_ts = ts 
    if (startTs == None):
      startTs = ts
      ts = 0
    else: 
      ts = ts - startTs
    eth = dpkt.ethernet.Ethernet(buf)
    if (type(eth.data) == dpkt.ip.IP):
      ip = eth.data
      src = socket.inet_ntoa(ip.src)
      if (src == args.attacker):
        return ts

def processServerPcap(pcapfn, idur, drones, attacker):
  intervalrecs = []
  last_interval = 0
  cur_rec = newRec(0, drones, attacker)
  f = open(pcapfn, "rb")
  pcap = dpkt.pcap.Reader(f)
  startTs = None

  rttCalc = RttCalc(drones)
  # process the pcap from the server.
  for ts, buf in pcap:    
    if (startTs == None):
      startTs = ts
      ts = 0
    else: 
      ts = ts - startTs
    interval = int(ts / idur)
    if (interval != last_interval):
      printIntervalRec(cur_rec)
      intervalrecs.append(cur_rec)
      cur_rec = newRec(ts, drones, attacker)
      last_interval = interval
    eth = dpkt.ethernet.Ethernet(buf)
    if (type(eth.data) == dpkt.ip.IP):
      ip = eth.data
      rttCalc.calc_rtt(ip, ts)
      src = socket.inet_ntoa(ip.src)
      iplen = ip.len
      if (src in drones):
        cur_rec[src] += iplen
      elif (src == attacker):
        cur_rec[src] += iplen
  return intervalrecs, rttCalc.get_df()

def get_node1_ts_offset(args):
  first_attack_ts_server = get_first_attack_timestamp(args, args.pcap)
  first_attack_ts_attack = get_first_attack_timestamp(args, args.node1_pcap)
  print ("first attack timestamp at server: %s"%first_attack_ts_server)
  print ("first attack timestamp at node1: %s"%first_attack_ts_attack)
  print ("node1 start +=: %s"%(first_attack_ts_server - first_attack_ts_attack))
  node1_ts_increment = first_attack_ts_server - first_attack_ts_attack
  return node1_ts_increment

def processAttackerPcap(pcapfn, idur, attacker, node1_ts_increment, intervalrecs):
  attacker_sent_bytes = 0  
  last_interval = None
  f = open(pcapfn, "rb")
  pcap = dpkt.pcap.Reader(f)
  startTs = None
  for ts, buf in pcap:    
    if (startTs == None):
      startTs = ts
      ts = 0
    else: 
      ts = ts - startTs
    ts = ts + node1_ts_increment
    interval = int(ts / idur) -1 # off by one because of timing alignment. might need to remove this to sync in a differetn run .
    if (last_interval == None):
      last_interval = interval
    if (interval != last_interval):
      intervalrecs[interval]["attacker_sent_bytes"] = attacker_sent_bytes
      print ("t: %s attacker_bytes: %s"%(ts, attacker_sent_bytes))
      print (intervalrecs[interval])
      attacker_sent_bytes = 0
      last_interval = interval
    eth = dpkt.ethernet.Ethernet(buf)
    if (type(eth.data) == dpkt.ip.IP):
      ip = eth.data
      src = socket.inet_ntoa(ip.src)
      # TODO: check that dst is server too
      if (src == attacker):
        attacker_sent_bytes += ip.len
  print ("done parsing attacker records.")
  return intervalrecs

def processPcap(args):
  interval_rec_temp = args.pcap+".recs.pkl"
  if( (not args.recalc) and ((os.path.isfile(interval_rec_temp)))):
    print ("loading interval records and rtt_df from: %s"%interval_rec_temp)
    intervalrecs, rtt_df = pkl.load(open(interval_rec_temp, "rb"))
    return intervalrecs, rtt_df
  else:
    print ("generating interval records and rtt_df and saving to: %s"%interval_rec_temp)

  # process the pcap from the server 
  intervalrecs, rtt_df = processServerPcap(args.pcap, args.i, args.drones, args.attacker)

  # process the pcap from the attacker (node1) to augment intervalrecs
  print ("adding interval records from attacker perspective.")
  attacker_ts_increment = get_node1_ts_offset(args)
  intervalrecs = processAttackerPcap(args.node1_pcap, args.i, args.attacker, attacker_ts_increment, intervalrecs)

  print ("saving output to: %s"%interval_rec_temp)
  pkl.dump((intervalrecs, rtt_df), open(interval_rec_temp, "wb"))
  return intervalrecs, rtt_df


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

# finish processing the rate dataframe
def add_topo_rate_cols(rate_df, drone_ips, atk_ip):
  agg_drone_ct = rate_df[drone_ips].sum(axis=1)
  interval = np.average(rate_df.diff().ts[1:-1])
  agg_drone_rate = (agg_drone_ct / interval) * 8.0
  
  rate_df['drone_tx'] = agg_drone_rate
  rate_df['drone_rx'] = agg_drone_rate
  rate_df['atk_tx'] = (rate_df["attacker_sent_bytes"] / interval) * 8.0
  rate_df['atk_rx'] = (rate_df[atk_ip] / interval) * 8.0
  return rate_df.fillna(0)

def df_of_intervalrecs(intervalrecs):
  return pd.DataFrame(intervalrecs)


def drawDashboard(args, intervalrecs, rtt_df):
  print ("plotting %s intervals"%len(intervalrecs))
  interval_df = df_of_intervalrecs(intervalrecs)
  interval_df = add_topo_rate_cols(interval_df, args.drones, args.attacker)
  # drawFrame(args, intervalrecs, rtt_df)
  drawFrame_vertical(args, intervalrecs, rtt_df, interval_df)

def set_agg_lims(ax):
  ax.set_ylim((.5, 5*(10**12)))

def setup_rate_pane(ax):
  ax.set_yscale("log")
  ax.set_xlabel("time (seconds)")
  ax.set_ylabel("(log) bit rate")
  ax.xaxis.set_major_locator(MaxNLocator(integer=True))
  set_agg_lims(ax)

def setup_topo_pane(ax):
  ax.axis('off')

def setup_drone_pane(ax):
  ax.set_ylim((0, 20))
  ax.set_xlim((0, 500))
  ax.yaxis.set_major_locator(MaxNLocator(integer=True))
  ax.set_xlabel("drone control round trip time (ms)")
  ax.set_ylabel("count")


def right_shift_ax(ax):
  box = ax.get_position()
  box.x0 = box.x0 + 0.11
  # box.x1 = box.x1 + 0.05
  box.y0 = box.y0 + 0.03
  box.y1 = box.y1 + 0.03
  ax.set_position(box)
  return ax


def vertical_init():
  # initialization for vertical layout 
  fig = plt.figure(figsize=(6, 12)) 
  # gs = gridspec.GridSpec(4, 1, figure=fig)
  # gs.update(wspace=0.025, hspace=0.2) # set the spacing between axes. 

  outer_gs = gridspec.GridSpec(2, 1)
  hspace = .3
  lb = 0.01
  ub = 1.0 - lb
  outer_gs.update(wspace = 0, hspace = .1, top = ub, bottom = lb, right = ub, left = lb)
  topo_gs = gridspec.GridSpecFromSubplotSpec(1, 1, subplot_spec = outer_gs[0], hspace = 0, wspace = 0)
  line_gs = gridspec.GridSpecFromSubplotSpec(2, 1, subplot_spec = outer_gs[1], hspace=hspace)
  # topo plot
  ax_topo = plt.subplot(topo_gs[0])
  setup_topo_pane(ax_topo)
  # rate plot 
  ax_agg = plt.subplot(line_gs[0])
  setup_rate_pane(ax_agg)  
  ax_agg = right_shift_ax(ax_agg)


  # rtt plot
  ax_drones = plt.subplot(line_gs[1])
  setup_drone_pane(ax_drones)
  ax_drones = right_shift_ax(ax_drones)

  # plt.tight_layout()

  axes = (ax_topo, ax_drones, ax_agg)
  return fig, axes


# todo: add the rate plot in the same frame
def drawFrame_vertical(args, intervalrecs, rtt_df, interval_df):
  fig, axes = vertical_init()
  # call animator
  ani = animation.FuncAnimation(fig, animateFig,
    # frames=len(intervalrecs), 
    frames=min(num_frames, len(intervalrecs)),
    interval = int(args.i*1000), blit = True, fargs=(args, G,
      intervalrecs, rtt_df, interval_df, fig, axes)
    )
  out_fn = args.pcap+".plot.vertical.html"
  matplotlib.rcParams["animation.bitrate"]=1000
  out_bin = ani.to_html5_video()
  print ("saving to file: %s"%out_fn)
  open(out_fn, "w").write(out_bin)
  # ani.save(args.out_fn, writer = "imagemagick")
  # plt.show() # don't show the plot in real time.
  return


def animateFig(fnum, args, G, intervalrecs, rtt_df, interval_df, fig, axes):
  print ("FRAME %s"%fnum)
  fnum = fnum + fnum_offset # FOR TESTING!
  (ax_topo, ax_drones, ax_agg) = axes
  topo_artists = animateTopoAx(fnum, args, intervalrecs, interval_df, G, ax_topo, fig)
  agg_artists = animateAggAx(fnum, args, intervalrecs, interval_df, G, ax_agg, fig)
  drone_artists = animateDroneAx(fnum, args, intervalrecs, G, ax_drones, fig, rtt_df)
  return topo_artists + agg_artists

# =====================================
# =           topology pane           =
# =====================================

def get_cur_from_rate_df(interval_df, i):
  rates = {
  frozenset(("Drones", "Switch")):interval_df.drone_tx[i],
  frozenset(("Attacker", "Switch")):interval_df.atk_tx[i],
  frozenset(("Drones", "Server")):interval_df.drone_rx[i],
  frozenset(("Attacker", "Server")):interval_df.atk_rx[i]
  }
  print (rates)
  return interval_df.ts[i], rates

def animateTopoAx(fnum, args, intervalrecs, interval_df, G, ax, fig):
  curtime, rates = get_cur_from_rate_df(interval_df, fnum)
  ax.clear()
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))
  artists = []
  edge_artists = plot_edges(args, fig, ax, G, rates, fnum)
  node_artists = plot_nodes(args, fig, ax, G)
  # stat_artists  = plot_stats(args, fig, ax, rates)
  # artists+=stat_artists
  artists+=edge_artists
  artists+=node_artists
  if (rates[frozenset(("Attacker", "Switch"))] > args.thresh):
    alert_artists = plot_alert(args, fig, ax)
    artists+=alert_artists

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


def get_edge_key(edge):
  edge_key = frozenset((edge[0], edge[1]))
  if (edge[0]=='Switch' and edge[1] == 'Server'):
    if (edge[2]['flow']=='bad'):
      edge_key = frozenset(("Attacker", "Server"))
    else:
      edge_key = frozenset(("Drones", "Server"))
  return edge_key


def plot_edges(args, fig, ax, G, rates, framenum):
  # draw each edge individually. 
  all_artists = []
  for edge in G.edges(data=True):
    edge_key = get_edge_key(edge)
    rate = rates.get(edge_key, 0)
    # mod 2 * .5 is the per-frame offset for the movement animation.
    artists = plot_edge(args, ax, edge, rate, (framenum%2*.5))
    all_artists += artists
  return all_artists

def plot_edge(args, ax, edge, rate, frame_offset):
  if (rate == 0):
    return [] # don't plot edges with rate of 0
  name = edge[0]
  flowtype = edge[2]['flow']
  flow_rate = rate
  # positioning and size
  cur_pos, next_pos = cur_pos_of(name, flowtype)
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

def cur_pos_of(name, flowtype):
  cur_pos = copy.copy(node_pos[name])
  next_pos = copy.copy(node_pos[next_hop[name]] )   
  cur_pos[1] = cur_pos[1] + flow_align_offset[flowtype]
  next_pos[1] = next_pos[1] + flow_align_offset[flowtype]

  cur_pos = np.array(cur_pos)
  next_pos = np.array(next_pos)
  return cur_pos, next_pos

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


# ======  End of topology pane  =======

# ======================================
# =           drone rtt pane           =
# ======================================


# animate a plot that shows drone connection quality. 
def animateDroneAx(fnum, args, intervalrecs, G, ax, fig, rtt_df):
  cur_ts = fnum * args.i
  ax.clear()

  setup_drone_pane(ax)
  samples = rtt_df[rtt_df["ts"]<cur_ts]["rtt"][-20:]
  ax.hist(samples*1000)

  return []


# ======  End of drone rtt pane  =======


# =======================================
# =           throughput pane           =
# =======================================

# animate aggregate throughput plot. 
agg_x = []
agg_drone_y = []
agg_attack_y = []

# current attack state machine
atk_sm = {
  "active":False,
  "start":0
}

# attack intervals (start time:end time)
atk_intervals = {}
def update_atk_intervals(cur_atk_rx, cur_ts):
  global atk_sm, atk_intervals
  prev_sm = copy.copy(atk_sm)
  # update the state machine.
  if (not atk_sm["active"]):
    if (cur_atk_rx > 0):
      atk_sm["active"] = True
      atk_sm["start"] = cur_ts
  else:
    if (cur_atk_rx == 0):
      atk_sm["active"] = False
      atk_sm["start"] = 0

  # if an attack is ongoing or just completed, 
  # update the attack records 
  if (prev_sm["active"] or atk_sm["active"]):
    atk_start = max(prev_sm["start"], atk_sm["start"])
    atk_end = max(atk_start, cur_ts)
    atk_intervals[atk_start] = atk_end


def overlay_attacks(ax, interval):
  # box: 
  # observed attack duration: X ms
  # arrow to first 
  global atk_intervals
  artists = []
  for t_start, t_end in atk_intervals.items():
    t_dur = max(t_end - t_start, interval) # attacks are at least 1 interval.
    t_dur_ms = int(t_dur * 1000)
    alertstr = "Observed attack\nduration: %i ms"%t_dur_ms
    a = ax.annotate(
      alertstr, 
      xy=(t_end-.2, 10), 
      xytext=(t_end-.2, .001),
      color = "red",
      fontweight = "bold",
      arrowprops=dict(facecolor='red', shrink = 0.05, edgecolor = 'red'),
      bbox=dict(facecolor='white', alpha=1.0, edgecolor = "red")      
    )

    # a = ax.text(t_end-1, .001, alertstr, color = "red")
    artists.append(a)
  return artists


max_window = 10

def animateAggAx(fnum, args, intervalrecs, interval_df, G, ax, fig):
  ax.clear()
  global agg_x, agg_drone_y, agg_attack_y

  cur_ts = interval_df.ts[fnum]
  interval = np.average(interval_df.diff().ts[1:-1])
  drone_agg_rate = interval_df.drone_rx[fnum]
  attack_rate = interval_df.atk_rx[fnum]
  print ("AGG -- drone: %s attacker: %s"%(drone_agg_rate, attack_rate))

  global atk_intervals
  prev_atk_intervals = copy.copy(atk_intervals)
  update_atk_intervals(attack_rate, cur_ts)
  if (prev_atk_intervals != atk_intervals):
    print ("new attack detected!")
    print (atk_intervals)

  agg_x.append(cur_ts)
  agg_drone_y.append(drone_agg_rate + 1)
  agg_attack_y.append(attack_rate + 1)

  # clear and redraw
  ax.clear()
  setup_rate_pane(ax)
  drone_line,  = ax.plot(agg_x, agg_drone_y, label = "drones", color = "b")
  attack_line,  = ax.plot(agg_x, agg_attack_y, label = "attacker", color = "r", linestyle = "-.")
  ax.legend(loc = "upper left")


  artists = overlay_attacks(ax, interval)

  # ax.autoscale()
  # ax.relim()
  max_x = np.max(agg_x)
  min_x = max(np.min(agg_x), max_x - max_window)
  ax.set_xlim((min_x, max_x))

  set_agg_lims(ax)

  return [drone_line, attack_line]+artists

# ======  End of throughput pane  =======



# dataframe-based revision -- not used, no time

# temporary dataframe.
temp_df_fn = "trace.df"

def parse_recs_raw(pcapfn, location):
  recs = []
  f = open(pcapfn, "rb")
  pcap = dpkt.pcap.Reader(f)
  for idx, (ts, buf) in enumerate(pcap):
    eth = dpkt.ethernet.Ethernet(buf)
    if (type(eth.data) == dpkt.ip.IP):
      ip = eth.data
      src = socket.inet_ntoa(ip.src)
      dst = socket.inet_ntoa(ip.dst)
      proto = ip.p
      seq = None
      ack = None
      sport = None
      dport = None
      if (type(ip.data) == dpkt.tcp.TCP):
        tcp = ip.data
        seq = tcp.seq
        ack = tcp.ack
        sport = tcp.sport
        dport = tcp.dport
      recs.append({
        "location":location,
        "ts":ts,
        "len":ip.len,
        "src":src,
        "dst":dst,
        "proto":proto,
        "seq":seq,
        "ack":ack,
        "sport":sport,
        "dport":dport
        })
    if (idx % 100000 == 0):
      print ("parsing %s at ts: %s"%(pcapfn, ts))
  return recs



def pcaps_to_df(args):
  if( (not args.recalc) and ((os.path.isfile(temp_df_fn)))):
    print ("loading from: %s"%temp_df_fn)
    return pd.read_pickle(temp_df_fn)
  else:
    server_pcapfn = args.pcap
    attacker_pcapfn = args.node1_pcap
    server_recs = parse_recs_raw(server_pcapfn, "server")
    attacker_recs = parse_recs_raw(attacker_pcapfn, "attacker")
    df = pd.DataFrame(server_recs+attacker_recs)
    print ("saving to: %s"%temp_df_fn)
    pd.to_pickle(df, temp_df_fn)
    return df
def df_main():
  args = check_args()
  # convert trace into a dataframe
  trace_df = pcaps_to_df(args)
  # make plots.
  # plotIntervals(args, trace_df)


def sync_df_ts(df):
  # sync timestamps in trace from node1 and node2
  return df




if __name__ == '__main__':
  main()