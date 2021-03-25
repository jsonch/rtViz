# visualization script. Run on server. 
from queue import Queue
from threading import Thread, Event

import subprocess
import time
import re
import copy

import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from matplotlib import animation
import matplotlib.patches as mpatch

client = "10.0.0.1"
attacker = "10.0.0.3"
interval = 1

def main():
  measQ = Queue()

  mthread = Thread(target = measLoop, args = (client, attacker, measQ, interval))
  mthread.daemon = True
  mthread.start()
  plotLoop(measQ)
  mthread.join()


### Flow measurement ###
def measLoop(clientIp, attackIp, measQ, interval = 1):    
  # measure the change in timestamp, client flow size, and attack flow size
  print ("starting flow measurement thread")
  meas = measFlows(clientIp, attackIp)
  time.sleep(interval)
  while (True):
    new_meas = measFlows(clientIp, attackIp)
    meas_delta = calcDelta(meas, new_meas)
    meas = new_meas
    time.sleep(interval)
    measQ.put(meas_delta)

def measFlows(clientIp, attackIp):
  cmd = "./pollflows.sh"
  # measure timestamp (in ms) and all bytes from client and attacker connections
  p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
  outstr = p.stdout.decode("utf-8")
  lines = outstr.split("\n")
  client_bytes, attack_bytes = 0, 0
  # parse through lines for client
  for idx, line in enumerate(lines[1::]):
    idx = idx + 1
    if (clientIp in line):
      flow_bytes = int(re.findall("bytes_received:(\d*) ", lines[idx+1])[0])
      client_bytes += flow_bytes
    if (attackIp in line):
      flow_bytes = int(re.findall("bytes_received:(\d*) ", lines[idx+1])[0])
      attack_bytes += flow_bytes

  ts_ms = int(re.findall("<<(\d*)>>", lines[0])[0])
  return {"ts":ts_ms, "client_bytes":client_bytes, "attack_bytes":attack_bytes}

def calcDelta(prev, cur):
  return {
    "ts":cur["ts"]-prev["ts"], 
    "client_bytes":max(0, cur["client_bytes"]-prev["client_bytes"]),
    "attack_bytes":max(0, cur["attack_bytes"]-prev["attack_bytes"])
  }


### Plotting 
# how many b/s to observe before drawing the "attack!" box
attack_threshold = 400000000 # 400 Mb/s

num_frames_to_record = 80
record_mode = False

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


def plotLoop(measQ):    
  print ("starting plotter")
  G, ax, fig = startTopoPlot()
  runTopoPlot(measQ, G, ax, fig)
  return 1

def startTopoPlot():
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

  return G, ax, fig


def runTopoPlot(measQ, G, ax, fig):
  global num_frames_to_record, record_mode
  if (not record_mode):
    num_frames_to_record = 4
  # run the plot. update in real time, saving the first K frames
  ani = animation.FuncAnimation(fig, topoQuiverUpdate, frames=num_frames_to_record, fargs=(measQ, G, ax))
  if (record_mode):
    ani.save('offlineTopoPlot.gif', writer='imagemagick')
  plt.show()


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
      
# arrow scaling parameters
min_arrow_width = 1.0
max_arrow_width = 5.0
min_flow_rate = 0
max_flow_rate = 10**9 # 1 Gb/s
def bps_to_arrow_width (rate):
  pt_width = ((float(rate) / max_flow_rate) * (max_arrow_width - min_arrow_width)) + min_arrow_width
  pt_width = (pt_width) * .005
  return pt_width

def plot_edge(ax, edge, rate, frame_offset):
  if (rate == 0):
    return # don't plot edges with rate of 0
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
  for pt in vec:
    ax.quiver(pt[0], pt[1], direction[0], direction[1], 
      color = flow_color[flowtype], 
      scale =  10,
      width = pt_width
    )

def draw_alert(ax):
  rectangles = {'Attack!' : mpatch.Rectangle((.25, -.5), .5, .25, linewidth=1, edgecolor='r', color='r')}

  for r in rectangles:
    ax.add_artist(rectangles[r])
    rx, ry = rectangles[r].get_xy()
    cx = rx + rectangles[r].get_width()/2.0
    cy = ry + rectangles[r].get_height()/2.0

    ax.annotate(r, (cx, cy), color='w', weight='bold', 
          fontsize=12, ha='center', va='center')



last_plottime = None
def topoQuiverUpdate(num, measQ, G, ax):
  # plot refresh function. Can be much more efficient. Oh well.
  global last_plottime
  data_in = measQ.get()
  if (last_plottime == None):
    curtime = data_in["ts"]
  else:
    curtime = last_plottime+data_in["ts"]
  last_plottime = curtime

  cli_to_switch = (data_in["client_bytes"]*8.0)
  cli_to_server = cli_to_switch
  atk_to_switch = (data_in["attack_bytes"]*8.0)
  atk_to_server = atk_to_switch
  print ("curtime: %s cli_to_switch: %s, atk_to_switch: %s, cli_to_server: %s, atk_to_server: %s"%
  (curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server))
  rates = {
  frozenset(("Client", "Switch")):cli_to_switch,
  frozenset(("Attacker", "Switch")):atk_to_switch,
  frozenset(("Client", "Server")):cli_to_server,
  frozenset(("Attacker", "Server")):atk_to_server
  }
  ax.clear()
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))
  for node in G.nodes(data=True):
    nx.draw_networkx_nodes(
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
  nx.draw_networkx_labels(G, pos=node_pos, ax=ax)
  # draw each edge individually. 
  for edge in G.edges(data=True):
    edge_key = frozenset((edge[0], edge[1]))
    if (edge[0]=='Switch' and edge[1] == 'Server'):
      if (edge[2]['flow']=='bad'):
        edge_key = frozenset(("Attacker", "Server"))
      else:
        edge_key = frozenset(("Client", "Server"))
    rate = rates[edge_key]
    plot_edge(ax, edge, rate, (num%2*.5))

  # 400 MB/s
  if (atk_to_switch > 400000000):
    draw_alert(ax)

  ax.set_title("Time {0}".format(curtime))





if __name__ == '__main__':
  main()