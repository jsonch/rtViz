import sys, copy, time, signal, select, random
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from matplotlib import animation
import matplotlib.patches as mpatch

matplotlib.use('tkagg')

stime = time.time()

record_mode = False
num_frames_to_record = 80

# plots csv-formatted data read on standard input.
# expects each line to have the format: time, value


def main():
  layout, G, ax, fig = startTopoPlot()
  runTopoPlot(layout, G, ax, fig)
  exit(1)

  if sys.stdin.isatty():
    print("Please use a pipe as stdin\n")
    return 0
  fig, ax, line = startPlot()

  signal.signal(signal.SIGINT, signal_handler)
  print('Starting plot. Press Ctrl+C to exit at any time.')

  continuePlot(fig, ax, line)

  print('Data stream terminated. Press Ctrl+C to exit.')
  signal.pause()



def startTopoPlot():
  # Build plot
  fig, ax = plt.subplots(figsize=(6,6))
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))
  cloc = .75 # corner location

  # Create a graph and layout
  G = nx.MultiDiGraph()
  G.add_node('Attacker', color = 'red')
  G.add_node('Switch', color = 'grey')
  G.add_node('Client', color = 'blue')
  G.add_node('Server', color = 'blue')
  G.add_edge('Client', 'Switch', color = 'blue', flow='good')
  G.add_edge('Attacker', 'Switch', color = 'red', flow='bad')
  G.add_edge('Switch', 'Server', rad = .1, color = 'blue', flow='good')
  G.add_edge('Switch', 'Server', rad = .4, color = 'red', flow='bad')

  pos = {
    "Attacker" : [-1*cloc, -1*cloc],
    "Client" : [-1*cloc, cloc],
    "Switch" : [0, 0],
    "Server" : [cloc, 0]
  }
  return pos, G, ax, fig


def runTopoPlot(layout, G, ax, fig):
  global num_frames_to_record, record_mode
  if (not record_mode):
    num_frames_to_record = 2
  # run the plot. update in real time, saving the first K frames
  ani = animation.FuncAnimation(fig, topoQuiverUpdate, frames=num_frames_to_record, fargs=(layout, G, ax))
  # ani = animation.FuncAnimation(fig, topoPlotUpdate, frames=K, fargs=(layout, G, ax))
  ani.save('offlineTopoPlot.gif', writer='imagemagick')
  plt.show()




##### quiver-based edges 
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
  vec = interp_vec_of(cur_pos, next_pos, flow_offset[flowtype] + frame_offset, num_pts)
  pt_width = np.log(rate+.1)*.02
  pt_width = rate*.005+.1
  min_width = 1
  max_width = 5.0
  min_rate = 1
  max_rate = 20
  pt_width = ((float(rate) / max_rate) * (max_width - min_width)) + min_width
  pt_width = (pt_width) * .005
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




def topoQuiverUpdate(num, pos, G, ax):
  data_in = read_input()

  if (data_in == False):
    return 
  curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server = data_in
  print ("curtime: %s cli_to_switch: %s, atk_to_switch: %s, cli_to_server: %s, atk_to_server: %s"%
    (curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server))
  rates = {
    frozenset(("Client", "Switch")):cli_to_switch,
    frozenset(("Attacker", "Switch")):atk_to_switch,
    frozenset(("Client", "Server")):cli_to_server,
    frozenset(("Attacker", "Server")):atk_to_server
  }
  ctime = time.time()
  etime = round(ctime - stime, 2)
  ax.clear()
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))
  for node in G.nodes(data=True):
  # for node in []:
    nx.draw_networkx_nodes(
      G, 
      pos, 
      [node[0]], 
      # node_color=node[1]['color'], 
      linewidths=5,
      edgecolors=node[1]['color'],
      node_color="white",
      ax = ax, 
      node_size=2500,
      node_shape = "s"
    )
  nx.draw_networkx_labels(G, pos=pos, ax=ax)
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

  if (cli_to_server < 1):
    draw_alert(ax)
  # Set the title

  ax.set_title("Time {0}".format(etime))



def testreadinput():
  while (True):
    read_input()
    time.sleep(1)
  return

def read_input() :
  while (True):
    if (sys.stdin in select.select([sys.stdin], [], [], 1)[0]):
      line = sys.stdin.readline()
      if line:        
        if "," not in line:
          continue
        else:
          curtime, cli_to_switch, atk_to_switch, cli_to_server, atk_to_server = line.split(",")          
          return (float(curtime), float(cli_to_switch), float(atk_to_switch), float(cli_to_server), float(atk_to_server))
      else:
        # EOF
        return False




##### 2d plots 

X = []
Y = []


def startPlot():
  # l2, = ax.plot(X, Y_min, linestyle = "-.", color = "grey")
  # l3, = ax.plot(X, Y_max,  linestyle = "-.", color = "grey")
  # ax.legend((l1,l3),("average", "best"))
  fig = plt.figure()
  ax = fig.add_subplot(111)
  ax.set_yscale('linear')  # or log
  ax.grid(True)
  ax.set_xlabel("Time")
  ax.set_ylabel("Value")
  ax.get_xaxis().get_major_formatter().set_scientific(False)
  fig.show()
  ax.get_xaxis().get_major_formatter().set_scientific(False)
  l1, = ax.plot(X, Y)
  plt.draw()
  return fig, ax, l1


def continuePlot(fig, ax, l1):
  while True:
    # break if there's no new input for 60 seconds.
    i, o, e = select.select([sys.stdin], [], [], 60)
    if not i:
      break
    line = sys.stdin.readline()
    print ("read line: %s" % line)
    if line == '':
      break
    # only plot actual lines data lines.
    if "," not in line:
      continue
    t, v = line.split(",")

    # add number to array, plot the data
    X.append(float(t))
    Y.append(float(v))
    l1.set_xdata(X)
    l1.set_ydata(Y)

    # rescale axes
    ax.relim()
    ax.autoscale()

    # redraw
    plt.draw()
    fig.canvas.flush_events()
  return 0


def signal_handler(sig, frame):
  print('Exitting.')
  sys.exit(0)

## OLD CODE, NOT USED
# plot with rate represented by arrow sizes.
def topoPlotUpdate(num, pos, G, ax):
  ctime = time.time()
  etime = round(ctime - stime, 2)
  ax.clear()
  ax.set_xlim((-1, 1))
  ax.set_ylim((-1, 1))

  for node in G.nodes(data=True):
    nx.draw_networkx_nodes(
      G, 
      pos, 
      [node[0]], 
      # node_color=node[1]['color'], 
      linewidths=5,
      edgecolors=node[1]['color'],
      node_color="white",
      ax = ax, 
      node_size=2500,
      node_shape = "s"
    )
  nx.draw_networkx_labels(G, pos=pos, ax=ax)
  # draw each edge individually. 
  for edge in G.edges(data=True):
    cur_rate = random.randint(1, 10)
    st = f"arc3, rad = .1"
    if "rad" in edge[2]:
      st = f"arc3, rad = {edge[2]['rad']}"
    nx.draw_networkx_edges(G, pos, edgelist=[edge], 
      width = cur_rate, 
      # arrowstyle = matplotlib.patches.ArrowStyle.Simple(tail_width = cur_rate * .5, head_width = cur_rate),
      # arrowstyle = matplotlib.patches.ArrowStyle.Wedge(tail_width=1, shrink_factor=.8),
      arrowsize = cur_rate*5,
      min_source_margin = 20,
      min_target_margin = 30,
      connectionstyle=st,
      edge_color = edge[2]['color'])
  # Set the title
  ax.set_title("Time {0}".format(etime))




if __name__ == '__main__':
  sys.exit(main())
