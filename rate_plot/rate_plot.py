import sys, copy, time, signal, select, random
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from matplotlib import animation

matplotlib.use('tkagg')

stime = time.time()

# this script expects an input of: 
# time, variable 1 value, variable 2 value, ... variable n value

# parameters.
y_var_names = ["Attack Rate", "Drone Rate"]
y_colors = ["red", "blue"]

def main():
  if sys.stdin.isatty():
    print("Please use a pipe as stdin\n")
    return 0
  fig, ax, line = startPlot()

  signal.signal(signal.SIGINT, signal_handler)
  print('Starting plot. Press Ctrl+C to exit at any time.')

  runPlot(fig, ax, line)

  print('Data stream terminated. Press Ctrl+C to exit.')
  signal.pause()


def startPlot():
  # l2, = ax.plot(X, Y_min, linestyle = "-.", color = "grey")
  # l3, = ax.plot(X, Y_max,  linestyle = "-.", color = "grey")
  # ax.legend((l1,l3),("average", "best"))
  fig = plt.figure()
  ax = fig.add_subplot(111)
  ax.set_yscale('linear')  # or log
  ax.grid(True)
  ax.set_xlabel("Time")
  ax.set_ylabel("Rate")
  ax.get_xaxis().get_major_formatter().set_scientific(False)
  ax.get_xaxis().get_major_formatter().set_scientific(False)

  lines = []
  for idx, y_var in enumerate(y_var_names):
    print (y_var)
    l1, = ax.plot([], [], label=y_var, color = y_colors[idx])
    lines.append(l1)

  fig.legend()
  fig.show()
  plt.draw()
  return fig, ax, lines

def runPlot(fig, ax, lines):
  K=10
  ani = animation.FuncAnimation(fig, plotUpdate, frames=K, fargs=(fig, ax, lines))
  ani.save('offlinePlot.gif', writer='imagemagick')
  plt.show()

def plotUpdate(num, fig, ax, lines):
  ctime = time.time()
  etime = round(ctime - stime, 2)

  rec = read_input()
  if (rec == False):
    return

  # update the lines
  for l_idx, l in enumerate(lines):
    X = l.get_xdata()
    X = np.append(X, rec[0])
    l.set_xdata(X)

    Y = l.get_ydata()
    Y = np.append(Y, rec[l_idx+1])
    l.set_ydata(Y)

  # rescale axes
  ax.relim()
  ax.autoscale()

  # redraw
  fig.canvas.draw()
  # plt.pause(0.05)
  # fig.canvas.flush_events()

  # Set the title
  ax.set_title("Time {0}".format(etime))


def read_input():
  while (True):
    if (sys.stdin in select.select([sys.stdin], [], [], 1)[0]):
      line = sys.stdin.readline()
      if line:        
        if "," not in line:
          continue
        else:
          rec = line.split(",")
          return [float(v) for v in rec]
      else:
        # EOF
        return False

def signal_handler(sig, frame):
  print('Exitting.')
  sys.exit(0)


if __name__ == '__main__':
  sys.exit(main())
