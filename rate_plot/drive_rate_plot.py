import time, sys, random 

# generates some test data for live_rate_plot.py

# parameters
num_y_vars = 2
interval = .5

def main():
    curtime = 0
    for i in range(100):
        vec = [curtime]+[random.randint(1, 10) for i in range(num_y_vars)]
        printstr = ["%s" for v in vec]
        printstr = ", ".join(printstr) + "\n"
        print (printstr%tuple(vec), flush = True)
        curtime += interval
        time.sleep(interval)
    return 0

if __name__ == '__main__':
    sys.exit(main())
