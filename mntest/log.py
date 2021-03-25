# log rates at server

from queue import Queue
from threading import Thread, Event

import subprocess
import time
import re


client = "10.0.0.1"
attacker = "10.0.0.3"

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

def measLoop(clientIp, attackIp, interval = 1):    
    # measure the change in timestamp, client flow size, and attack flow size
    meas = measFlows(clientIp, attackIp)
    time.sleep(interval)
    while (True):
        new_meas = measFlows(clientIp, attackIp)
        meas_delta = calcDelta(meas, new_meas)
        meas = new_meas
        print (meas_delta)
        time.sleep(interval)


def main():

    mthread = Thread(target = measLoop, args = (client, attacker))
    mthread.daemon = True
    mthread.start()
    mthread.join()


if __name__ == '__main__':
    main()