#!/usr/bin/env python

"""
Simple example of setting network and CPU parameters
NOTE: link params limit BW, add latency, and loss.
There is a high chance that pings WILL fail and that
iperf will hang indefinitely if the TCP handshake fails
to complete.
"""

from sys import argv

from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info

from mininet.nodelib import LinuxBridge
from mininet.node import OVSBridge

class DemoTopo(Topo):
    def __init__(self):

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        client = self.addHost('client', ip="10.0.0.1")
        server = self.addHost('server', ip="10.0.0.2")
        attacker = self.addHost('attacker', ip="10.0.0.3")
        s1 = self.addSwitch('s1', cls=OVSBridge) # LinuxBridge so no controller needed

        # Add links
        self.addLink(client, s1, bw=2) # bw in mbps
        self.addLink(server, s1, bw=1000)
        self.addLink(attacker, s1)

def attackCli():
    topo = DemoTopo()
    net = Mininet( topo=topo, controller=None,
                   host=CPULimitedHost, link=TCLink,
                   autoStaticArp=True)
    net.start()
    info( "Hosts:\n" )
    dumpNodeConnections(net.hosts)

    a, s, c = net.getNodeByName('attacker', 'server', 'client')

    s.cmd('iperf -s &')
    c.cmd('iperf -c 10.0.0.2 -t 600 > client_iperf.log.txt &')
    a.cmd('iperf -c 10.0.0.2 -t 600 > attacker_iperf.log.txt &')
    # net.iperf( ( a, s ), l4Type='TCP' )
    # net.iperf( ( c, s ), l4Type='TCP' )

    CLI( net )

    net.stop()

def attackTest():
    topo = DemoTopo()
    net = Mininet( topo=topo, controller=None,
                   host=CPULimitedHost, link=TCLink,
                   autoStaticArp=True)
    net.start()
    info( "Hosts:\n" )
    dumpNodeConnections(net.hosts)
    info( "Testing bandwidth between attacker and server\n" )
    a, s = net.getNodeByName('attacker', 'server')
    net.iperf( ( a, s ), l4Type='TCP' )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    attackCli()
