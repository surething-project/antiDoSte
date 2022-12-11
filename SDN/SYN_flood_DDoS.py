from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController		
from mininet.cli import CLI
from mininet.log import setLogLevel, info

import time

def fill_arp_table(net):
	hosts = net.hosts
	for host in hosts:
		host.cmd('ping 10.0.7.100 -c 5 &')
		time.sleep(5)

def start_CROSS_sim(net):
	hosts = net.hosts
	hosts[0].cmd('python3 CROSS_server.py &')
	count = 1
	for host in hosts[1:]:
                #time.sleep(0.19524175275011810454317328309176829944071792138217)
                host.cmd('iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.0.' + str(count) + '.100 -j DROP')
                host.cmd('while true; do python DoS_sc.py 10.0.7.100; done &')
                count += 1

def myNetwork():

	net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

	info( '*** Adding controller\n' )
	c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='0.0.0.0',
                      protocol='tcp',
                      port=6633)

    # Add hosts to the network.
	hserver = net.addHost('Alva', ip='10.0.7.100/24', defaultRoute='via 10.0.7.1')
	h1 = net.addHost('Jero', ip='10.0.1.100/24', defaultRoute='via 10.0.1.1')
	h2 = net.addHost('Come', ip='10.0.2.100/24', defaultRoute='via 10.0.2.1')
	h3 = net.addHost('Se', ip='10.0.3.100/24', defaultRoute='via 10.0.3.1')
	h4 = net.addHost('Ocea', ip='10.0.4.100/24', defaultRoute='via 10.0.4.1')
	h5 = net.addHost('Gulb', ip='10.0.5.100/24', defaultRoute='via 10.0.5.1')

    # Add switches to the network.
	switchOne = net.addSwitch('s1')
	switchTwo = net.addSwitch('s2')
	switchThree = net.addSwitch('s3')
	switchFour = net.addSwitch('s4')
	switchFive = net.addSwitch('s5')
	switchSeven = net.addSwitch('s7')

	net.addLink (switchOne, h1)
	net.addLink (switchTwo, h2)
	net.addLink (switchThree, h3)
	net.addLink (switchFour, h4)
	net.addLink (switchFive, h5)
	net.addLink (switchSeven, hserver)
	net.addLink (switchOne, switchSeven)
	net.addLink (switchTwo, switchSeven)
	net.addLink (switchThree, switchSeven)
	net.addLink (switchFour, switchSeven)
	net.addLink (switchFive, switchSeven)

    # Start execution.
	net.start()

	fill_arp_table(net)

	start_CROSS_sim(net)

	CLI( net )

if __name__ == '__main__':
	setLogLevel( 'info' )  # for CLI output
	myNetwork()
