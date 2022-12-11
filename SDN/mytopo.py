from mininet.topo import Topo

class MyTopo( Topo ):
	
	def __init__(self):

		Topo.__init__(self)

		#Add switch
		switchOne = self.addSwitch('s1')
		switchTwo = self.addSwitch('s2')
		switchThree = self.addSwitch('s3')
		switchFour = self.addSwitch('s4')
		switchFive = self.addSwitch('s5')
		switchSeven = self.addSwitch('s7')

		#Add hosts
		AHost = self.addHost('Jero', ip='10.0.1.100/24', defaultRoute='via 10.0.1.1')
		BHost = self.addHost('Come', ip='10.0.2.100/24', defaultRoute='via 10.0.2.1')
		CHost = self.addHost('Se', ip='10.0.3.100/24', defaultRoute='via 10.0.3.1')
		DHost = self.addHost('Ocea', ip='10.0.4.100/24', defaultRoute='via 10.0.4.1')
		EHost = self.addHost('Gulb', ip='10.0.5.100/24', defaultRoute='via 10.0.5.1')
		ServerHost = self.addHost('Alva', ip='10.0.7.100/24', defaultRoute='via 10.0.7.1')
		AttackerHost = self.addHost('JeroAtk', ip='10.0.1.101/24', defaultRoute='via 10.0.1.1')
		

		#Add links
		self.addLink (switchOne, AHost)
		self.addLink (switchTwo, BHost)
		self.addLink (switchThree, CHost)
		self.addLink (switchFour, DHost)
		self.addLink (switchFive, EHost)
		self.addLink (switchSeven, ServerHost)
		self.addLink (switchOne, switchSeven)
		self.addLink (switchTwo, switchSeven)
		self.addLink (switchThree, switchSeven)
		self.addLink (switchFour, switchSeven)
		self.addLink (switchFive, switchSeven)
		self.addLink (switchOne, AttackerHost)

topos = {'mytopo' : (lambda: MyTopo())}
