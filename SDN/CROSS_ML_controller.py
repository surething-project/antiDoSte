from pox.core import core
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp, echo
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
from cryptography.fernet import Fernet

import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
import time
import pox

from threading import *
import os

log = core.getLogger()

# Router Configurations
info_table = dict()
info_table[1] = {'Local Networks':'10.0.1.0/24','Gateway':'10.0.1.1', 'MAC':'AA:BB:CC:DD:EE:01', 'Destination Address':'10.0.7.0/24', 'Next Hop':'10.0.7.1'}
info_table[2] = {'Local Networks':'10.0.2.0/24','Gateway':'10.0.2.1', 'MAC':'AA:BB:CC:DD:EE:02', 'Destination Address':'10.0.7.0/24', 'Next Hop':'10.0.7.1'}
info_table[3] = {'Local Networks':'10.0.3.0/24','Gateway':'10.0.3.1', 'MAC':'AA:BB:CC:DD:EE:03', 'Destination Address':'10.0.7.0/24', 'Next Hop':'10.0.7.1'}
info_table[4] = {'Local Networks':'10.0.4.0/24','Gateway':'10.0.4.1', 'MAC':'AA:BB:CC:DD:EE:04', 'Destination Address':'10.0.7.0/24', 'Next Hop':'10.0.7.1'}
info_table[5] = {'Local Networks':'10.0.5.0/24','Gateway':'10.0.5.1', 'MAC':'AA:BB:CC:DD:EE:05', 'Destination Address':'10.0.7.0/24', 'Next Hop':'10.0.7.1'}
info_table[6] = {'Local Networks':'10.0.6.0/24','Gateway':'10.0.6.1', 'MAC':'AA:BB:CC:DD:EE:06', 'Destination Address':'10.0.7.0/24', 'Next Hop':'10.0.7.1'}
info_table[7] = {'Local Networks':'10.0.7.0/24','Gateway':'10.0.7.1', 'MAC':'AA:BB:CC:DD:EE:07', 'Destination Address':'10.0.1.0/24 10.0.2.0/24 10.0.3.0/24 10.0.4.0/24 10.0.5.0/24 10.0.6.0/24', 'Next Hop':'10.0.1.1 10.0.2.1 10.0.3.1 10.0.4.1 10.0.5.1 10.0.6.1'}


#   For each Router object created, it will query for their respective configurations
#   Each router :
#       +   are uniquely identified via their DPID
#       +   has their own CAM, Routing, ARP tables
#   Each different network that exists in a Router will be represented as two different interfaces

#   TODO - 1:   ICMP Destination Unreachable
#   TODO - 2:   Send out buffered frames awaiting for ARP Replies

class Router(object):
    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Switch DPID
        self.dpid = connection.dpid

        # Buffer for packets waiting for ARP
        self.buffer = dict()

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = dict()

        self.t0 = time.time()
        self.frame_number = 0 #will be converted to string

        self.TCP_packets = {}
        self.packets = {}

        # Router Interfaces
        self.interfaces = dict()
        self.interfaces[info_table[self.dpid]['Gateway']] = {'MAC':info_table[self.dpid]['MAC'], 'Network':info_table[self.dpid]['Local Networks']}
        log.debug("%s %s" % (self.dpid, self.interfaces))

        # ARP Table
        self.arp_table = dict()

        self.threshold = 5
        self.tracker = {}
        self.warmup = False
        self.warmup2 = False
        self.foults = {}
        global in_analysis
        in_analysis = []
        global in_analysis_behavior
        in_analysis_behavior = []
        global attackers
        attackers = []
        self.next_http = []
        
        # key generation
        global key
        key = Fernet.generate_key()
  
        # string the key in a file
        with open('pox/misc/filekey.key', 'wb') as filekey:
            filekey.write(key)
       

        # Routing Table
        self.routing_table = dict()
        if len(info_table[self.dpid]['Destination Address'].split(" ")) > 1:
            i = 0
            while i < len(info_table[self.dpid]['Destination Address'].split(" ")):
                self.routing_table[info_table[self.dpid]['Destination Address'].split(" ")[i]] = {'Next Hop' : info_table[self.dpid]['Next Hop'].split(" ")[i], 'Connected': info_table[self.dpid]['Gateway']}
                i = i + 1
        else:
            self.routing_table[info_table[self.dpid]['Destination Address']] = {'Next Hop' : info_table[self.dpid]['Next Hop'], 'Connected': info_table[self.dpid]['Gateway']}
        log.debug("%s %s" % (self.dpid, self.routing_table))

    def myThread(self, src, dst):
        done = False
        #with open('pox/misc/filekey.key', 'rb') as filekey:
        #    key = filekey.read()
        
        #fernet = Fernet(self.key)
        while 1:
            x = os.listdir(r"pox/misc/aux_files")
            for f in x:
                if "_prediction" in f:
                    while os.stat("pox/misc/aux_files/" + f).st_size == 0:
                        time.sleep(0.1)
                    prediction = []

                    #with open("pox/misc/aux_files/" + f, 'r') as enc_file:
                    enc_file = open("pox/misc/aux_files/" + f, 'r')
                    for entry in enc_file:
                        prediction.append(entry.split(' ')[:len(entry.split(' ')) - 1])
                    #print(entry)
                    #    encrypted = enc_file.read()
                    #decrypted = fernet.decrypt(encrypted)
                    #line = decrypted.decode('UTF-8').split('\n')
                    #prediction.pop()
                    #print(prediction)

                    
                    if prediction[0].count('1.0') * 2 > prediction[0].count('0.0'):
                        print("Mitigating " + f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3])
                        #self.connection.send(of.ofp_flow_mod(priority=99, command=of.OFPFC_ADD, match=of.ofp_match(dl_src = src, dl_dst = dst), actions = [of.ofp_action_vlan_vid(vlan_vid = 1)]))
                        self.connection.send(of.ofp_flow_mod(priority=99, command=of.OFPFC_ADD, match=of.ofp_match(dl_vlan=1)))
                        attackers.append([src, dst])
                    #print(file.split("_")[0] + '.' + file.split("_")[1] + '.' + file.split("_")[2] + '.' + file.split("_")[3])
                    print("O que esta na lista in_analysis e " + str(in_analysis))
                    self.TCP_packets[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]] = []
                    in_analysis.remove(f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3])
                    print(attackers)
                    os.remove("pox/misc/aux_files/" + f)
                    done = True
                    break
            if done == True:
                break
                

    def myThread2(self, src, dst, ip):
        done = False
        #with open('pox/misc/filekey.key', 'rb') as filekey:
         #   key = filekey.read()
        
        fernet = Fernet(key)
        while 1:
            x = os.listdir(r"pox/misc/normal_behavior")
            for f in x:
                if ip.split('.')[0] + '_' + ip.split('.')[1] + '_' + ip.split('.')[2] + '_' + ip.split('.')[3] + "_encrypted_encrypted_prediction" in f:
                    while os.stat("pox/misc/normal_behavior/" + f).st_size == 0:
                        time.sleep(0.1)
                    prediction = []
                    

                    with open("pox/misc/normal_behavior/" + f, 'rb') as enc_file:
                        encrypted = enc_file.read()
                    decrypted = fernet.decrypt(encrypted)
                    line = decrypted.decode('UTF-8').split('\n')
                    for entry in line:
                        prediction.append(entry.split(' ')[:len(entry.split(' ')) - 1])
                    prediction.pop()
                    #print(prediction)

                    os.remove("pox/misc/normal_behavior/" + f)
                    if prediction[0].count(u'1') * 2 > prediction[0].count(u'0'):
                        print(f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3] + "_111111111111111111111111111111111111111111111")
                        if f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3] not in self.foults:
                            self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]] = [1,0]
                        else:
                            self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]] = [self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]][0] + 1, 0]
                        
                        if self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]][0] >= 3:
                            print(f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3] + "_2222222222222222222222222222222222222222222")
                            print("Mitigating " + f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3])
                            #self.connection.send(of.ofp_flow_mod(priority=99, command=of.OFPFC_ADD, match=of.ofp_match(dl_src = src, dl_dst = dst), actions = [of.ofp_action_vlan_vid(vlan_vid = 1)]))
                            self.connection.send(of.ofp_flow_mod(priority=99, command=of.OFPFC_ADD, match=of.ofp_match(dl_vlan=1)))
                            attackers.append([src, dst])
                    else:
                       if f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3] in self.foults:
                            if self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]][1] == 0:
                                self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]] = [self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]][0], 1]
                            else:
                                if self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]][0] > 1:
                                    self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]] = [self.foults[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]][0] - 1, 0]
                                else:
                                    self.foults.pop(self.foults.keys().index(f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]))     
                                    
                    done = True
                    #print("O que esta na lista in_analysis e " + str(in_analysis_behavior))
                    #print(file.split("_")[0] + '.' + file.split("_")[1] + '.' + file.split("_")[2] + '.' + file.split("_")[3])
                    in_analysis_behavior.remove(f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3])
                    self.packets[f.split("_")[0] + '.' + f.split("_")[1] + '.' + f.split("_")[2] + '.' + f.split("_")[3]] = []
            if done:
                break

            #time.sleep(5)

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in.pack()

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)
    
    def drop_packet(self, packet_in):

        msg = of.ofp_packet_out()
        msg.data = packet_in.pack()

        # Add an action to send to the specified port
        action = of.ofp_action_vlan_vid(vlan_vid=1)
        msg.actions.append(action)
        action = of.ofp_action_output(port=of.OFPP_TABLE)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def ARP_Handler(self, etherFrame, packet_in):
        log.debug("%s ARP FRAME RECEIVED FROM %s" % (self.dpid, packet_in.in_port))

        # ARP Request
        if etherFrame.payload.opcode == arp.REQUEST:
            log.debug("IT'S AN ARP REQUEST!")

            arp_payload = etherFrame.payload
            # Is the ARP Request for the Router's Interface/ Gateway?
            arp_request_protodst = str(arp_payload.protodst)
            if arp_request_protodst in self.interfaces:
                # Construct ARP Reply
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = EthAddr(self.interfaces[arp_request_protodst]['MAC'])
                arp_reply.hwdst = arp_payload.hwsrc
                arp_reply.protosrc = arp_payload.protodst
                arp_reply.protodst = arp_payload.protosrc

                ether = ethernet()
                ether.type = ether.ARP_TYPE
                ether.src = EthAddr(self.interfaces[arp_request_protodst]['MAC'])
                ether.dst = arp_payload.hwsrc
                ether.payload = arp_reply
                self.resend_packet(ether, packet_in.in_port)
                log.debug("%s ARP REPLY SENT!" % self.dpid)
            # ARP Request for other hosts in LAN
            else:
                msg = of.ofp_packet_out()
                msg.data = etherFrame
                msg.in_port = packet_in.in_port
                msg.actions.append((of.ofp_action_output(port = of.OFPP_FLOOD)))
                self.connection.send(msg)
                log.debug("%s ARP REQUEST FLOODED TO OTHER PORTS" % self.dpid)

        # ARP Replies
        elif etherFrame.payload.opcode == arp.REPLY:
            log.debug("IT'S AN ARP REPLY!")

            arp_payload = etherFrame.payload
            # Did the Router make the ARP Request?
            arp_reply_protodst = str(arp_payload.protodst)
            if arp_reply_protodst in self.interfaces:
                arp_reply_hwsrc = str(arp_payload.hwsrc)
                arp_reply_protosrc = str(arp_payload.protosrc)

                if arp_reply_protosrc not in self.arp_table:
                    self.arp_table[arp_reply_protosrc] = arp_reply_hwsrc
                    self.mac_to_port[arp_reply_hwsrc] = packet_in.in_port
                    log.debug("%s %s INSTALLED TO CAM TABLE" % (arp_reply_protosrc, arp_reply_hwsrc))
            # Forward the ARP Reply
            else:
                self.resend_packet(etherFrame, self.mac_to_port[str(arp_payload.hwdst)])
                log.debug("ARP Reply from %s to %s forwarded" % (arp_payload.hwsrc, arp_payload.hwdst))
                    

    def save_TCP_packet(self, etherFrame, frameLen, proto):
        frame_lengh = str(frameLen)
        t = time.time() - self.t0
        time_live = str(etherFrame.payload.ttl)
                
        TCP_datagram = etherFrame.payload.payload
        if proto == 0 or proto == 2:
            src_port = str(TCP_datagram.srcport)
            dst_port = str(TCP_datagram.dstport)
            SYN_flag = int(TCP_datagram.SYN == True)
            ACK_flag = int(TCP_datagram.ACK == True)
            RST_flag = int(TCP_datagram.RST == True)
        else:
            src_port = 0
            dst_port = 0
            SYN_flag = 0
            ACK_flag = 0
            RST_flag = 0

        ip_packet = etherFrame.payload
        destination_ip = str(ip_packet.dstip)

        if destination_ip == "10.0.7.100":
            if str(etherFrame.payload.srcip) not in self.TCP_packets:
                self.TCP_packets[str(etherFrame.payload.srcip)] = [[t, self.frame_number, frame_lengh, src_port, dst_port, SYN_flag, ACK_flag, RST_flag, time_live, proto]]

            elif str(etherFrame.payload.srcip) in self.TCP_packets:
                self.TCP_packets[str(etherFrame.payload.srcip)] += [[t, self.frame_number, frame_lengh, src_port, dst_port, SYN_flag, ACK_flag, RST_flag, time_live, proto]]
                
    def save_packet(self, etherFrame, frameLen, proto):
        frame_lengh = str(frameLen)
        t = time.time() - self.t0
        time_live = str(etherFrame.payload.ttl)
                
        datagram = etherFrame.payload.payload
        if proto == 0 or proto == 2:
            src_port = str(datagram.srcport)
            dst_port = str(datagram.dstport)
            SYN_flag = int(datagram.SYN == True)
            ACK_flag = int(datagram.ACK == True)
            if proto == 0:
                if "1.1" in datagram.payload:
                    version = 1.1
                else:
                    version = 1.0
                if "GET" in datagram.payload:
                    req_type = 1
                else:
                    req_type = 2
                try:
                    if datagram.payload.split('\n')[4].startswith("Get Synchronization and") and len(datagram.payload.split('\n')[4]) == 34:
                        data = 1
                    else:
                        data = 2
                except:
                    data = 0             
            else:
                version = 0.0
                req_type = 0
                data = 0
        else:
            src_port = 0
            dst_port = 0
            SYN_flag = 0
            ACK_flag = 0
            version = 0.0
            req_type = 0
            data = 0

        ip_packet = etherFrame.payload
        destination_ip = str(ip_packet.dstip)

        if destination_ip == "10.0.7.100":
            if str(etherFrame.payload.srcip) not in self.packets:
                self.packets[str(etherFrame.payload.srcip)] = [[t, self.frame_number, frame_lengh, src_port, dst_port, SYN_flag, ACK_flag, time_live, proto, version, req_type, data]]

            elif str(etherFrame.payload.srcip) in self.packets:
                self.packets[str(etherFrame.payload.srcip)] += [[t, self.frame_number, frame_lengh, src_port, dst_port, SYN_flag, ACK_flag, time_live, proto, version, req_type, data]]

    def ICMP_Handler(self, packet, packet_in):
        ethernet_frame = packet
        ip_packet = packet.payload

        icmp_request_packet = ip_packet.payload

        # ICMP Echo Request (8) -> ICMP Echo Reply (0)
        if icmp_request_packet.type == 8:
            icmp_echo_reply_packet = icmp()
            icmp_echo_reply_packet.code = 0
            icmp_echo_reply_packet.type = 0
            icmp_echo_reply_packet.payload = icmp_request_packet.payload

            ip = ipv4()
            ip.srcip = ip_packet.dstip
            ip.dstip = ip_packet.srcip
            ip.protocol = ipv4.ICMP_PROTOCOL
            ip.payload = icmp_echo_reply_packet

            ether = ethernet()
            ether.type = ethernet.IP_TYPE
            ether.src = ethernet_frame.dst
            ether.dst = ethernet_frame.src
            ether.payload = ip

            self.resend_packet(ether, packet_in.in_port)
            log.debug("%s ICMP ECHO REPLY SENT!" % self.dpid)
    
    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        etherFrame = event.parsed   # This is the parsed packet data.
        packet_in = event.ofp       # The actual ofp_packet_in message.

        self.frame_number += 1

        # Incomplete frames
        if not etherFrame.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # LLDP
        if etherFrame.type == ethernet.LLDP_TYPE:
            log.warning("Ignoring LLDP")
            return

        # Add the new MAC into CAM table
        if str(etherFrame.src) not in self.mac_to_port:
            self.mac_to_port[str(etherFrame.src)] = packet_in.in_port
            log.debug('%s Adding %s into CAM' % (self.dpid, str(etherFrame.src)))

        # Switchable?
        if str(etherFrame.dst) in self.mac_to_port:
            self.resend_packet(etherFrame, self.mac_to_port[str(etherFrame.dst)])
            log.debug("%s Frame can be switched!" % self.dpid)

        else:
            # ARP
            if etherFrame.type == ethernet.ARP_TYPE:
                log.debug('RECEIVED: EtherType -> ARP')
                self.ARP_Handler(etherFrame, packet_in)

            # IP
            elif etherFrame.type == ethernet.IP_TYPE:
                #log.debug('%s RECEIVED: EtherType -> IP' % self.dpid)

                attack = False

                    #TODO Deploy model
                    #https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-ofp_packet_out-Sendingpacketsfromtheswitch
                    #See ofp_packet_out() and ofp_flow_mod()
                    #maybe use OFPFC_DELETE and OFPFC_ADD on ofp_flow_mod()
                    #Usar a flag attack quando o modelo detetar o ataque
                    #https://github.com/EmreOvunc/Python-SYN-Flood-Attack-Tool     TCP-SYN flood python
                """
                        if attack:
                            if destination_ip not in self.arp_table: 
                                arp_request = arp()
                                arp_request.opcode = arp.REQUEST
                                arp_request.protosrc = IPAddr(netaddr)
                                arp_request.protodst = IPAddr(destination_ip)
                                arp_request.hwsrc = EthAddr(self.interfaces[netaddr]['MAC'])
                                arp_request.hwdst = EthAddr('00:00:00:00:00:00')

                                ether = ethernet()
                                ether.type = ethernet.ARP_TYPE
                                ether.src = EthAddr(self.interfaces[netaddr]['MAC'])
                                ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                                ether.payload = arp_request

                                msg = of.ofp_packet_out()
                                msg.data = ether
                                #Group malicious nodes into same vlan to drop packets from that VLAN
                                msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = 1))
                                self.connection.send(msg)

                            if destination_ip in self.arp_table:
                                etherFrame.src = etherFrame.dst
                                etherFrame.dst = EthAddr(self.arp_table[destination_ip])
                                self.connection.send(of.ofp_flow_mod(priority=1, command=of.OFPFC_MODIFY_STRICT match=of.ofp_match(dl_src = etherFrame.src, dl_dst = etherFrame.dst), actions = [of.ofp_action_vlan_vid(vlan_vid = 1)]))
                        if attack:
                            #TODO see way to metigate the attack without creating to many flow entries
                            if destination_ip not in self.arp_table: 
                                arp_request = arp()
                                arp_request.opcode = arp.REQUEST
                                arp_request.protosrc = IPAddr(netaddr)
                                arp_request.protodst = IPAddr(destination_ip)
                                arp_request.hwsrc = EthAddr(self.interfaces[netaddr]['MAC'])
                                arp_request.hwdst = EthAddr('00:00:00:00:00:00')

                                ether = ethernet()
                                ether.type = ethernet.ARP_TYPE
                                ether.src = EthAddr(self.interfaces[netaddr]['MAC'])
                                ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                                ether.payload = arp_request

                                msg = of.ofp_packet_out()
                                msg.data = ether
                                #No action in order to drop the packet
                                #msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                                self.connection.send(msg)

                            if destination_ip in self.arp_table:
                                etherFrame.src = etherFrame.dst
                                etherFrame.dst = EthAddr(self.arp_table[destination_ip])
                                self.connection.send(of.ofp_flow_mod(priority=1, command=of.OFPFC_MODIFY_STRICT match=of.ofp_match(dl_src = etherFrame.src, dl_dst = etherFrame.dst)))

                """

                # Extract IP Packet from Ethernet Frame
                ip_packet = etherFrame.payload
                destination_ip = str(ip_packet.dstip)

                # For Router?
                if destination_ip in self.interfaces:
                    log.debug('%s ICMP ECHO -> ROUTER INTERFACE' % self.dpid)
                    self.ICMP_Handler(etherFrame, packet_in)
                else:
                    local = False
                    flag = False
                    for netaddr in self.interfaces.keys():
                        destination_network = self.interfaces[netaddr]['Network']
                        if self.interfaces[netaddr]['Network'].split('/')[1] == '8':
                            if self.interfaces[netaddr]['Network'].split('.')[0] == destination_ip.split('.')[0]:
                                flag = True
                        if self.interfaces[netaddr]['Network'].split('/')[1] == '16':
                            if self.interfaces[netaddr]['Network'].split('.')[0] == destination_ip.split('.')[0] and netaddr.split('.')[1] == destination_ip.split('.')[1]:
                                flag = True
                        if self.interfaces[netaddr]['Network'].split('/')[1] == '24':
                            if self.interfaces[netaddr]['Network'].split('.')[0] == destination_ip.split('.')[0] and netaddr.split('.')[1] == destination_ip.split('.')[1] and netaddr.split('.')[2] == destination_ip.split('.')[2]:
                                flag = True
                        if flag:
                            local = True
                            #log.debug('%s Packet can be routed!' % self.dpid)
                            break

                    routable = False
                    flag = False
                    if not local:
                        for netaddr in self.routing_table.keys():
                            size = self.routing_table.keys()
                            if len(size) < 2:
                                destination_network = "10.0.7.0/24"
                                routable = True
                                break
                            destination_network = netaddr
                            if netaddr.split('/')[1] == '8':
                                if netaddr.split('.')[0] == destination_ip.split('.')[0]:
                                    flag = True
                            if netaddr.split('/')[1] == '16':
                                if netaddr.split('.')[0] == destination_ip.split('.')[0] and netaddr.split('.')[1] == destination_ip.split('.')[1]:
                                    flag = True
                            if netaddr.split('/')[1] == '24':
                                if netaddr.split('.')[0] == destination_ip.split('.')[0] and netaddr.split('.')[1] == destination_ip.split('.')[1] and netaddr.split('.')[2] == destination_ip.split('.')[2]:
                                    flag = True
                            if flag:
                                routable = True
                                break

                    tcp_found = etherFrame.find('tcp')
                    ip = etherFrame.payload
                    if tcp_found and self.dpid != 7 and [etherFrame.src, etherFrame.dst] not in attackers:
                        TCP_datagram = etherFrame.payload.payload
                        #print(TCP_datagram.payload.split('\n'))
                        if "GET" in TCP_datagram.payload or etherFrame.dst in self.next_http:
                            self.save_TCP_packet(etherFrame, len(etherFrame), 0)
                            self.save_packet(etherFrame, len(etherFrame), 0)
                            if etherFrame.dst in self.next_http:
                                self.next_http.remove(etherFrame.dst)
                        else:
                            self.save_TCP_packet(etherFrame, len(etherFrame), 2)
                            self.save_packet(etherFrame, len(etherFrame), 2)
                            if "OK" in TCP_datagram.payload:
                                self.next_http.append(etherFrame.dst)

                        if routable and int(TCP_datagram.FIN == True) == 0 and int(TCP_datagram.RST == True) == 0 and int(TCP_datagram.PSH == True) == 0:
                            if tcp_found.SYN or tcp_found.ACK:
                                if tcp_found.SYN:
                                    if etherFrame.src not in self.tracker:
                                        self.tracker[etherFrame.src] = 1
                                    else:
                                        self.tracker[etherFrame.src] += 1
                                        if self.tracker[etherFrame.src] > self.threshold:
                                            print(etherFrame.src)
                                            print(self.dpid)
                                            if [etherFrame.src, etherFrame.dst] not in attackers:
                                                attackers.append([etherFrame.src, etherFrame.dst])
                                            print(attackers)
                                            #self.connection.send(of.ofp_flow_mod(priority=99, command=of.OFPFC_ADD, match=of.ofp_match(dl_src = etherFrame.src, dl_dst = etherFrame.dst), actions = [of.ofp_action_vlan_vid(vlan_vid = 1)]))
                                            self.connection.send(of.ofp_flow_mod(priority=99, command=of.OFPFC_ADD, match=of.ofp_match(dl_vlan=1)))

                                elif tcp_found.ACK:
                                    if etherFrame.src in self.tracker:
                                        self.tracker[etherFrame.src] = self.tracker[etherFrame.src] - 1
                    if etherFrame.find('icmp') and self.dpid != 7 and [etherFrame.src, etherFrame.dst] not in attackers and ip not in in_analysis: #maybe need to add in_analysis_behavior
                        self.save_TCP_packet(etherFrame, len(etherFrame), 1)
                    if etherFrame.find('icmp') and self.dpid != 7 and [etherFrame.src, etherFrame.dst] not in attackers and ip not in in_analysis_behavior:
                        self.save_packet(etherFrame, len(etherFrame), 1)
                    if etherFrame.find('udp') and self.dpid != 7 and [etherFrame.src, etherFrame.dst] not in attackers and ip not in in_analysis_behavior:
                        self.save_packet(etherFrame, len(etherFrame), 3)
                    if etherFrame.find('dns') and self.dpid != 7 and [etherFrame.src, etherFrame.dst] not in attackers and ip not in in_analysis_behavior:
                        self.save_packet(etherFrame, len(etherFrame), 4)     
                    
                    
                    for ip in self.TCP_packets:
                        #print(len(self.TCP_packets[str(etherFrame.payload.dstip)]))
                    
                        if len(self.TCP_packets[ip]) >= 100 and self.warmup == True and self.dpid != 7:
                            if ip not in in_analysis:
                                in_analysis.append(ip)
                                print(in_analysis)
                                file_name = 'pox/misc/aux_files/' + ip.split('.')[0] + '_' + ip.split('.')[1] + '_' + ip.split('.')[2] + '_' + ip.split('.')[3] + '.txt'
                                with open(file_name, 'w') as f:
                                    for line in self.TCP_packets[ip]:
                                        for entry in line:
                                            f.write(str(entry) + " ")
                                        f.write('\n')
  
                                # using the generated key

                                
                                thre = Thread(target = self.myThread, args = (etherFrame.src, etherFrame.dst))
                                thre.start()
                            self.TCP_packets[ip] = []
                        elif self.warmup == False and len(self.TCP_packets[ip]) >= 30  and self.dpid != 7:
                            self.warmup = True
                            print("Warm up done by", self.dpid)
                            self.TCP_packets[ip] = []
                            
                    for ip in self.packets:
                        #print(len(self.packets[str(etherFrame.payload.dstip)]))
                    
                        if len(self.packets[ip]) >= 100 and self.warmup2 == True and self.dpid != 7:
                            if ip not in in_analysis_behavior:
                                in_analysis_behavior.append(ip)
                                print(in_analysis_behavior)
                                file_name = 'pox/misc/normal_behavior/' + ip.split('.')[0] + '_' + ip.split('.')[1] + '_' + ip.split('.')[2] + '_' + ip.split('.')[3] + '.txt'
                                with open(file_name, 'w') as f:
                                    for line in self.packets[ip]:
                                        for entry in line:
                                            f.write(str(entry) + " ")
                                        f.write('\n')
  
                                # using the generated key
                                fernet = Fernet(key)
  
                                # opening the original file to encrypt
                                with open(file_name, 'rb') as file:
                                    original = file.read()
                                # encrypting the file
                                encrypted = fernet.encrypt(original)
  
                                # opening the file in write mode and 
                                # writing the encrypted data
                                encry_file = 'pox/misc/normal_behavior/' + ip.split('.')[0] + '_' + ip.split('.')[1] + '_' + ip.split('.')[2] + '_' + ip.split('.')[3] + '_encrypted.txt'
                                with open(encry_file, 'wb') as encrypted_file:
                                    encrypted_file.write(encrypted)
                                os.remove(file_name)
                                
                                thre = Thread(target = self.myThread2, args = (etherFrame.src, etherFrame.dst, ip))
                                thre.start()
                            self.packets[ip] = []
                        elif self.warmup2 == False and len(self.packets[ip]) >= 30  and self.dpid != 7:
                            self.warmup2 = True
                            print("Warm up 2 done by", self.dpid)
                            self.packets[ip] = []

                    if local: # and [etherFrame.src, etherFrame.dst] not in attackers:
                        #print(1111111111111111)
                        if destination_ip not in self.arp_table:
                            #print(2222222222222222)
                            # ARP for the Next Hop
                            arp_request = arp()
                            arp_request.opcode = arp.REQUEST
                            arp_request.protosrc = IPAddr(netaddr)
                            arp_request.protodst = IPAddr(destination_ip)
                            arp_request.hwsrc = EthAddr(self.interfaces[netaddr]['MAC'])
                            arp_request.hwdst = EthAddr('00:00:00:00:00:00')

                            ether = ethernet()
                            ether.type = ethernet.ARP_TYPE
                            ether.src = EthAddr(self.interfaces[netaddr]['MAC'])
                            ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                            ether.payload = arp_request

                            msg = of.ofp_packet_out()
                            msg.data = ether
                            if [etherFrame.src, etherFrame.dst] not in attackers:
                                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                            else:
                                msg.actions.append(of.ofp_action_vlan_vid(1))
                                msg.actions.append(ofp_action_output(port=of.OFPP_TABLE))
                            self.connection.send(msg)
                        if destination_ip in self.arp_table:
                            etherFrame.src = etherFrame.dst
                            etherFrame.dst = EthAddr(self.arp_table[destination_ip])
                            self.resend_packet(etherFrame, self.mac_to_port[self.arp_table[destination_ip]])

                    elif routable: # and [etherFrame.src, etherFrame.dst] not in attackers:
                        next_hop = self.routing_table[destination_network]['Next Hop']
                        if next_hop not in self.arp_table:
                            # ARP for the Next Hop
                            arp_request = arp()
                            arp_request.opcode = arp.REQUEST
                            arp_request.protosrc = IPAddr(self.routing_table[destination_network]['Connected'])
                            arp_request.protodst = IPAddr(next_hop)
                            arp_request.hwsrc = EthAddr(self.interfaces[self.routing_table[destination_network]['Connected']]['MAC'])
                            arp_request.hwdst = EthAddr('00:00:00:00:00:00')

                            ether = ethernet()
                            ether.type = ethernet.ARP_TYPE
                            ether.src = EthAddr(self.interfaces[self.routing_table[destination_network]['Connected']]['MAC'])
                            ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                            ether.payload = arp_request

                            msg = of.ofp_packet_out()
                            msg.data = ether
                            print(etherFrame.src)
                            print(etherFrame.dst)
                            print(attackers)
                            if [etherFrame.src, etherFrame.dst] not in attackers:
                                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                            else:
                                print(1)
                                msg.actions.append(of.ofp_action_vlan_vid(1))
                                msg.actions.append(ofp_action_output(port=of.OFPP_TABLE))
                            self.connection.send(msg)
                        if next_hop in self.arp_table:
                            if [etherFrame.src, etherFrame.dst] not in attackers:
                                etherFrame.src = EthAddr(self.interfaces[self.routing_table[destination_network]['Connected']]['MAC'])
                                etherFrame.dst = EthAddr(self.arp_table[next_hop])
                                self.resend_packet(etherFrame, self.mac_to_port[self.arp_table[next_hop]])
                                #log.debug('%s Packet forwarded to next hop!' % self.dpid)
                            else:
                                #print(333333333333333333)
                                self.drop_packet(etherFrame)
                                


def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
