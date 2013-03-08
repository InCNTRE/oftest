"""These tests fall under Conformance Test-Suite (OF-SWITCH-1.0.0 TestCases).
    Refer Documentation -- Detailed testing methodology 
    <Some of test-cases are directly taken from oftest> """

"Test Suite 6 --> Flow Matches"


import logging

import unittest
import random

import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.parse as parse
import oftest.base_tests as base_tests
import time

from oftest.oflog import *
from oftest.testutils import *
from time import sleep
from FuncUtils import *



class Grp50No10(base_tests.SimpleDataPlane):

    """Verify for an all wildcarded flow all the injected packets would match that flow"""
    @wireshark_capture
    
    def runTest(self):
        logging = get_logger()
        logging.info("Running All Wildcard Match Grp50No10 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting an all wildcarded flow and sending packets with various match fields")
        logging.info("Expecting all sent packets to match")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        
        sleep(2)

        #Insert an All Wildcarded flow.
        wildcard_all(self,of_ports)

        #check for different  match fields and verify packet implements the action specified in the flow
        pkt1 = simple_tcp_packet(dl_src="00:01:01:01:01:01");
        self.dataplane.send(of_ports[0], str(pkt1))
        receive_pkt_check(self.dataplane,pkt1,[yes_ports],no_ports,self)
       
        pkt2 = simple_tcp_packet(dl_dst="00:01:01:01:01:01");    
        self.dataplane.send(of_ports[0], str(pkt2))
        receive_pkt_check(self.dataplane,pkt2,[yes_ports],no_ports,self)
        
        pkt3 = simple_tcp_packet(ip_src="192.168.2.1");
        self.dataplane.send(of_ports[0], str(pkt3))
        receive_pkt_check(self.dataplane,pkt3,[yes_ports],no_ports,self)
        
        pkt4 = simple_tcp_packet(ip_dst="192.168.2.2");
        self.dataplane.send(of_ports[0], str(pkt4))
        receive_pkt_check(self.dataplane,pkt4,[yes_ports],no_ports,self)
        
        pkt5 = simple_tcp_packet(ip_tos=2);
        self.dataplane.send(of_ports[0], str(pkt5))
        receive_pkt_check(self.dataplane,pkt5,[yes_ports],no_ports,self)
       
        pkt6 = simple_tcp_packet(tcp_sport=8080);
        self.dataplane.send(of_ports[0], str(pkt6))
        receive_pkt_check(self.dataplane,pkt6,[yes_ports],no_ports,self)
              
        pkt7 = simple_tcp_packet(tcp_dport=8081);
        self.dataplane.send(of_ports[0], str(pkt7))
        receive_pkt_check(self.dataplane,pkt7,[yes_ports],no_ports,self)


class Grp50No20(base_tests.SimpleDataPlane):
    
    """Verify match on single Header Field Field -- In_port """

    @wireshark_capture
    
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No20 Ingress Port test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        sleep(2)

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
    
        logging.info("Inserting a flow with match on Ingress Port ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying only matching packets implements the action specified in the flow")
        
        #Insert a Match on Ingress Port FLow
        (pkt,match) = wildcard_all_except_ingress(self,of_ports,priority=0)
        
        #Send Packet matching the flow i.e on in_port specified in the flow
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send Non-Matching Packet 
        self.dataplane.send(of_ports[1],str(pkt))

        #Verify PacketIn event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non-matching packet")


class Grp50No30(base_tests.SimpleDataPlane):
    
    """Verify match on single header field -- Ethernet Src Address  """
    @wireshark_capture
    
    def runTest(self):
        logging = get_logger()
        logging.info("Running Ethernet Src Address Grp50No30 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
    
        logging.info("Inserting a flow with match on Ethernet Source Address ")
        logging.info("Sending matching and non-matching ethernet packets")
        logging.info("Verifying only matching packets implements the action specified in the flow")

        sleep(2)

        #Insert a Match On Ethernet Src Address flow
        (pkt,match) = match_ethernet_src_address(self,of_ports)   

        #Sending packet matching the flow, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_eth_packet(dl_src='00:01:01:01:01:02');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packets")

class Grp50No40(base_tests.SimpleDataPlane):
    
    """Verify match on single Header Field Field -- Ethernet Dst Address """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No40 Ethernet Dst Address test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
        
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        
        logging.info("Inserting a flow with match on Ethernet Destination Address ")
        logging.info("Sending matching and non-matching ethernet packets")
        logging.info("Verifying only matching packets implements the action specified in the flow")
        
        sleep(2)

        #Insert a Match on Destination Address flow   
        (pkt,match) = match_ethernet_dst_address(self,of_ports)
        
        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send Non-matching packet
        pkt2 = simple_eth_packet(dl_dst='00:01:01:01:01:02');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        #Verify PacketIn event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No50(base_tests.SimpleDataPlane):
    
    """Verify match on single header field -- Ethernet Type """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No50 Ethernet Type test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        
        logging.info("Inserting a flow with match on Ethernet Type ")
        logging.info("Sending matching and non-matching ethernet packets")
        logging.info("Verifying only matching packets implements the action specified in the flow")

        sleep(2)        

        #Insert a Match on Ethernet-Type flow
        (pkt,match) = match_ethernet_type(self,of_ports)   

        #Sending packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send non-matching packet 
        pkt3 = simple_eth_packet(dl_type=0x0805)
        self.dataplane.send(of_ports[0],str(pkt3))

        #verify Packetin event gets triggered.
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non-matching packet")

            

class Grp50No60(base_tests.SimpleDataPlane):

    """Verify match on single Header Field Field -- Vlan Id """

    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No60 Match on Vlan Id  test")
        
        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
    
        logging.info("Inserting a flow with match on VLAN ID ")
        logging.info("Sending matching and non-matching tagged packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        sleep(2)
    
        #Create a flow with match on Vlan Id
        (pkt,match) = match_vlan_id(self,of_ports)

        #Send tagged packet matching the flow i.e packet with same vlan id as in flow
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send Non-matching packet, i.e packet with different Vlan Id
        pkt2 = simple_tcp_packet(dl_vlan_enable=True,dl_vlan=4);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        #Verify PacketIn event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

class Grp50No70(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- Vlan Priority"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No70 VlanPCP test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        sleep(2)

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
    
        logging.info("Inserting a flow with match on VLAN Priority ")
        logging.info("Sending matching and non-matching tagged packets")
        logging.info("Verifying matching packet implements the action specified in the flow")

        #Create a flow matching on VLAN Priority
        (pkt,match) = match_vlan_pcp(self,of_ports)

        #Send tagged Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send tagged packet with same vlan_id but different vlan priority
        pkt2 = simple_tcp_packet(dl_vlan_enable=True,dl_vlan=1,dl_vlan_pcp=20);
        self.dataplane.send(of_ports[0], str(pkt2))

        #Verify Packet_In event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

class Grp50No80a(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- IP_SRC_ADDRESS 
    Generates an exact match here"""
    @wireshark_capture
    def runTest(self):

        logging = get_logger()
        logging.info("Running Grp50No80a Ip_Src test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        
        sleep(2)

        #Create a simple tcp packet and generate match on ip src address , exact match 
        pkt = simple_tcp_packet(ip_src='192.168.100.100')
        match = parse.packet_to_flow_match(pkt)
        #Wildcards -- 
        match.wildcards = 0xffffc0cf 
        msg = message.flow_mod()
        msg.match = match
        act = action.action_output()
        act.port = of_ports[1]
        rv = msg.actions.add(act)
        self.assertTrue(rv, "Could not add output action " + 
                        str(of_ports[1]))
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed")  

        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send a non-matching packet , verify packet_in gets triggered
        pkt2 = simple_tcp_packet(ip_src='149.165.130.66')
        self.dataplane.send(of_ports[0], str(pkt2))
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No80b(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- IP_SRC_ADDRESS 
    Wildcards all bits in ip_src_address here"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No80b IpSrcWildcard test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)

        #Create a simple tcp packet and generate match on ip src address 
        pkt = simple_tcp_packet(ip_src='192.168.100.100')
        match = parse.packet_to_flow_match(pkt)
        match.wildcards = 0xffffffcf
        msg = message.flow_mod()
        msg.match = match
        act = action.action_output()
        act.port = of_ports[1]
        rv = msg.actions.add(act)
        self.assertTrue(rv, "Could not add output action " + 
                            str(of_ports[1]))
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed") 
        
        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send a non-matching packet , verify it also matches the flow_entry
        pkt2 = simple_tcp_packet(ip_src='149.165.130.66')
        self.dataplane.send(of_ports[0], str(pkt2))
        receive_pkt_check(self.dataplane,pkt2,[yes_ports],no_ports,self)


class Grp50No80c(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- IP_SRC_ADDRESS 
    Generates an match with wildcarding certain number of bits in ip_address"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Ip_Src test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)

        #Create a simple tcp packet and generate match on ip src address 
        pkt = simple_tcp_packet(ip_src='192.168.100.100')
        match = parse.packet_to_flow_match(pkt)
        match.wildcards = 0x3fffd9cf
        msg = message.flow_mod()
        msg.match = match
        act = action.action_output()
        act.port = of_ports[1]
        rv = msg.actions.add(act)
        self.assertTrue(rv, "Could not add output action " + 
                            str(of_ports[1]))
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed") 

        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send a non-matching packet , with only LSB different than the ip-address matched against
        pkt2 = simple_tcp_packet(ip_src='192.170.100.101')
        self.dataplane.send(of_ports[0], str(pkt2))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt2,[yes_ports],no_ports,self)
        
        #Send a non-matching packet , verify packet_in gets triggered
        pkt3 = simple_tcp_packet(ip_src='200.168.100.100')
        self.dataplane.send(of_ports[0], str(pkt3))
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No90a(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- IP_DST_ADDRESS 
    Generates an exact match here"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No90a Ip_Dst test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)

        #Create a flow for match on ip_dst_address (exact match)
        pkt = simple_tcp_packet(ip_src='192.168.100.100')
        match = parse.packet_to_flow_match(pkt)
        match.wildcards = 0x3ff03fcf
        msg = message.flow_mod()
        msg.match = match
        act = action.action_output()
        act.port = of_ports[1]
        rv = msg.actions.add(act)
        self.assertTrue(rv, "Could not add output action " + 
                            str(of_ports[1]))
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed") 
        
        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send a non-matching packet , verify packet_in gets triggered
        pkt2 = simple_tcp_packet(ip_dst='149.165.130.66')
        self.dataplane.send(of_ports[0], str(pkt2))
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

class Grp50No90b(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- IP_DST_ADDRESS 
    Generates an wildcard match here"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No90b Ip_Dst test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)

        #Create a flow for match on ip_dst_address (wildcard match))
        pkt = simple_tcp_packet(ip_src='192.168.100.100')
        match = parse.packet_to_flow_match(pkt)
        match.wildcards = 0x3fffffcf
        msg = message.flow_mod()
        msg.match = match
        act = action.action_output()
        act.port = of_ports[1]
        rv = msg.actions.add(act)
        self.assertTrue(rv, "Could not add output action " + 
                            str(of_ports[1]))
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed") 
        
        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send a non-matching packet , verify it also matches the flow_entry
        pkt2 = simple_tcp_packet(ip_src='149.165.130.66')
        self.dataplane.send(of_ports[0], str(pkt2))
        receive_pkt_check(self.dataplane,pkt2,[yes_ports],no_ports,self)



class Grp50No90c(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- IP_SRC_ADDRESS 
    Generates an match with wildcarding certain number of bits in ip_address"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No90c Ip_Src test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)

        #Create a flow for match on ip_dst_address (wildcard match))
        pkt = simple_tcp_packet(ip_src='192.168.100.100')
        match = parse.packet_to_flow_match(pkt)
        match.wildcards = 0x3ff67fcf
        msg = message.flow_mod()
        msg.match = match
        act = action.action_output()
        act.port = of_ports[1]
        rv = msg.actions.add(act)
        self.assertTrue(rv, "Could not add output action " + 
                            str(of_ports[1]))
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed") 

        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send a non-matching packet , with only LSB different than the ip-address matched against
        pkt2 = simple_tcp_packet(ip_dst='192.156.100.101')
        self.dataplane.send(of_ports[0], str(pkt2))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt2,[yes_ports],no_ports,self)
        
        #Send a non-matching packet , verify packet_in gets triggered
        pkt3 = simple_tcp_packet(ip_dst='200.168.100.100')
        self.dataplane.send(of_ports[0], str(pkt3))
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No100(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- Ip Protocol"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No100 Ip Protocol test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        sleep(2)

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
    
        logging.info("Inserting a flow with match on Ip Protocol ")
        logging.info("Sending matching and non-matching tcp/ip packets")
        logging.info("Verifying only matching packets implements the action specified in the flow")

        #Create a flow matching on VLAN Priority
        (pkt,match) = match_ip_protocol(self,of_ports)

        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Create a non-matching packet , verify packet_in get generated
        pkt2 = simple_icmp_packet();
        self.dataplane.send(of_ports[0], str(pkt2))
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")



class Grp50No110(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- Type of service"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No110 Ip_Tos test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)
    
        logging.info("Inserting a flow with match on Ip_Tos ")
        logging.info("Sending matching and non-matching tcp/ip packets")
        logging.info("Verifying only matching packets implements the action specified in the flow")

        #Create a flow matching on VLAN Priority
        (pkt,match) = match_ip_tos(self,of_ports)

        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Create a non-matching packet , verify packet_in get generated
        pkt2 = simple_tcp_packet(ip_tos=2);
        self.dataplane.send(of_ports[0], str(pkt2))
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

class Grp50No120a(base_tests.SimpleDataPlane):
    
    """Verify match on Single header field -- Tcp Source Port"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No120a Tcp Src Port test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        
        sleep(2)
        logging.info("Inserting a flow with match on Tcp Tcp Source Port ")
        logging.info("Sending matching and non-matching tcp packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = match_tcp_src(self,of_ports)   

        #Sending packet matching the tcp_sport, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_sport=540);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

class Grp50No120b(base_tests.SimpleDataPlane):
    
    """Verify match on Single header field --Match on Tcp Source Port/IcmpType  """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running IcmpType test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)
        (pkt,match) = match_icmp_type(self,of_ports)   

        #Sending packet matching the tcp_sport, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_icmp_packet(icmp_type=11);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

class Grp50No130a(base_tests.SimpleDataPlane):
    
    """Verify match on Single header field -- Tcp Destination Port """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Tcp Destination Port Grp50No130 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        
        logging.info("Inserting a flow with match on Tcp Destination Port ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = match_tcp_dst(self,of_ports)   

        #Sending packet matching the tcp_dport, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_dport=541);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=10)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No130b(base_tests.SimpleDataPlane):
    
    """Verify match on Single header field -- Tcp Destination Port/IcmpCode  """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No130b test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        (pkt,match) = match_icmp_code(self,of_ports)   

        #Sending packet matching the tcp_sport, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_icmp_packet(icmp_type=3,icmp_code=1);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No140(base_tests.SimpleDataPlane):
    
    """Verify match on multiple header field -- Ethernet Type, Ethernet Source Address, Ethernet Destination Address """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No140 Multiple Header Field L2 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
    
        logging.info("Inserting a flow with match on Multiple Header Fields in L2 ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = match_mul_l2(self,of_ports)   

        #Send eth packet matching the dl_type field, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet (only dl_dst is different) , verify Packetin event gets triggered.
        pkt2 = simple_eth_packet(dl_type=0x88cc,dl_src='00:01:01:01:01:01',dl_dst='00:01:01:02:01:01');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

        #Sending non matching packet (only dl_src is different) , verify Packetin event gets triggered.
        pkt2 = simple_eth_packet(dl_type=0x88cc,dl_src='00:01:01:01:01:02',dl_dst='00:01:01:01:01:02');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

        #Sending non matching packet (only ether_type is different) , verify Packetin event gets triggered.
        pkt2 = simple_eth_packet(dl_type=0x0805,dl_src='00:01:01:01:01:01',dl_dst='00:01:01:01:01:02');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        #Verify packet_in event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No150(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- IP_DST_ADDRESS 
    Generates an wildcard match here"""
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No90b Ip_Dst test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)

        #Create a flow for match on ip_dst_address & ip_src_address (exact match))
        pkt = simple_tcp_packet(ip_src='192.168.100.100',ip_dst='192.168.100.200')
        match = parse.packet_to_flow_match(pkt)
        match.wildcards = 0x3ff000cf
        msg = message.flow_mod()
        msg.match = match
        act = action.action_output()
        act.port = of_ports[1]
        rv = msg.actions.add(act)
        self.assertTrue(rv, "Could not add output action " + 
                            str(of_ports[1]))
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed") 
        
        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send a non-matching packet , verify it also matches the flow_entry
        pkt2 = simple_tcp_packet(ip_src='200.168.100.100',ip_dst='192.168.100.200')
        self.dataplane.send(of_ports[0], str(pkt2))
        
        #Verify packet_in event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

        #Send a non-matching packet , verify it also matches the flow_entry
        #pkt3 = simple_tcp_packet(ip_src='192.168.100.300',ip_dst='192.168.100.200')
        #self.dataplane.send(of_ports[0], str(pkt3))




class Grp50No160(base_tests.SimpleDataPlane):
    
    """Verify match on multiple header field -- Tcp Source Port, Tcp Destination Port  """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No160 Multiple Header Field L4 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        sleep(2)

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        
        logging.info("Inserting a flow with match on Multiple Header Field L4 ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = match_mul_l4(self,of_ports)   

        #Sending packet matching the tcp_sport and tcp_dport field, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet (tcp_dport different), verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_sport=111,tcp_dport=541);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")

        #Sending non matching packet (tcp_sport different), verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_sport=100,tcp_dport=112);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No170(base_tests.SimpleDataPlane):
    
    """Verify match on All header fields -- Exact Match  """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No170 Exact Match test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]

        sleep(2)
        
        logging.info("Inserting a flow with match for Exact Match ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = exact_match(self,of_ports)   

        #Sending packet matching all the fields of a tcp_packet, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_sport=540);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received for non matching packet")


class Grp50No180(base_tests.SimpleDataPlane):
    
    """Verify that Exact Match has highest priority """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No180a Exact Match High Priority test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        egress_port=of_ports[2]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[2]
    
        logging.info("Inserting a flow with Exact Match (low priority)")
        logging.info("Inserting an overlapping wildcarded flow (higher priority)")
        logging.info("Sending packets matching both the flows ")
        logging.info("Verifying matching packets implements the action specified in the exact match flow")

        sleep(2)

        #Insert two Overlapping Flows : Exact Match and Wildcard All.
        (pkt,match) = exact_match_with_prio(self,of_ports,priority=10) 
        
        sleep(2)

        (pkt2,match2) = wildcard_all(self,of_ports,priority=20)
        
        #Sending packet matching both the flows , 
        self.dataplane.send(of_ports[0], str(pkt2))

        #verify it implements the action specified in Exact Match Flow
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)




class Grp50No190(base_tests.SimpleDataPlane):
    
    """Verify that Wildcard Match with highest priority overrides the low priority WildcardMatch """
    @wireshark_capture
    def runTest(self):
        logging = get_logger()
        logging.info("Running Grp50No190 Wildcard Match High Priority test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        sleep(2)

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
    
        logging.info("Inserting two wildcarded flows with priorities ")
        logging.info("Sending packets matching the flows")
        logging.info("Verifying matching packets implements the action specified in the flow with higher priority")

        (pkt,match) = wildcard_all(self,of_ports,priority=20) 
        (pkt1,match1) =  wildcard_all_except_ingress1(self,of_ports,priority=10)  

        #Sending packet matching both the flows , verify it implements the action specified by Higher Priority flow
        self.dataplane.send(of_ports[0], str(pkt1))
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)






       
