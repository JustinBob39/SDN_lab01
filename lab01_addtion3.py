import copy

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
import networkx as nx


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)

        # global data structure to save the mac and port mapping
        self.mac_to_port = {}

        # global data structure to save the switch port connect host
        self.host_port = {}

        # global data structure to save the switch port connect switch
        self.switch_port = {}

        # global data structure to save the learn status of the switch port connect host
        self.learn = {}

        self.topology_api_app = self
        # global data structure to save the candidate switches
        # notice that it is a set, not a dictionary
        self.candidate = set()

        # global data structure to save neighbour relation
        self.N = {}

    # add a flow table entry in switch
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # construct a FlowMod message
        # send a switch to add a flow table entry
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    # add table miss entry causing switch send packets to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    # handle packet_in message
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # the identity of switch
        dpid = dp.id

        # the port that receive the packet
        in_port = msg.match['in_port']

        # the port that forward the packet
        # out_port = None

        # make the value of mac_to_port dictionary
        self.mac_to_port.setdefault(dpid, {})
        self.host_port.setdefault(dpid, set())
        self.learn.setdefault(dpid, {})

        # use msg.data to make packet
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # return if the packet is not Ethernet
        if eth_pkt is None:
            # print('This packet is not Ethernet')
            return

        # ignore the LLDP and IPv6 packet
        # or will cause flood disaster
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        # get the mac address
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src

        # use the logger to print some useful information
        self.logger.info('Packet:    dpid={} eth_src={} eth_dst={} in_port={}'.format(dpid, eth_src, eth_dst, in_port))

        # learn a mac and port mapping to avoid flood next time
        # if eth_src not in self.mac_to_port[dpid].keys():
        self.mac_to_port[dpid][eth_src] = in_port

        # learn a port that connect the host
        # then drop/ignore the packet
        print('host port {}'.format(self.host_port))

        if in_port not in self.switch_port[dpid]:
            if in_port not in self.host_port[dpid]:
                self.host_port[dpid].add(in_port)
                self.learn[dpid][in_port] = False
                print('Switch {} Port {} connect a host'.format(dpid, in_port))
                return
            else:
                if not self.learn[dpid][in_port]:
                    self.learn[dpid][in_port] = True
                    print('this port learn finish')
                    return
        # judge the packet is ARP or not
        arp_pkt = pkt.get_protocol(arp.arp)

        # the packet is not ARP, then continue
        # does not matter

        # the packet is ARP
        if arp_pkt:

            # judge the packet is an ARP request or response
            # if the packet is ARP response, then continue
            # does not matter, just go on

            # forward ports depends on whether it is candidate or not
            if arp_pkt.opcode == arp.ARP_REQUEST:

                print('Deal with an ARP request')
                if in_port in self.host_port[dpid] or dpid in self.candidate:

                    print('Reach a candidate switch.')
                    print('or the in port is a switch-host port')

                    out_port = ofp.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst='ff:ff:ff:ff:ff:ff')
                    self.add_flow(datapath=dp, priority=20, match=match, actions=actions,
                                  idle_timeout=300, hard_timeout=600)
                    print('Add a table flow entry')

                    data = None
                    if msg.buffer_id == ofp.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    dp.send_msg(out)
                    return

                if dpid not in self.candidate:

                    print('Reach a non-candidate switch')

                    # multicast to the ports connect host
                    # use the Group Table to achieve

                    # actions1 = [parser.OFPActionOutput(1)]
                    # buckets = [parser.OFPBucket(actions=actions1)]

                    if not self.host_port[dpid]:
                        return

                    buckets = []
                    for port in self.host_port[dpid]:
                        actions = [parser.OFPActionOutput(port)]
                        buckets.append(parser.OFPBucket(actions=actions))
                    req = parser.OFPGroupMod(datapath=dp, command=ofp.OFPGC_ADD, type_=ofp.OFPGT_ALL,
                                             group_id=50, buckets=buckets)

                    # class ryu.ofproto.ofproto_v1_3_parser.OFPGroupMod(datapath, command=0, type_=0, group_id=0, buckets=None)
                    dp.send_msg(req)
                    print('Add a group table entry')
                    print(req)

                    match = parser.OFPMatch(in_port=in_port, eth_dst='ff:ff:ff:ff:ff:ff')
                    actions = [parser.OFPActionGroup(group_id=50)]
                    self.add_flow(datapath=dp, priority=20, match=match, actions=actions,
                                  idle_timeout=300, hard_timeout=600)
                    print('Add a table flow entry')

                    data = None
                    if msg.buffer_id == ofp.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    dp.send_msg(out)
                return

        # get the out_port, whether flood or not
        if eth_dst in self.mac_to_port[dpid].keys():
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # know which port to go to
        # add flow table to the switch
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
            self.add_flow(dp, 10, match, actions, 90, 180)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        dp.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topo(self, ev):
        # for more details, please check the link
        # https://github.com/faucetsdn/ryu/blob/d1d1dc94278fd81799ac37b09128b306827c8a3d/ryu/topology/switches.py

        # get the switch set
        # use it to generate candidate switch
        switch_list = get_switch(self.topology_api_app)
        S = set(switch.dp.id for switch in switch_list)
        print('Current Switch:')
        print(S)

        # use dictionary:set to save neighbour relation
        # every dpid have a set to store neighbour
        for dpid in S:
            self.N.setdefault(dpid, set())
            self.switch_port.setdefault(dpid, set())

        # get the link list
        link_list = get_link(self.topology_api_app)
        L = [(link.src.dpid, link.dst.dpid) for link in link_list]
        print('Current Link:')
        print(L)

        # get the port connect switch
        for link in link_list:
            self.switch_port[link.src.dpid].add(link.src.port_no)
            self.switch_port[link.dst.dpid].add(link.dst.port_no)

        # get the neighbour relations
        for dpid in S:
            for link in L:
                if link[0] == dpid:
                    self.N[dpid].add(link[1])

            print('Switch {} connect another Switch using Port:'.format(dpid))
            print(self.switch_port[dpid])

            print('Neighbours of Switch {}'.format(dpid))
            print(self.N[dpid])

        # run the algorithm to find candidate switches
        # create a temp Graph to store the topo
        G = nx.Graph()

        # create a temp edge to store the link
        edge = []

        S1 = copy.deepcopy(S)
        for s in S1:
            print('Now checking Switch {}'.format(s))
            done = False
            S.remove(s)
            for dpid in self.N.keys():
                if S & self.N[dpid] is None:
                    S.add(s)
                    print('Switch {} is a candidate.'.format(s))
                    done = True
                    break
            if done:
                continue

            G.clear()
            G.add_nodes_from(S)
            print('Add node:')
            print(S)

            edge.clear()
            for dpid in S:
                for link in L:
                    if link[0] == dpid and link[1] in S:
                        edge.append(link)
            G.add_edges_from(edge)
            print('Add edge:')
            print(edge)

            print("The nodes and edges of the Graph:")
            print(G.nodes)
            print(G.edges)

            if nx.is_empty(G):
                print('Error, G is empyt')
                break

            if nx.is_connected(G) is False:
                S.add(s)
                print('Switch {} is a candidate.'.format(s))

        # copy the S to candidate
        self.candidate = copy.deepcopy(S)

        print('Candidate Switches:')
        print(self.candidate)