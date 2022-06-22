from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches
import networkx as nx


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)

        # global data structure to save the link between switch and host
        self.switch_host = {}

        # global data structure to save the switches
        self.dp = {}

        # use this api to get the topo of switches
        self.topology_api_app = self

        # global data structure to save the Graph topo
        self.G = nx.Graph()

        # global data structure to save the link between switches
        self.switch_switch = {}

    # add a flow table entry in switch
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # construct a FlowMod message
        # send a switch to add a flow table entry
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    # add table_miss entry cause switch send packets to the controller
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
        self.dp[dpid] = dp

        # set switch_host value to dictionary
        self.switch_host.setdefault(dpid, {})

        # the port that receive the packet
        in_port = msg.match['in_port']

        # make a packet using the msg.data metadata
        pkt = packet.Packet(msg.data)

        # judge the packet is Ethernet or not
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # the packet is Ethernet
        if eth_pkt:

            # ignore the LLDP and IPv6 packet
            # or will cause flood disaster
            if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
                return

            # get the mac address
            eth_src = eth_pkt.src
            eth_dst = eth_pkt.dst

            # judge the packet is ARP or not
            arp_pkt = pkt.get_protocol(arp.arp)

            # the packet is ARP
            if arp_pkt:

                # the packet is ARP Request
                if arp_pkt.opcode == arp.ARP_REQUEST:

                    # get the sender's ip and mac
                    arp_src_ip = arp_pkt.src_ip
                    arp_src_mac = arp_pkt.src_mac

                    # get the target's ip
                    arp_dst_ip = arp_pkt.dst_ip

                    # already have the ip record
                    if arp_src_ip in self.switch_host[dpid].keys():

                        # find the wanted mac address
                        ARP_Reply_eth_dst = None
                        for switch in self.switch_host.keys():
                            if arp_dst_ip in self.switch_host[switch].keys():
                                ARP_Reply_eth_dst = self.switch_host[switch][arp_dst_ip]['mac']
                                break

                        if ARP_Reply_eth_dst is None:
                            print('Not have the mac address for the wanted ip.')
                            return

                        # response to the ARP request
                        # make an ARP response packet
                        ARP_Reply = packet.Packet()

                        # add the Ethernet field
                        ARP_Reply.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
                                                                 dst=eth_src, src=ARP_Reply_eth_dst))

                        # add the ARP field
                        ARP_Reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=ARP_Reply_eth_dst,
                                                       src_ip=arp_dst_ip, dst_mac=arp_src_mac, dst_ip=arp_src_ip))

                        ARP_Reply.serialize()

                        actions = [parser.OFPActionOutput(in_port)]

                        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                                  in_port=ofp.OFPP_CONTROLLER, actions=actions, data=ARP_Reply.data)
                        dp.send_msg(out)

                        print('Send an ARP response.')

                    # not have the ip record yet
                    else:
                        self.switch_host[dpid].setdefault(arp_src_ip, {})
                        self.switch_host[dpid][arp_src_ip]['mac'] = arp_src_mac
                        self.switch_host[dpid][arp_src_ip]['port'] = in_port
                        print('Learn a switch and host relation.')
                        print('Host:{} Mac:{} Port:{}'.format(arp_src_ip, arp_src_mac,in_port))
                        print('Now add a flow table entry!!!')

                        # all the packet eth_dst goes to the in_port
                        actions = [parser.OFPActionOutput(in_port)]
                        match = parser.OFPMatch(eth_dst=arp_src_mac)
                        self.add_flow(dp, 10, match, actions, 90, 180)

                    return

                # the packet is ARP response
                else:
                    pass

            # the packet is not ARP
            else:
                # print('This packet is not ARP.')
                pass

            # find the final switch
            dst_dpid = None
            find = False
            for switch in self.switch_host.keys():
                for host in self.switch_host[switch].keys():
                    if eth_dst == self.switch_host[switch][host]['mac']:
                        dst_dpid = switch
                        find = True
                        break
                if find:
                    break

            # get the shortest path
            # every link weight 1 the same
            if dst_dpid is None:
                print('dst_dpid is none.')
                return

            short_path = nx.shortest_path(self.G, dpid, dst_dpid)
            print('From {} to {}, find the path {}'.format(dpid, dst_dpid, short_path))

            # hand out flow table entry
            for i in range(0, len(short_path)-1):
                cur_switch = short_path[i]
                next_switch = short_path[i+1]
                out_port = self.switch_switch[cur_switch][next_switch]

                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_dst=eth_dst)
                self.add_flow(self.dp[cur_switch], 20, match, actions, 300, 600)
                print('add a table flow table to switch {}'.format(cur_switch))

            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data

            cur_switch = short_path[0]
            next_switch = short_path[1]
            out_port = self.switch_switch[cur_switch][next_switch]
            actions = [parser.OFPActionOutput(out_port)]

            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            dp.send_msg(out)

        else:
            # print('This packet is not Ethernet.')
            pass

    @set_ev_cls(event.EventSwitchEnter)
    def get_topo(self, ev):

        # get the switch list and join them into the Graph
        switch_list = get_switch(self.topology_api_app)
        node = []
        print('Current Switch:')
        for switch in switch_list:
            print(switch)
            node.append(switch.dp.id)
            self.switch_switch.setdefault(switch.dp.id, {})
        self.G.add_nodes_from(node)

        # get the link list and join the into the Graph
        link_list = get_link(self.topology_api_app)
        edge = []
        print('Current Link:')
        for link in link_list:
            print(link)
            edge.append((link.src.dpid, link.dst.dpid))
            self.switch_switch[link.src.dpid][link.dst.dpid] = link.src.port_no
        self.G.add_edges_from(edge)

        # https://github.com/faucetsdn/ryu/blob/d1d1dc94278fd81799ac37b09128b306827c8a3d/ryu/topology/switches.py

        # get the host list
        print('Current Host:')
        host_list = get_all_host(self.topology_api_app)
        print(host_list)
        # for host in host_list:
        #     print(host)