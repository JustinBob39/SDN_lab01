from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)

        # global data structure to save the mac and port mapping
        self.mac_to_port = {}

        # global data structure to save the timestamp last ARP
        self.last_time = {}

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

        # make switch send ARP to controller
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 1, match, actions)

    # handle packet_in message
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg

        # the source switch dp
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # the identity of switch
        dpid = dp.id

        # the port that receive the packet
        in_port = msg.match['in_port']

        # make the value of mac_to_port and last_time dictionary
        self.mac_to_port.setdefault(dpid, {})
        self.last_time.setdefault(dpid, {})

        # use msg.data to make packet
        pkt = packet.Packet(msg.data)

        # judge the packet is Ethernet or not
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # the packet is not Ethernet
        if not eth_pkt:
            # print('The packet is not Ethernet.')
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
        self.logger.info('Packet: dpid={} eth_src={} eth_dst={} in_port={} '.format(dpid, eth_src, eth_dst, in_port))

        # learn a mac and port mapping to avoid flood next time
        if eth_src not in self.mac_to_port[dpid].keys():
            self.mac_to_port[dpid][eth_src] = in_port

        # judge the packet is ARP or not
        arp_pkt = pkt.get_protocol(arp.arp)

        # the packet is ARP
        if arp_pkt:

            # the packet is an ARP request
            if arp_pkt.opcode == arp.ARP_REQUEST:
                arp_src_ip = arp_pkt.src_ip
                arp_dst_ip = arp_pkt.dst_ip
                if arp_src_ip not in self.last_time[dpid].keys():
                    self.last_time[dpid].setdefault(arp_src_ip, {})
                    self.last_time[dpid][arp_src_ip][arp_dst_ip] = ev.timestamp
                else:
                    if arp_dst_ip not in self.last_time[dpid][arp_src_ip].keys():
                        self.last_time[dpid][arp_src_ip][arp_dst_ip] = ev.timestamp
                    else:

                        # 120 is normal ARP cache time
                        if ev.timestamp - self.last_time[dpid][arp_src_ip][arp_dst_ip] < 120:
                            print('Two ARP request gap too short, drop the packet!')
                            print('just between {} second'.format(ev.timestamp - self.last_time[dpid][arp_src_ip][arp_dst_ip]))
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
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)