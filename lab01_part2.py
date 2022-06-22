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

        # global data structure to save the mapping
        self.mac_to_port = {}

        self.arp_in_port = {}

    # add a flow table entry in switch
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # construct a FlowMod message, send it to a switch to add a flow table entry
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    # add default flow table which sends packets to the controller
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

        # set mac_to_port and arp_in_port values to dictionary
        self.mac_to_port.setdefault(dpid, {})
        self.arp_in_port.setdefault(dpid, {})

        # print mac_to_port
        # print('**** mac_to_port OF SWITCH {} ****'.format(dpid))
        # for mac,port in self.mac_to_port[dpid].items():
        #     print(mac, port)

        # the port receive the packet
        in_port = msg.match['in_port']

        # make a packet using the msg.data
        pkt = packet.Packet(msg.data)

        # judge the packet is Ethernet or not
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # the packet is Ethernet
        if eth_pkt:

            # ignore the LLDP and IPv6 packet
            if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
                return

            # get the mac address
            eth_dst = eth_pkt.dst
            eth_src = eth_pkt.src

            # use the logger to print some useful information
            # self.logger.info('Packet    dpid:{} eth_src:{} eth_dst:{} in_port:{}'.format(dpid, eth_src, eth_dst, in_port))


            # learn a source mac & port relation
            if eth_src not in self.mac_to_port[dpid].keys():
                self.mac_to_port[dpid][eth_src] = in_port

            # judge the packet is ARP protocol or not
            arp_pkt = pkt.get_protocol(arp.arp)

            # the packet is ARP
            if arp_pkt:

                # the packet is an ARP request
                if arp_pkt.opcode == arp.ARP_REQUEST:

                    # get the request destination ip and source mac
                    req_dst_ip = arp_pkt.dst_ip
                    arp_src_mac = arp_pkt.src_mac

                    # already have the arp_src_mac record
                    if arp_src_mac in self.arp_in_port[dpid].keys():

                        # already have the req_dst_ip record
                        if req_dst_ip in self.arp_in_port[dpid][arp_src_mac].keys():

                            # the ports are different
                            if in_port != self.arp_in_port[dpid][arp_src_mac][req_dst_ip]:

                                # drop the packet
                                match = parser.OFPMatch(in_port=in_port, arp_op=arp.ARP_REQUEST,
                                                        arp_tpa=req_dst_ip, arp_sha=arp_src_mac)
                                self.add_flow(datapath=dp, priority=20, match=match, actions=[],
                                              idle_timeout=300, hard_timeout=600)
                                print('add a drop flow entry to switch {}'.format(dpid))

                                print('self.arp_in_port[dpid][arp_src_mac][req_dst_ip] = {}'.format(self.arp_in_port[dpid][arp_src_mac][req_dst_ip]))
                                print('but this time in port = {}'.format(in_port))
                                print('Switch{} drop an ARP packet.'.format(dpid))
                                return
                            else:
                                pass

                        # do not have the req_dst_ip record
                        else:
                            self.arp_in_port[dpid][arp_src_mac][req_dst_ip] = in_port

                    # do not have the arp_src_mac record
                    else:
                        self.arp_in_port[dpid].setdefault(arp_src_mac, {})
                        self.arp_in_port[dpid][arp_src_mac][req_dst_ip] = in_port

                # the packet is ARP response
                else:
                    # print('This is not the ARP request.')
                    pass

            # the packet is not ARP
            else:
                # print('This is not the ARP protocol.')
                pass

            if eth_dst in self.mac_to_port[dpid].keys():
                out_port = self.mac_to_port[dpid][eth_dst]

            else:
                out_port = ofp.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # add flow table to the switch
            if out_port != ofp.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
                self.add_flow(dp, 10, match, actions, 90, 180)

            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            dp.send_msg(out)

        # the packet is not Ethernet
        else:
            # print('This is not the Ethernet protocol.')
            pass