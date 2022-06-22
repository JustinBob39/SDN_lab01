# 二层交换机

## 自学习交换机

### 拓扑图

直接 `python topo_1969_1.py` 或者 `python3 topo_1969_1.py` 都会报错

既然直接执行不行，那我们另辟蹊径，通过mn指定拓扑文件

`sudo mn --custom topo_1969_1.py --topo GeneratedTopo --controller remote`

在执行上面那条命令之前，需要在代码中加入一行

![image-20220408160523990](https://cdn.justinbob.site/typora/202204081605040.png)

对了，上面的 py 文件都是相对路径，也可以使用绝对路径



成功启动拓扑文件，links 查看链路连接情况

![image-20220408160227137](https://cdn.justinbob.site/typora/202204081602990.png)



绘制拓扑图

![SDN_lab01_1](https://cdn.justinbob.site/typora/202204081603814.png)



### 算法思想

其实很朴素

就是当一个 Packet_In 消息被控制器接收后，控制器检查这个 Packet_In 携带的是不是 Ethernent 类型

如果是 Ethernnet 类型的话，就提取出 eth_src 和 in_port 建立映射关系，进行学习

后面还有 Ethernent 类型数据包的话，检测是否已经学习了 dst_mac 的端口，如果学习到了，下发流表，指定从学习到的端口转发；如果没有学习到，进行泛洪

需要注意的是，我们这次实验都是二层交换机，不会修改数据包的 eth_src 字段

in_port 指的是交换机从哪个端口收到的报文，匹配到 Table_Miss ，然后交给控制器处理



### 关键代码

在 Switch 类中定义一个数据结构，用来存储源 mac 地址和端口的映射关系，每个交换机都需要这样的数据结构

首先定义一个字典

`self.mac_to_port = {}`

然后将每个 dpid 键对应的值也定义为字典，字典的嵌套

`self.mac_to_port.setdefault(dpid, {})`

学习一个源 mac 地址和端口的对应关系，存储到相应的 dpid 中

`self.mac_to_port[dpid][src] = in_port`

当后面有新的 Ethernet 数据包进入控制器时，对目的 mac 地址进行检查

```python
if dst in self.mac_to_port[dpid]:
	out_port = self.mac_to_port[dpid][dst]
else:
	out_port = ofp.OFPP_FLOOD
	
actions = [parser.OFPActionOutput(out_port)]
```

如果不是泛洪，还可以下发流表

```python
if out_port != ofp.OFPP_FLOOD:
	match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
	self.add_flow(dp, 10, match, actions, 90, 180)
```



### 实验结果

![image-20220408163808213](https://cdn.justinbob.site/typora/202204081638306.png)



S1 流表

![image-20220408164423602](https://cdn.justinbob.site/typora/202204081644700.png)



S2 流表

![image-20220408164444824](https://cdn.justinbob.site/typora/202204081644852.png)



S3 流表

![image-20220408164515079](https://cdn.justinbob.site/typora/202204081645110.png)



S4 流表

![image-20220408164604454](https://cdn.justinbob.site/typora/202204081646514.png)



## 环路广播

### 拓扑图

可以看到 S1、S3、S4 形成了一个环路

如果不解决环路问题，ARP Request会一直在环路中存在，而且也会导致学习到的源 mac 地址和端口的关系异常，出现无法 ping 通的情况

![SDN_lab01_2](https://cdn.justinbob.site/typora/202204081648674.png)

### 算法思想

记录第一次 ARP 请求使用的端口，如果下次，同样内容的 ARP 请求报文，从不同的端口进来，说明网络中很可能有环路，我们需要把这个数据包丢弃

### 关键代码

在 Switch 类中定义一个数据结构 `self.arp_in_port={}` ，用来存储每个交换机收到的每个源 mac 地址请求每个目标 ip 的端口

首先，老样子 `self.arp_in_port.setdefault{dpid, {}}` ，每个交换机都需要存储

* 没有源 mac 地址记录，执行`self.arp_in_port[dpid].setdefault{arp_src_mac, {}}`，并添加记录 `self.arp_in_port[dpid][arp_src_mac][arp_dst_ip]=in_port`

* 有源 mac 地址记录，检查是否有目标 ip 的记录
    * 有目标 ip 的记录，检查端口
        * in_port 与记录值一致，正常进行泛洪
        * in_port与记录值不一致，就进行丢弃
    * 没有目标 ip 的记录，添加记录 `self.arp_in_port[dpid][arp_src_mac][arp_dst_ip]=in_port`



### 实验结果

![image-20220408172454887](https://cdn.justinbob.site/typora/202204081724931.png)

![image-20220408172530594](https://cdn.justinbob.site/typora/202204081725621.png)



S1 流表

![image-20220408172633476](https://cdn.justinbob.site/typora/202204081726508.png)



S2 流表

![image-20220408172651517](https://cdn.justinbob.site/typora/202204081726549.png)



S3 流表

![image-20220408172711293](https://cdn.justinbob.site/typora/202204081727325.png)



S4 流表

![image-20220408172734441](https://cdn.justinbob.site/typora/202204081727480.png)



## 扩展部分

传统网络解决环路问题，主要采用的 STP 算法，最小生成树算法，ryu也有相应的实现和封装，就是利用每个端口有一个状态转移图，跑完 STP 算法后，有的端口就不能转发数据包了，被 block 掉了大概是这样

### 算法思想

我想了三种方案

1. 时间戳，如果在 ARP 缓存时间内，出现了同一个 ARP 请求，直接丢弃，不进行转发

    因为 ARP 请求会交付给控制器处理，产生一个 Packet_In 时间，我们记录本次这个 ARP 请求的时间戳

    如果下次，还是同样内容的 ARP 请求，但是两个时间戳间隔没有超过 120s， 120s大概是正常的 ARP 缓存时间，

    直接丢弃，这种方法非常简单高效

2. ARP 请求统一交给控制器处理，控制器响应目标 ip 的 mac 地址，避免了 ARP 泛洪，类似于 ARP 代理，并且算出路径，在路径上的交换机上下发流表

    首先必须执行一次 pingall，让控制器学习到所有的 host 的 mac 地址，学习到 host 连接在哪个交换机上

    通过 api 获取交换机之间的连接线路，执行ryu的时候加上 `--observe-links` ，构建一个无向图，每个边的权重为1

    路径规划采用的是 networkx ，计算跳数最小的路径，对路径上所有的交换机下发流表，一路畅通无阻

    这种方法也很好，很SDN

3. 将交换机分类，采用懒惰策略，破坏对称性，候选交换机向所有端口泛洪，其他的交换机只向连接客户机的接口转发

    这种方法是最有工程意义的，是我在国外的一篇论文上看到的，我来详细描述一下吧

    首先，通过 api 获取到交换机之间的连接，跑下面的算法，newtworkx 真的很好用，真的是我这种算法菜鸡的福音

    ![image-20220408174427258](https://cdn.justinbob.site/typora/202204081744291.png)

    算出了candidate，基本上已经成功了 80%，还有一些细致的事情要done

    * ARP 请求来自自己连接的 host，向所有端口泛洪
    * ARP 请求来自别的交换机
        * 自己是candidate，向所有端口泛洪
        * 自己不是candidate，向连接 host 的端口转发，向 host 端口泛洪通过组表实现

    其实文献里说过，candidate 可能还会有环路，如果拓扑特别复杂的话，对 candidate 还要跑一遍 STP，我不太会，就没搞了

    [文献下载链接](https://justinbob.site/file/SDN_lab01.pdf)



### 关键代码

因为我不是很熟悉 python ，也是边学边做，代码写的很烂，就不贴出来献丑了

如果大家有需要，可以在附件中获取



### 实验结果

### 方案一

![image-20220408174920902](https://cdn.justinbob.site/typora/202204081749939.png)



ryu 输出

![image-20220408174948933](https://cdn.justinbob.site/typora/202204081749974.png)



S1 流表

![image-20220408175145490](https://cdn.justinbob.site/typora/202204081751527.png)



S2 流表

![image-20220408175206028](https://cdn.justinbob.site/typora/202204081752068.png)



S3 流表

![image-20220408175226349](https://cdn.justinbob.site/typora/202204081752387.png)



S4 流表

![image-20220408175244467](https://cdn.justinbob.site/typora/202204081752505.png)



### 方案二

![image-20220408175719666](https://cdn.justinbob.site/typora/202204081757710.png)



ryu 输出

![image-20220408214918023](https://cdn.justinbob.site/typora/202204082152207.png)



S1 流表

![image-20220408215321160](https://cdn.justinbob.site/typora/202204082153202.png)



S2 流表

![image-20220408215336583](https://cdn.justinbob.site/typora/202204082153651.png)



S3 流表

![image-20220408215353643](https://cdn.justinbob.site/typora/202204082153705.png)



S4 流表

![image-20220408215409889](https://cdn.justinbob.site/typora/202204082154922.png)



### 方案三

算出 cadidate 只有 S1

![image-20220408175924322](https://cdn.justinbob.site/typora/202204081759366.png)



![image-20220408180010559](https://cdn.justinbob.site/typora/202204081800597.png)



ryu输出

![image-20220408180051704](https://cdn.justinbob.site/typora/202204081800751.png)



S1 流表

![image-20220408180646426](https://cdn.justinbob.site/typora/202204081806463.png)



S2 流表

![image-20220408180706139](https://cdn.justinbob.site/typora/202204081807171.png)



S3 流表

![image-20220408180720826](https://cdn.justinbob.site/typora/202204081807858.png)



S4 流表

![image-20220408180738710](https://cdn.justinbob.site/typora/202204081807745.png)



## 附件

### lab01_part1.py

```python
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)

        # maybe you need a global data structure to save the mapping
        self.mac_to_port = {}

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
        self.mac_to_port.setdefault(dpid, {})

        # the port that receive the packet
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # get the mac
        dst = eth_pkt.dst
        src = eth_pkt.src

        # we can use the logger to print some useful information
        self.logger.info('packet: %s %s %s %s', dpid, src, dst, in_port)

        # you need to code here to avoid the direct flooding
        # having fun
        # :)
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        # add flow table to the switch
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(dp, 10, match, actions, 90, 180)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

```



### lab01_part2.py

```python
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

```



### lab01_addtion1.py

```python
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

```



### lab01_addtion2.py

```python
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

```



### lab01_addtion3.py

```python
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

```
