#   ryu-manager Dataset_Collect_Attack.py

from __future__ import print_function
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import hub
import random
import os

import timeit

os.chdir(os.path.dirname(os.path.abspath(__file__)))

packets_in = 0
stat_replies = 0
flow_stats_file = open("flow_stats_attack.txt", "a+")


class Dataset_Collect(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Dataset_Collect, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        self.collect_thread = hub.spawn(self.collect)

    def collect(self):
        self.logger.info("Collecting flows to build dataset")
        while True:
            for datapath in self.datapaths.values():
                self.logger.info(
                    "Sending flow stats request for datapath %s", datapath.id)
                ofpro = datapath.ofproto
                ofpro_parser = datapath.ofproto_parser
                request = ofpro_parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(request)
            hub.sleep(random.randint(10, 15))

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply, ], MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        global flow_stats_file
        global stat_replies
        stat_replies += 1
        self.logger.info(
            "Receiving flow stats from datapath %s", ev.msg.datapath.id)

        start = timeit.default_timer()
        for stat in sorted([flow for flow in body if (flow.priority == 1)]):
            if int(stat.match['ip_proto']) == 1:
                flow_stats_file.write("\n" + str(ev.msg.datapath.id) + "," + str(stat.match['eth_src']) + "," + str(
                    stat.duration_sec) + "," + str(stat.match['ip_proto']) + "," + "0" + "," + "0" + "," + str(
                    stat.byte_count) + "," + str(stat.packet_count) + "," + "1")
            elif int(stat.match['ip_proto']) == 6:
                flow_stats_file.write("\n" + str(ev.msg.datapath.id) + "," + str(stat.match['eth_src']) + "," + str(
                    stat.duration_sec) + "," + str(stat.match['ip_proto']) + "," + str(
                    stat.match['tcp_src']) + "," + str(stat.match['tcp_dst']) + "," + str(stat.byte_count) + "," + str(
                    stat.packet_count) + "," + "1")
            elif int(stat.match['ip_proto']) == 17:
                flow_stats_file.write("\n" + str(ev.msg.datapath.id) + "," + str(stat.match['eth_src']) + "," + str(
                    stat.duration_sec) + "," + str(stat.match['ip_proto']) + "," + str(
                    stat.match['udp_src']) + "," + str(stat.match['udp_dst']) + "," + str(stat.byte_count) + "," + str(
                    stat.packet_count) + "," + "1")
        stop = timeit.default_timer()
        self.logger.info(
            "Stat reply %s takes %s seconds to process", stat_replies, stop-start)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global packets_in
        packets_in += 1
        start = timeit.default_timer()
        self.logger.info("Processing packet %s", packets_in)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            #self.logger.info("Aborting LLDP packet")
            return

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port), parser.OFPActionOutput(1)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                            eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                            eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port,
                                            tcp_dst=t.dst_port, )

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                            eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port,
                                            udp_dst=u.dst_port, )
                # verify if we have a valid buffer_id, if yes avoid to send both FLOW_MOD & PACKET_OUT
                # maximum buffer ID is NO BUFFER to due to OVS bug.
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,
                                  msg.buffer_id, idle=15)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=15)
                stop = timeit.default_timer()
                self.logger.info(
                    "Packet %s takes %s seconds to process", packets_in, stop-start)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle, instructions=inst)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, idle_timeout=idle, instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("Port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("Port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("Port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
