from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import datetime

class TrafficMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.stats_history = []   # for reporting

    # ─── Switch Handshake ───────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow: send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected", datapath.id)
        
        # Block ALL traffic from h3's MAC (more reliable than IP blocking)
        # First we need to find h3's MAC — use a fixed MAC approach instead
        # Block by IP but also handle ARP - add higher priority
        match_block = parser.OFPMatch(eth_type=0x0800, ipv4_src='10.0.0.3')
        self._add_flow(datapath, 100, match_block, [], idle=0, hard=0)  # permanent rule

        #match_block_arp = parser.OFPMatch(eth_type=0x0806, arp_spa='10.0.0.3')
        #self._add_flow(datapath, 100, match_block_arp, [], idle=0, hard=0)  # block ARP too
        
        #match allowing ARP
        match_arp = parser.OFPMatch(eth_type=0x0806)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, 50, match_arp, actions_arp)

    # ─── Track connected datapaths ──────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Registered datapath: %s", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.logger.info("Unregistered datapath: %s", datapath.id)

    # ─── Packet-In Handler (L2 Learning + Flow Installation) ────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
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
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule for known destination
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self._add_flow(datapath, 1, match, actions)

        # Send packet out
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ─── Flow Entry Helper ───────────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=10, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle,
                hard_timeout=hard
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle,
                hard_timeout=hard
            )

        datapath.send_msg(mod)

    # ─── Periodic Stats Polling (every 5 seconds) ───────────────────────────

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        # Request flow stats
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        # Request port stats
        req = parser.OFPPortStatsRequest(
            datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # ─── Flow Stats Reply Handler ────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info("\n" + "="*60)
        self.logger.info("FLOW TABLE — Switch %016x @ %s",
                         ev.msg.datapath.id,
                         datetime.datetime.now().strftime("%H:%M:%S"))
        self.logger.info("%-10s %-20s %-12s %-12s",
                         'Priority', 'Match', 'Packets', 'Bytes')
        self.logger.info("-"*60)
        for stat in sorted(body, key=lambda s: s.priority, reverse=True):
            self.logger.info("%-10s %-20s %-12d %-12d",
                             stat.priority,
                             str(stat.match),
                             stat.packet_count,
                             stat.byte_count)
        # Save to history for report
        self.stats_history.append({
            'time': str(datetime.datetime.now()),
            'flows': [(s.priority, s.packet_count, s.byte_count)
                      for s in body]
        })

    # ─── Port Stats Reply Handler ────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info("\n" + "="*60)
        self.logger.info("PORT STATS — Switch %016x", ev.msg.datapath.id)
        self.logger.info("%-8s %-15s %-15s %-10s %-10s",
                         'Port', 'RX-pkts', 'TX-pkts', 'RX-bytes', 'TX-bytes')
        self.logger.info("-"*60)
        for stat in body:
            self.logger.info("%-8d %-15d %-15d %-10d %-10d",
                             stat.port_no,
                             stat.rx_packets, stat.tx_packets,
                             stat.rx_bytes,   stat.tx_bytes)
