from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
import datetime


class TrafficMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    BLOCKED_IP = "10.0.0.3"   # Host to block

    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.stats_history = []

        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

    # ─── Switch Handshake ───────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Switch connected: %s", datapath.id)

        # Table-miss flow (send to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        # 🔒 Block IPv4 traffic from host
        match_ipv4 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.BLOCKED_IP
        )
        self._add_flow(datapath, priority=100, match=match_ipv4,
                       actions=[], idle=0, hard=0)

        # 🔒 Block ARP from host (prevents MAC resolution)
        match_arp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_spa=self.BLOCKED_IP
        )
        self._add_flow(datapath, priority=100, match=match_arp,
                       actions=[], idle=0, hard=0)

    # ─── Datapath Tracking ──────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Datapath registered: %s", dp.id)

        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.logger.info("Datapath unregistered: %s", dp.id)

    # ─── Packet-In Handler (Learning Switch) ────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 🚫 Ignore LLDP (prevents controller overhead)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = dp.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install flow for known destinations
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst
            )

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(dp, 1, match, actions,
                               buffer_id=msg.buffer_id)
                return
            else:
                self._add_flow(dp, 1, match, actions)

        # Send packet out
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    # ─── Flow Installation Helper ───────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, idle=30, hard=0):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard
        )

        if buffer_id is not None:
            kwargs['buffer_id'] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    # ─── Monitoring Thread ──────────────────────────────────────────────────

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser

        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
        datapath.send_msg(parser.OFPPortStatsRequest(
            datapath, 0, datapath.ofproto.OFPP_ANY))

    # ─── Flow Stats Handler ─────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info("\n=== FLOW STATS | Switch %s | %s ===",
                         ev.msg.datapath.id,
                         datetime.datetime.now().strftime("%H:%M:%S"))

        for stat in sorted(body, key=lambda s: s.priority, reverse=True):
            # Log only active flows (reduce noise)
            if stat.packet_count > 0:
                self.logger.info(
                    "P=%d Match=%s Packets=%d Bytes=%d",
                    stat.priority,
                    stat.match,
                    stat.packet_count,
                    stat.byte_count
                )

        # 📊 Maintain bounded history
        self.stats_history.append({
            "time": str(datetime.datetime.now()),
            "flows": [(s.priority, s.packet_count, s.byte_count)
                      for s in body]
        })

        if len(self.stats_history) > 100:
            self.stats_history.pop(0)

    # ─── Port Stats Handler ─────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info("\n=== PORT STATS | Switch %s ===",
                         ev.msg.datapath.id)

        for stat in body:
            # Log only active ports
            if stat.rx_packets > 0 or stat.tx_packets > 0:
                self.logger.info(
                    "Port %d | RX:%d TX:%d | RX-bytes:%d TX-bytes:%d",
                    stat.port_no,
                    stat.rx_packets,
                    stat.tx_packets,
                    stat.rx_bytes,
                    stat.tx_bytes
                )
