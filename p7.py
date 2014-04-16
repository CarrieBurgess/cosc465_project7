from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ipv4 import ipv4,tcp
from pox.lib.addresses import IPAddr,EthAddr
import pox.openflow.libopenflow_01 as of

ANOTHERGLOBALVARIABLE = "but Sommers doesn't like global variables\n"
totally_shocked_student = "surely you can't be serious!\n"
Curt_Mahoney = "I am serious. And don't call me Shirley\n"

class p7(object):
    def __init__ (self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        # yippee.  a switch connected to us.
        log.info("Got connection from {}".format(event.connection))

    def _handle_PacketIn (self, event):
        inport = event.port # input port number on which packet arrived at switch
        packet = event.parsed # reference to POX packet object
        pktin = event.ofp # reference to Openflow PacketIn message (ofp_packet_in)

        if not packet.parsed:
            log.warning("{} {} ignoring unparsed packet".format(dpid, inport))
            return

        # packet is a "normal" POX packet object
        tcphdr = packet.find('tcp')

        if tcphdr is None:
            flood = of.ofp_action_output()
            flood.port = of.OFPP_FLOOD
            pktout = of.ofp_packet_out()
            pktout.in_port = inport
            pktout.actions = [flood]
            pktout.data = packet
            event.connection.send(pktout.pack())

        else: 
            # for any TCP traffic, install Openflow rules
            dstip = str(packet.dstip)
            actions = []
            if(IPAddr('10.0.0.4') in [packet.srcip, packet.dstip] or inport!=5):
                actions += [of.ofp_action_dl_addr(
                        dl_addr = EthAddr('00:00:00:00:00:05'))
                outport = 5
            else:
                outport = int(dstip[len(dstip)-1])

            actions += [of.ofp_action_output(port = outport)]
            send_flowmod(event, packet, actions) 

def send_flowmod(event, packet, actions):
    flowmod = of.ofp_flow_mod(command = of.OFPC_ADD,
                    idle_timeout=10,
                    hard_timeout=10,
                    buffer_id = event.ofp.buffer_id
                    match = of.ofp_match.from_packet(packet, event.port)
                    actions = actions)
    event.connection.send(flowmod.pack())


def launch():
    core.registerNew(p7)
