from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ipv4 import ipv4,tcp
from pox.lib.addresses import IPAddr,EthAddr
import pox.openflow.libopenflow_01 as of


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
            # for any non-TCP traffic, flood out all ports
            #Houston, we have a problem.
            #Surely you aren't serious!
            #I am serious.  And don't call me Shirley.
            flood = of.ofp_action_output()
            flood.port = of.OFPP_FLOOD
            pktout = of.ofp_packet_out()
            pktout.in_port = inport
            pktout.actions = [flood]
            pktout.data = packet
            event.connection.send(pktout.pack())

        else: 
            # for any TCP traffic, install Openflow rules
            pass


def launch():
    core.registerNew(p7)
