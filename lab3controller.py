# Lab 3 Skeleton
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.

    msg = of.ofp_flow_mod()
    msg.match.dl_type = pkt.ARP_TYPE
    port = self.macToPort[packet.dst]

    #https://stackoverflow.com/questions/54407743
    #/sdn-pox-controller-arp-type-ip-type-but-no-icmp-type
    if packet.type == pkt.ARP_TYPE :
    	log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, packet.port, packet.dst, port))
    	msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, packet_in.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = packet_in 
        self.connection.send(msg)
    elif packet.type == pkt.IP_TYPE :
    	ip_packet = packet.payload
    	if ip_packet.protocol == pkt.ICMP_PROTOCOL :
    		log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
    		msg = of.ofp_flow_mod()
        	msg.match = of.ofp_match.from_packet(packet, packet.port)
        	msg.idle_timeout = 10
        	msg.hard_timeout = 30
        	msg.actions.append(of.ofp_action_output(port = port))
        	msg.data = packet_in 
        	self.connection.send(msg)
    else :
		self.connection.send(msg)        



  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
