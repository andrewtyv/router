package ports;

import ARP.ArpEngine;
import network.IpAddres;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.UdpPort;
import rip.RipEngine;


public class DemuxPacketHandler implements PacketHandler {

    private final ArpEngine arp;
    private final RipEngine rip;
    private final Forwarder fwd;

    public DemuxPacketHandler(ArpEngine arp, RipEngine rip,Forwarder fwd ) {
        this.arp = arp;
        this.rip = rip;
        this.fwd = fwd;
    }

    @Override
    public void onPacket(EthernetPacket eth, String ifName) {
        EtherType et = eth.getHeader().getType();

        // 1) ARP
        if (EtherType.ARP.equals(et)) {
            System.out.println("demux arp works");
            arp.onEthernetFrame(eth, ifName);
            System.out.println();
            return;
        }
        else if (!EtherType.IPV4.equals(et)) {
            return; // ignore
        }

        else if (!(eth.getPayload() instanceof IpV4Packet ip4)) return;

       else  if (EtherType.IPV4.equals(et)) {
            fwd.onIpv4Frame(eth, ifName);
            return;
        }
        // TODO dhcp


        /*// RIP: UDP:520 → 224.0.0.9
        if (ip4.getHeader().getProtocol() == IpNumber.UDP && ip4.getPayload() instanceof UdpPacket udp) {
            UdpPort dst = udp.getHeader().getDstPort();
            if (dst != null && dst.valueAsInt() == 520) {
                IpAddres srcIp = new IpAddres(ip4.getHeader().getSrcAddr().getHostAddress());
                byte[] ripPayload = udp.getPayload() == null ? new byte[0] : udp.getPayload().getRawData();
                rip.onRipPacket(ifName, srcIp, ripPayload);
                return;
            }
        }
        */
    }
}
