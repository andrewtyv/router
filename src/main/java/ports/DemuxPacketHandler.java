package ports;

import ARP.ArpEngine;
import DHCP.DHCPEngine;
import network.IpAddres;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import rip.RipEngine;
import rip.RipParser;


public class DemuxPacketHandler implements PacketHandler {

    private final ArpEngine arp;
    private final RipEngine rip;
    private final Forwarder fwd;
    private final DHCPEngine dhcp;

    public DemuxPacketHandler(ArpEngine arp, RipEngine rip, Forwarder fwd, DHCPEngine dhcp) {
        this.arp = arp;
        this.rip = rip;
        this.fwd = fwd;
        this.dhcp = dhcp;
    }

    @Override
    public void onPacket(EthernetPacket eth, String ifName) {
        EtherType et = eth.getHeader().getType();

        if (EtherType.ARP.equals(et)) {
            System.out.println("demux arp works");
            arp.onEthernetFrame(eth, ifName);
            System.out.println();
            return;
        } else if (!EtherType.IPV4.equals(et)) {
            return; // ignore
        } else if (!(eth.getPayload() instanceof IpV4Packet ip4)) return;

        else {
            IpV4Packet ip = (IpV4Packet) eth.getPayload();

            if (ip.getHeader().getProtocol().equals(IpNumber.UDP) && ip.getPayload() instanceof UdpPacket udp) {
                int srcPort = udp.getHeader().getSrcPort().valueAsInt();
                int dstPort = udp.getHeader().getDstPort().valueAsInt();


                if (srcPort == 520 || dstPort == 520) {
                    System.out.println("we have rip here");

                    byte[] udpPayload = udp.getPayload() != null ?
                            udp.getPayload().getRawData() : new byte[0];

                    IpAddres srcIp = new IpAddres(ip.getHeader().getSrcAddr().getHostAddress());
                    rip.onRipPacket(ifName, srcIp, udpPayload);
                    return;
                }


                if ((srcPort == 68 && dstPort == 67) || (srcPort == 67 && dstPort == 68)) {

                    System.out.println("we have dhcp here");

                    byte[] udpPayload = udp.getPayload() != null
                            ? udp.getPayload().getRawData()
                            : new byte[0];

                    MacAddress srcMac = eth.getHeader().getSrcAddr();
                    IpAddres srcIp = new IpAddres(ip.getHeader().getSrcAddr().getHostAddress());

                    if (dhcp != null) {
                        System.out.println("DHCP working");
                        dhcp.onDhcpPacket(ifName, srcMac, srcIp, udpPayload);
                    }
                    return;
                }

            }
        }
        fwd.onIpv4Frame(eth, ifName);

    }
}
