package ARP;

import network.IpAddres;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class ArpFrameBuilder {

    private static final MacAddress ZERO_MAC = MacAddress.getByName("00:00:00:00:00:00");

    private static InetAddress toInet4(IpAddres ip) {
        try {
            return InetAddress.getByAddress(ip.toBytes()); // 4 байти -> Inet4Address
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv4: " + ip, e);
        }
    }

    /** who-has targetIp? tell srcIp */
    public static EthernetPacket buildRequest(MacAddress srcMac, IpAddres srcIp, IpAddres targetIp) {
        ArpPacket.Builder arp = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) 6)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(srcMac)
                .srcProtocolAddr(toInet4(srcIp))
                .dstHardwareAddr(ZERO_MAC)                // у ARP-request target MAC невідомий -> 00:00:00:00:00:00
                .dstProtocolAddr(toInet4(targetIp));

        EthernetPacket.Builder eth = new EthernetPacket.Builder()
                .srcAddr(srcMac)
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS) // Ethernet-level broadcast
                .type(EtherType.ARP)
                .payloadBuilder(arp)
                .paddingAtBuild(true);

        return eth.build();
    }

    /** is-at srcIp (unicast reply to dstMac/dstIp) */
    public static EthernetPacket buildReply(MacAddress srcMac, IpAddres srcIp,
                                            MacAddress dstMac, IpAddres dstIp) {
        ArpPacket.Builder arp = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) 6)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(srcMac)
                .srcProtocolAddr(toInet4(srcIp))
                .dstHardwareAddr(dstMac)
                .dstProtocolAddr(toInet4(dstIp));

        EthernetPacket.Builder eth = new EthernetPacket.Builder()
                .srcAddr(srcMac)
                .dstAddr(dstMac)
                .type(EtherType.ARP)
                .payloadBuilder(arp)
                .paddingAtBuild(true);

        return eth.build();
    }
}
