package ports;

import network.IpAddres;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import rip.RipV2;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.List;

public final class RipTx {

    private RipTx() {}

    private static final MacAddress RIP_V2_MULTICAST_MAC =
            MacAddress.getByName("01:00:5e:00:00:09");
    private static final String RIP_V2_MULTICAST_IP = "224.0.0.9";
    private static final UdpPort RIP_PORT = UdpPort.getInstance((short) 520);

    public static void sendRipResponse(TxSender txHandle,
                                       MacAddress ifMac,
                                       IpAddres ifIp,
                                       String ifname,
                                       List<RipV2.RipRte> rtes) throws Exception {

        if (txHandle == null) {
            throw new IllegalArgumentException("txHandle is null");
        }

        List<byte[]> payloads = RipV2.buildRipResponsePayloads(rtes);
        if (payloads.isEmpty()) {
            return;
        }

        Inet4Address srcIp = (Inet4Address) InetAddress.getByName(ifIp.toString());
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName(RIP_V2_MULTICAST_IP);

        for (byte[] ripPayload : payloads) {

            UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
            udpBuilder
                    .srcPort(RIP_PORT)
                    .dstPort(RIP_PORT)
                    .srcAddr(srcIp)
                    .dstAddr(dstIp)
                    .payloadBuilder(new UnknownPacket.Builder().rawData(ripPayload))
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
            ipBuilder
                    .version(IpVersion.IPV4)
                    .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                    .ttl((byte) 1)
                    .protocol(IpNumber.UDP)
                    .srcAddr(srcIp)
                    .dstAddr(dstIp)
                    .payloadBuilder(udpBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            EthernetPacket.Builder ethBuilder = new EthernetPacket.Builder();
            ethBuilder
                    .srcAddr(ifMac)
                    .dstAddr(RIP_V2_MULTICAST_MAC)

                    .type(EtherType.IPV4)
                    .payloadBuilder(ipBuilder)
                    .paddingAtBuild(true);

            EthernetPacket frame = ethBuilder.build();

            try {
                txHandle.send(ifname,frame);
            } catch (PcapNativeException e) {
                e.printStackTrace();
            }
        }
    }
}
