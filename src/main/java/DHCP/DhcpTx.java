package DHCP;

import ARP.IfAddressBook;
import network.IpAddres;
import network.IpMask;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import ports.TxSender;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public class DhcpTx {

    private final TxSender txSender;
    private final IfAddressBook ifBook;

    public DhcpTx(TxSender txSender, IfAddressBook ifBook) {
        this.txSender = txSender;
        this.ifBook = ifBook;
    }

    public void sendOffer(String ifName,
                          MacAddress clientMac,
                          int xid,
                          IpAddres offeredIp,
                          IpMask mask,
                          IpAddres gateway,
                          long leaseMs) {

        byte[] payload = buildDhcpPayload(
                (byte) 2,
                (byte) 2,
                xid,
                clientMac,
                offeredIp,
                mask,
                gateway,
                leaseMs
        );

        sendUdp(ifName, clientMac, payload);
    }

    public void sendAck(String ifName,
                        MacAddress clientMac,
                        int xid,
                        IpAddres offeredIp,
                        IpMask mask,
                        IpAddres gateway,
                        long leaseMs) {

        byte[] payload = buildDhcpPayload(
                (byte) 2,
                (byte) 5,
                xid,
                clientMac,
                offeredIp,
                mask,
                gateway,
                leaseMs
        );

        sendUdp(ifName, clientMac, payload);
    }

    private void sendUdp(String ifName, MacAddress clientMac, byte[] dhcpPayload) {

        MacAddress srcMac = ifBook.getMac(ifName);
        IpAddres   srcIpAddr = ifBook.getIp(ifName);

        if (srcMac == null || srcIpAddr == null) {
            System.out.println("DhcpTx: no MAC/IP for interface " + ifName);
            return;
        }

        try {
            Inet4Address srcIp = (Inet4Address) InetAddress.getByName(srcIpAddr.toString());
            Inet4Address dstIp = (Inet4Address) InetAddress.getByName("255.255.255.255");
            MacAddress dstMac = MacAddress.ETHER_BROADCAST_ADDRESS;

            UnknownPacket.Builder dhcpPayloadBuilder =
                    new UnknownPacket.Builder().rawData(dhcpPayload);

            UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
            udpBuilder
                    .srcPort(UdpPort.BOOTPS)
                    .dstPort(UdpPort.BOOTPC)
                    .srcAddr(srcIp)
                    .dstAddr(dstIp)
                    .payloadBuilder(dhcpPayloadBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            // IPv4
            IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
            ipBuilder
                    .version(IpVersion.IPV4)
                    .ihl((byte) 5)
                    .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                    .ttl((byte) 64)
                    .protocol(IpNumber.UDP)
                    .srcAddr(srcIp)
                    .dstAddr(dstIp)
                    .payloadBuilder(udpBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);
            // Ethernet
            EthernetPacket.Builder eth = new EthernetPacket.Builder();
            eth.srcAddr(srcMac)
                    .dstAddr(dstMac)
                    .type(EtherType.IPV4)
                    .payloadBuilder(ipBuilder)
                    .paddingAtBuild(true);

            EthernetPacket pkt = eth.build();

            txSender.send(ifName, pkt);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private byte[] buildDhcpPayload(byte op,
                                    byte dhcpMsgType,
                                    int xid,
                                    MacAddress clientMac,
                                    IpAddres yiaddr,
                                    IpMask mask,
                                    IpAddres gateway,
                                    long leaseMs) {

        ByteBuffer buf = ByteBuffer.allocate(300);

        // fixed header
        buf.put(op);            // op
        buf.put((byte) 1);      // htype = ethernet
        buf.put((byte) 6);      // hlen = MAC len
        buf.put((byte) 0);      // hops
        buf.putInt(xid);        // xid
        buf.putShort((short) 0);      // secs
        buf.putShort((short) 0x8000); // flags: broadcast

        buf.putInt(0);                   // ciaddr
        buf.putInt(yiaddr.toInt());      // yiaddr
        buf.putInt(gateway.toInt());     // siaddr (server IP)
        buf.putInt(0);                   // giaddr

        // chaddr (16 bytes)
        byte[] macBytes = clientMac.getAddress();
        byte[] chaddr = new byte[16];
        System.arraycopy(macBytes, 0, chaddr, 0, Math.min(macBytes.length, 6));
        buf.put(chaddr);

        // sname + file
        buf.put(new byte[64 + 128]);

        // magic cookie
        buf.put((byte) 0x63);
        buf.put((byte) 0x82);
        buf.put((byte) 0x53);
        buf.put((byte) 0x63);

        // option 53: DHCP message type
        buf.put((byte) 53);
        buf.put((byte) 1);
        buf.put(dhcpMsgType);

        // option 54: server identifier (gateway IP)
        buf.put((byte) 54);
        buf.put((byte) 4);
        putIp(buf, gateway);

        // option 1: subnet mask
        buf.put((byte) 1);
        buf.put((byte) 4);
        putMask(buf, mask);

        // option 3: router (default gateway)
        buf.put((byte) 3);
        buf.put((byte) 4);
        putIp(buf, gateway);

        // option 51: lease time
        int leaseSec = (int) (leaseMs / 1000);
        buf.put((byte) 51);
        buf.put((byte) 4);
        buf.putInt(leaseSec);

        // END
        buf.put((byte) 255);

        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }


    private void putIp(ByteBuffer buf, IpAddres ip) {
        int v = ip.toInt();
        buf.put((byte) ((v >>> 24) & 0xFF));
        buf.put((byte) ((v >>> 16) & 0xFF));
        buf.put((byte) ((v >>> 8)  & 0xFF));
        buf.put((byte) (v & 0xFF));
    }

    private void putMask(ByteBuffer buf, IpMask mask) {
        int v = mask.toInt();
        buf.put((byte) ((v >>> 24) & 0xFF));
        buf.put((byte) ((v >>> 16) & 0xFF));
        buf.put((byte) ((v >>> 8)  & 0xFF));
        buf.put((byte) (v & 0xFF));
    }
}
