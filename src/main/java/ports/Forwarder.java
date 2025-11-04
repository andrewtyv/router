package ports;

import ARP.ArpEngine;
import ARP.IfAddressBook;
import network.IpAddres;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;
import ports.TxSender;
import rib.Rib;
import routingTable.RouteEntry;

import java.util.Optional;

public class Forwarder {

    private final Rib rib;
    private final ArpEngine arp;
    private final TxSender tx;
    private final IfAddressBook ifBook; // твій каталог MAC/IP по логічним інтерфейсам

    public Forwarder(Rib rib, ArpEngine arp, TxSender tx, IfAddressBook ifBook) {
        this.rib = rib;
        this.arp = arp;
        this.tx = tx;
        this.ifBook = ifBook;
    }

    public void onIpv4Frame(EthernetPacket ethIn, String inIf){
        if (ethIn.getHeader().getType() != EtherType.IPV4) return;
        if (!(ethIn.getPayload() instanceof IpV4Packet ip4)) return;

        IpAddres dst = new IpAddres(ip4.getHeader().getDstAddr().getHostAddress());

        if (!dst.isUnicast()) return;

        IpAddres local = ifBook.getIp(inIf);
        if (local != null && local.equals(dst)) return;
        // 2)  TTL
        int ttl = Byte.toUnsignedInt(ip4.getHeader().getTtl());
        if (ttl <= 1) {
            // TODO ICMP Time Exceeded
            return;
        }

        //  Lookup  RIB:
        Optional<RouteEntry> bestOpt = rib.lookup(dst);
        if (bestOpt.isEmpty()) {
            // TODO: ICMP Destination Unreachable (Network/Host)
            return;
        }
        RouteEntry re = bestOpt.get();
        String outIf = re.outIf();
        if (outIf == null) {
            // cannot send - drop
            return;
        }

        if (outIf.equals(inIf)) {
            return;
        }

        IpAddres l3Target = (re.nextHop() == null) ? dst : re.nextHop();

        IpV4Packet.Builder ipb = new IpV4Packet.Builder(ip4);
        ipb.ttl((byte) (ttl - 1))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);
        IpV4Packet ip4Out = ipb.build();

        arp.resolve(outIf, l3Target).thenAccept(dstMac -> {
            if (dstMac == null) {
                return;
            }
            MacAddress srcMac = ifBook.getMac(outIf);
            if (srcMac == null) return;

            EthernetPacket outEth = new EthernetPacket.Builder()
                    .dstAddr(dstMac)
                    .srcAddr(srcMac)
                    .type(EtherType.IPV4)
                    .payloadBuilder(new SimpleBuilder(ip4Out))
                    .paddingAtBuild(true)
                    .build();

            try {
                tx.send(outIf, outEth);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}
