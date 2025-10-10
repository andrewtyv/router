package ports;

import org.pcap4j.packet.EthernetPacket;

@FunctionalInterface
public interface PacketHandler {
    void onPacket(EthernetPacket frame, String ifName);
}
