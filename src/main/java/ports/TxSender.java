package ports;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.EthernetPacket;

import java.util.Objects;

public class TxSender {

    private final IfBindingManager binding;

    public TxSender(IfBindingManager binding) {
        this.binding = Objects.requireNonNull(binding);
    }


    public void send(String ifName, EthernetPacket frame) throws Exception {
        PcapHandle h = binding.getHandle(ifName);
        if (h == null) throw new IllegalStateException("No pcap handle for " + ifName);
        h.sendPacket(frame);
        System.out.println("sended");
    }
}
