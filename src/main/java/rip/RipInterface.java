package rip;

import network.IpAddres;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.util.MacAddress;
import rib.Rib;                    // твій інтерфейс RIB (якщо в іншому пакеті — поправ import)

public class RipInterface {

    private final String ifName;       // наприклад "eth0"
    private final MacAddress ifMac;    // MAC цього інтерфейсу
    private final IpAddres ifIp;       // IPv4 цього інтерфейсу
    private final PcapHandle txHandle; // TX-хендл pcap4j саме на цьому інтерфейсі
    private final Rib rib;

    public RipInterface(String ifName,
                        MacAddress ifMac,
                        IpAddres ifIp,
                        PcapHandle txHandle,
                        Rib rib) {
        this.ifName = ifName;
        this.ifMac = ifMac;
        this.ifIp = ifIp;
        this.txHandle = txHandle;
        this.rib = rib;
    }

    /** ТВОЙ КОД — відправка періодичного (або тригерного) апдейта на цьому інтерфейсі */
    public void sendPeriodicUpdate() throws Exception {
        boolean poisonReverse = true; // або false, якщо хочеш чистий split-horizon
        var rtes = RipRibAdapter.buildRtesForInterface(rib, ifName, poisonReverse);

        // якщо нема RTE — шлемо лише заголовок (ок для Cisco)
        if (rtes.isEmpty()) {
            rtes = java.util.List.of();
        }

       // RipTx.sendRipResponse(txHandle, ifMac, ifIp, rtes);
    }

    public String getIfName() { return ifName; }
    public IpAddres getIfIp() { return ifIp; }
    public MacAddress getIfMac() { return ifMac; }
    public PcapHandle getTxHandle() { return txHandle; }
}

