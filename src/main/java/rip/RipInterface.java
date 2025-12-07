package rip;

import network.IpAddres;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.util.MacAddress;
import ports.RipTx;
import ports.TxSender;
import rib.Rib;
import rib.RipRibAdapter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;

public class RipInterface {

    private final String ifName;
    private final MacAddress ifMac;
    private final IpAddres ifIp;
    private final Rib rib;
    private final TxSender txSender;

    public RipInterface(String ifName,
                        MacAddress ifMac,
                        IpAddres ifIp,
                        TxSender txSender,
                        Rib rib) {
        this.ifName = ifName;
        this.ifMac = ifMac;
        this.ifIp = ifIp;
        this.rib = rib;
        this.txSender = txSender;
    }


    public void sendPeriodicUpdate() throws Exception {
        boolean poisonReverse = true;
        var rtes = RipRibAdapter.buildRtesForInterface(rib, ifName, poisonReverse);

        if (rtes.isEmpty()) {
            return;
        }


        RipTx.sendRipResponse(txSender, ifMac, ifIp,ifName, rtes);
    }


    public void sendPoisonUpdate() throws Exception {

        var base = RipRibAdapter.buildRtesForInterface(rib, ifName, false);

        if (base.isEmpty()) {
            System.out.println("base is empty \n");
            return;
        }

        List<RipV2.RipRte> poisoned = new ArrayList<>(base.size());
        for (RipV2.RipRte r : base) {
            poisoned.add(new RipV2.RipRte(
                    r.dest,
                    r.prefixLen,
                    r.nextHop,
                    16
            ));
        }

        RipTx.sendRipResponse(txSender, ifMac, ifIp,ifName, poisoned);
    }
    public String getIfName() { return ifName; }
    public IpAddres getIfIp() { return ifIp; }
    public MacAddress getIfMac() { return ifMac; }
}

