package ports;

import org.pcap4j.core.*;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;


public class IfBindingManager {

    private static final Logger log = LoggerFactory.getLogger(IfBindingManager.class);

    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT_MS = 10;
    private final LinkStatusWatcher watcher;

    private final ConcurrentHashMap<String, Binding> bindings = new ConcurrentHashMap<>();

    public IfBindingManager(LinkStatusWatcher watcher) {

        this.watcher = Objects.requireNonNull(watcher, "watcher");
    }

    private static final class Binding {
        final String ifName;
        final String nicName;
        final PcapNetworkInterface nif;
        final MacAddress mac;
        final PcapHandle handle;

        Binding(String ifName, String nicName, PcapNetworkInterface nif, MacAddress mac, PcapHandle handle) {
            this.ifName = ifName;
            this.nicName = nicName;
            this.nif = nif;
            this.mac = mac;
            this.handle = handle;
        }
    }

    //NOT USE!!!!!
    private static boolean isAllowedEn(String nicName) {
        /*if (nicName == null || !nicName.startsWith("en")) return false;
        try {
            int n = Integer.parseInt(nicName.substring(2));
            return n > 0;
        } catch (NumberFormatException e) {
            return false;
        }
        */
        return true; 
    }


    public synchronized void bind(String ifName, String nicName) throws Exception {
        Objects.requireNonNull(ifName, "ifName");
        Objects.requireNonNull(nicName, "nicName");

        if (!isAllowedEn(nicName)) {
            throw new IllegalStateException("NIC not allowed by policy (need enN, N>6): " + nicName);
        }
        if (!watcher.isActive(nicName)) {
            throw new IllegalStateException("NIC " + nicName + " is not active (no carrier) — refusing bind");
        }

        unbind(ifName);

        PcapNetworkInterface nif = Pcaps.getDevByName(nicName);
        if (nif == null) {
            throw new IllegalArgumentException("NIC not found: " + nicName);
        }
        if (nif.getLinkLayerAddresses().isEmpty()) {
            throw new IllegalStateException("NIC has no MAC address: " + nicName);
        }

        PcapHandle handle = nif.openLive(
                SNAPLEN,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                TIMEOUT_MS
        );

        MacAddress mac = (MacAddress) nif.getLinkLayerAddresses().get(0);
        String bpf =
                "arp or " +
                        // RIP v2 multicast 224.0.0.9
                        "dst host 224.0.0.9 or " +
                        // DHCP broadcast/unicast
                        "(udp port 67 or udp port 68) or " +
                        // інший трафік до нашого MAC
                        "(ip and ether dst " + mac + ")";
        handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);

        bindings.put(ifName, new Binding(ifName, nicName, nif, mac, handle));
        log.info("Bound {} -> {} (MAC={}, filter='{}')", ifName, nicName, mac, bpf);
    }

    public synchronized void unbind(String ifName) {
        Binding b = bindings.remove(ifName);
        if (b == null) return;

        try {

            b.handle.breakLoop();
        } catch (Throwable ignored) {
        }
        try {
            b.handle.close();
        } catch (Throwable ignored) {
        }
        log.info("Unbound {} (was {})", ifName, b.nicName);
    }

    public PcapHandle getHandle(String ifName) {
        Binding b = bindings.get(ifName);
        return b == null ? null : b.handle;
    }

    public MacAddress getMac(String ifName) {
        Binding b = bindings.get(ifName);
        return b == null ? null : b.mac;
    }

    public String getNicName(String ifName) {
        Binding b = bindings.get(ifName);
        return b == null ? null : b.nicName;
    }

    public void setFilter(String ifName, String bpf){
        try {
            Binding b = bindings.get(ifName);
            if (b == null) throw new IllegalStateException("Not bound: " + ifName);
            b.handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
            log.info("Updated BPF for {} -> {}", ifName, bpf);
        }
        catch (Exception e  ) {
            e.printStackTrace();
        }
    }
}

