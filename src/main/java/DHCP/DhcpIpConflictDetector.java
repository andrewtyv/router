package DHCP;

import ARP.ArpEngine;
import ARP.ArpCache;
import network.IpAddres;
import org.pcap4j.util.MacAddress;

import java.util.Map;
import java.util.concurrent.*;

public class DhcpIpConflictDetector {

    private final ArpEngine arp;
    private final ArpCache cache;

    private final Map<String, CompletableFuture<Boolean>> probes = new ConcurrentHashMap<>();

    public DhcpIpConflictDetector(ArpEngine arp, ArpCache cache) {
        this.arp = arp;
        this.cache = cache;
    }

    private String key(String ifName, IpAddres ip) {
        return ifName + "|" + ip.getIp();
    }

    public CompletableFuture<Boolean> probeIp(String ifName, IpAddres ip) {

        var opt = cache.get(ip);
        if (opt.isPresent()) {
            var e = opt.get();

            if (e.state == ArpCache.State.REACHABLE && e.mac != null) {
                return CompletableFuture.completedFuture(true);   // busy
            }

            if (e.state == ArpCache.State.FAILED) {
                return CompletableFuture.completedFuture(false);  // free
            }

        }

        String k = key(ifName, ip);
        CompletableFuture<Boolean> f = new CompletableFuture<>();
        probes.put(k, f);

        arp.resolve(ifName, ip)
                .whenComplete((mac, err) -> {
                    if (mac != null) {
                        f.complete(true);
                    } else {
                        f.complete(false);
                    }
                    probes.remove(k);
                });

        return f;
    }


    public void onArpSeen(String ifName, IpAddres ip, MacAddress mac) {

        String k = key(ifName, ip);

        var f = probes.get(k);
        if (f != null) {
            f.complete(true);
            probes.remove(k);
        }
    }
}
