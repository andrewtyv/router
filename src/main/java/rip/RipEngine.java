package rip;

import network.IpAddres;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.util.MacAddress;
import org.springframework.beans.factory.annotation.Autowired;
import ports.TxSender;
import rib.Rib;
import routingTable.AdminDistance;
import routingTable.Proto;
import routingTable.RouteEntry;
import rib.RibListener;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;

public class RipEngine implements RibListener {

    private final Rib rib;
    private final ScheduledExecutorService ses = Executors.newScheduledThreadPool(1);
    private final Map<String, RipInterface> ifaces = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> triggerCooldownMs = new ConcurrentHashMap<>();

    private static final long ROUTE_TIMEOUT_MS = 180_000L;
    private static final long GC_INTERVAL_MS = 240_000L;
    private final ConcurrentMap<RipRouteKey,Long> lastSeenMs = new ConcurrentHashMap<>();
    private final TxSender txSender;

    public RipEngine(Rib rib,TxSender txSender) {
        ses.scheduleAtFixedRate(this::ageRipRoutes, 5,  5, TimeUnit.SECONDS);
        this.rib = Objects.requireNonNull(rib);
        rib.addListener(this);
        this.txSender = txSender;
    }

    public void enableOnInterface(String ifName,
                                  MacAddress ifMac,
                                  IpAddres ifIp ){

        RipInterface rif = new RipInterface(ifName, ifMac, ifIp,txSender, rib);
        ifaces.put(ifName, rif);

        try { rif.sendPeriodicUpdate(); } catch (Exception ignored) {}

        ses.scheduleAtFixedRate(() -> {
            try {
                rif.sendPeriodicUpdate();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    public void disableOnInterface(String ifName) {

        RipInterface rif = ifaces.remove(ifName);
        if (rif != null) {
            try {
                rif.sendPoisonUpdate();
            } catch (Exception e) {
                System.err.println("RIP poison update failed on " + ifName + ": " + e.getMessage());
            }
        }
    }


    public void triggerUpdate(String ifName) {
        RipInterface rif = ifaces.get(ifName);
        if (rif == null) return;

        long now = System.currentTimeMillis();
        long nextAllowed = triggerCooldownMs.getOrDefault(ifName, 0L);
        if (now < nextAllowed) return;

        triggerCooldownMs.put(ifName, now + 1000);
        try { rif.sendPeriodicUpdate(); } catch (Exception e) { /* TODO лог */ }
    }

    public void onRipPacket(String inIfName, IpAddres srcIp, byte[] udpPayload) {
        RipInterface rif = ifaces.get(inIfName);
        if (rif == null) {
            System.out.println("here null ");
            return;
        }
        try {
            RipParser.RipMessage msg = RipParser.parse(udpPayload);
            System.out.println("RIP packet on " + inIfName + " from " + srcIp
                    + " isRequest=" + msg.isRequest()
                    + " isResponse=" + msg.isResponse()
                    + " rtes=" + msg.getRtes().size());

            if (msg.isRequest()) {
                if (rif != null) {
                    try { rif.sendPeriodicUpdate(); } catch (Exception e) {e.printStackTrace();}
                }
                return;
            }
            if (!msg.isResponse()) return;

            for (RipParser.Rte rte : msg.getRtes()) {
                IpAddres prefixNet = rte.getPrefixNetwork();
                int      prefixLen = rte.getPrefixLen();
                IpAddres nextHop   = rte.getNextHop();
                int      metric    = rte.getMetric();

                if (nextHop == null) nextHop = srcIp;

                int newMetric = Math.min(16, metric + 1);

                if (newMetric >= 16) {
                    rib.removeRip(prefixNet, prefixLen, srcIp);
                    RipRouteKey key = new RipRouteKey(prefixNet, prefixLen, srcIp);
                    lastSeenMs.remove(key);
                    continue;
                }

                IpAddres normalized = prefixNet.networkAddress(prefixLen);
                rib.upsertRip(
                        RouteEntry.builder()
                                .network(normalized)
                                .length(prefixLen)
                                .outIf(inIfName)
                                .nextHop(nextHop)
                                .metric(newMetric)
                                .ad(AdminDistance.RIP)
                                .proto(Proto.RIP)
                                .learnedFrom(srcIp)
                                .build()
                );
                RipRouteKey key = new RipRouteKey(normalized, prefixLen, srcIp);
                lastSeenMs.put(key, System.currentTimeMillis());
            }

            triggerUpdate(inIfName);

        } catch (Exception e) {
            System.err.println("RIP parse error on " + inIfName + ": " + e.getMessage());
        }
    }
    @Override
    public void onRouteChange(RouteChangeEvent evt) {
        if (!shouldTriggerOn(evt)) {
            return;
        }

        for (String ifName : ifaces.keySet()) {
            triggerUpdate(ifName);
        }
    }

    private boolean shouldTriggerOn(RouteChangeEvent evt) {
        return evt.getAddedOrUpdated().stream().anyMatch(this::isExportableByRip)
                || evt.getRemoved().stream().anyMatch(this::isExportableByRip);
    }

    private boolean isExportableByRip(RouteEntry e) {
        Proto p = e.proto();
        return p == Proto.CONNECTED || p == Proto.STATIC || p == Proto.RIP;
    }

    private void ageRipRoutes() {
        long now = System.currentTimeMillis();

        for (var entry : lastSeenMs.entrySet()) {
            RipRouteKey key = entry.getKey();
            long last = entry.getValue();
            long age = now - last;

            if (age >= ROUTE_TIMEOUT_MS + GC_INTERVAL_MS) {
                try {
                    rib.removeRip(key.network, key.prefixLen, key.learnedFrom);
                } catch (Exception ignored) {}
                lastSeenMs.remove(key);
            }
            else if (age >= ROUTE_TIMEOUT_MS) {
                poisonRoute(key);
            }
        }
    }

    private void poisonRoute(RipRouteKey key) {
        try {
            var snapshot = rib.snapshot();
            for (RouteEntry e : snapshot) {
                if (e.proto() != Proto.RIP) continue;
                if (!e.network().equals(key.network)) continue;
                if (e.length() != key.prefixLen) continue;
                if (!e.learnedFrom().equals(key.learnedFrom)) continue;

                if (e.metric() >= 16) {
                    return;
                }

                RouteEntry poisoned = RouteEntry.builder()
                        .network(e.network())
                        .length(e.length())
                        .outIf(e.outIf())
                        .nextHop(e.nextHop())
                        .metric(16)
                        .ad(e.ad())
                        .proto(e.proto())
                        .learnedFrom(e.learnedFrom())
                        .build();

                rib.upsertRip(poisoned);
                return;
            }
        } catch (Exception ignored) { }
    }


    private static final class RipRouteKey {
        final IpAddres network;
        final int prefixLen;
        final IpAddres learnedFrom;

        RipRouteKey(IpAddres network, int prefixLen, IpAddres learnedFrom) {
            this.network = network;
            this.prefixLen = prefixLen;
            this.learnedFrom = learnedFrom;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof RipRouteKey other)) return false;
            return prefixLen == other.prefixLen
                    && network.equals(other.network)
                    && learnedFrom.equals(other.learnedFrom);
        }

        @Override
        public int hashCode() {
            int result = network.hashCode();
            result = 31 * result + Integer.hashCode(prefixLen);
            result = 31 * result + learnedFrom.hashCode();
            return result;
        }
    }


}
