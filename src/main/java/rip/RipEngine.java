package rip;

import network.IpAddres;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.util.MacAddress;
import rib.Rib;
import routingTable.AdminDistance;
import routingTable.Proto;
import routingTable.RouteEntry;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;

public class RipEngine {

    private final Rib rib;
    private final ScheduledExecutorService ses = Executors.newScheduledThreadPool(1);
    private final Map<String, RipInterface> ifaces = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> triggerCooldownMs = new ConcurrentHashMap<>();

    public RipEngine(Rib rib) {
        this.rib = Objects.requireNonNull(rib);
    }

    /** Увімкнути RIP на інтерфейсі */
    public void enableOnInterface(String ifName,
                                  MacAddress ifMac,
                                  IpAddres ifIp,
                                  PcapHandle txHandle) {
        RipInterface rif = new RipInterface(ifName, ifMac, ifIp, txHandle, rib);
        ifaces.put(ifName, rif);

        try { rif.sendPeriodicUpdate(); } catch (Exception ignored) {}

        ses.scheduleAtFixedRate(() -> {
            try { rif.sendPeriodicUpdate(); } catch (Exception e) { /* TODO лог */ }
        }, 30, 30, TimeUnit.SECONDS);
    }

    /** Вимкнути RIP на інтерфейсі */
    public void disableOnInterface(String ifName) {
        RipInterface rif = ifaces.remove(ifName);
        if (rif != null) {
            // TODO: rif.sendPoisonUpdate();
            // TODO: закрити handle, якщо відкривався тут
        }
    }

    /** Тригерний апдейт (rate-limit 1s/IF) */
    public void triggerUpdate(String ifName) {
        RipInterface rif = ifaces.get(ifName);
        if (rif == null) return;

        long now = System.currentTimeMillis();
        long nextAllowed = triggerCooldownMs.getOrDefault(ifName, 0L);
        if (now < nextAllowed) return;

        triggerCooldownMs.put(ifName, now + 1000);
        try { rif.sendPeriodicUpdate(); } catch (Exception e) { /* TODO лог */ }
    }

    /** Вхід RIP-пакета з Demux/Rx */
    public void onRipPacket(String inIfName, IpAddres srcIp, byte[] udpPayload) {
        try {
            RipParser.RipMessage msg = RipParser.parse(udpPayload);

            if (msg.isRequest()) {
                RipInterface rif = ifaces.get(inIfName);
                if (rif != null) {
                    try { rif.sendPeriodicUpdate(); } catch (Exception ignored) {}
                }
                return;
            }
            if (!msg.isResponse()) return;

            for (RipParser.Rte rte : msg.getRtes()) {
                IpAddres prefixNet = rte.getPrefixNetwork();   // вже нормалізована мережа
                int      prefixLen = rte.getPrefixLen();
                IpAddres nextHop   = rte.getNextHop();
                int      metric    = rte.getMetric();

                // nextHop 0.0.0.0 → srcIp
                if (nextHop == null) nextHop = srcIp;

                // +1 до метрики, обмеження 16
                int newMetric = Math.min(16, metric + 1);

                if (newMetric >= 16) {
                    // unreachable → прибрати з RIB (learnedFrom = сусід)
                    rib.removeRip(prefixNet, prefixLen, srcIp);
                    continue;
                }

                // Оновити/додати у RIB (нормалізуємо мережу на всяк випадок)
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
            }

            triggerUpdate(inIfName);

        } catch (Exception e) {
            System.err.println("RIP parse error on " + inIfName + ": " + e.getMessage());
        }
    }


}
