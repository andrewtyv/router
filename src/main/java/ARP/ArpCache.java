package ARP;

import network.IpAddres;
import org.pcap4j.util.MacAddress;

import java.util.*;
import java.util.concurrent.*;

public class ArpCache {

    public enum State { INCOMPLETE, REACHABLE, STALE, FAILED }

    public static final class ArpEntry {
        public final IpAddres ip;
        public volatile MacAddress mac;
        public volatile State state;
        public volatile long updatedMillis;

        ArpEntry(IpAddres ip, State st) {
            this.ip = ip; this.state = st;
            this.updatedMillis = System.currentTimeMillis();
        }
        public long ageSeconds() { return (System.currentTimeMillis() - updatedMillis) / 1000; }
    }

    public static final class ArpRow {
        public final String ip, mac, state;
        public final long ageSec;
        public ArpRow(ArpEntry e) {
            this.ip = e.ip.getIp();
            this.mac = e.mac == null ? "" : e.mac.toString();
            this.state = e.state.name();
            this.ageSec = e.ageSeconds();
        }
    }

    private final ConcurrentHashMap<IpAddres, ArpEntry> table = new ConcurrentHashMap<>();
    private final ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "arp-aging"); t.setDaemon(true); return t;
    });

    private final int REACHABLE_TO_STALE_SEC = 60;
    private final int STALE_EVICT_SEC = 120;

    public ArpCache() {
        ses.scheduleAtFixedRate(this::ageSweep, 1, 1, TimeUnit.SECONDS);
    }

    private void ageSweep() {
        long now = System.currentTimeMillis();
        for (ArpEntry e : table.values()) {
            long sec = (now - e.updatedMillis) / 1000;
            if (e.state == State.REACHABLE && sec > REACHABLE_TO_STALE_SEC) {
                e.state = State.STALE;
            } else if (e.state == State.STALE && sec > STALE_EVICT_SEC) {
                table.remove(e.ip);
            }
        }
    }

    public void learned(IpAddres ip, MacAddress mac) {
        ArpEntry e = table.computeIfAbsent(ip, k -> new ArpEntry(k, State.INCOMPLETE));
        e.mac = mac;
        e.state = State.REACHABLE;
        e.updatedMillis = System.currentTimeMillis();
    }

    public ArpEntry beginResolve(IpAddres ip) {
        return table.compute(ip, (k, v) -> {
            if (v == null) return new ArpEntry(k, State.INCOMPLETE);
            if (v.state == State.FAILED) v.state = State.INCOMPLETE;
            v.updatedMillis = System.currentTimeMillis();
            return v;
        });
    }

    public Optional<ArpEntry> get(IpAddres ip) {
        ArpEntry e = table.get(ip);
        return Optional.ofNullable(e);
    }

    public void markFailed(IpAddres ip) {
        ArpEntry e = table.get(ip);
        if (e != null) { e.state = State.FAILED; e.updatedMillis = System.currentTimeMillis(); }
    }

    public void remove(IpAddres ip) { table.remove(ip); }

    public List<ArpRow> snapshot() {
        List<ArpRow> out = new ArrayList<>();
        for (ArpEntry e : table.values()) out.add(new ArpRow(e));
        out.sort(Comparator.comparing(r -> r.ip));
        return out;
    }

    public void shutdown() { ses.shutdownNow(); }
}
