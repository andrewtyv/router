package rib;

import network.IpAddres;
import rip.RouteChangeEvent;
import routingTable.AdminDistance;
import routingTable.Proto;
import routingTable.RouteEntry;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;


public final class InMemoryRib implements Rib {

    private static final class Key implements Comparable<Key> {
        final IpAddres network;  // нормалізована мережева адреса
        final int length;        // 0..32
        Key(IpAddres anyAddressInPrefix, int length) {
            if (length < 0 || length > 32) throw new IllegalArgumentException("Bad prefix len");
            this.network = Objects.requireNonNull(anyAddressInPrefix).networkAddress(length);
            this.length = length;
        }
        @Override public int compareTo(Key o) {
            int byLen = Integer.compare(o.length, this.length); // DESC
            if (byLen != 0) return byLen;
            return Integer.compareUnsigned(this.network.toInt(), o.network.toInt()); // ASC
        }
        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Key k)) return false;
            return this.length == k.length && this.network.equals(k.network);
        }
        @Override public int hashCode() { return Objects.hash(network, length); }
        @Override public String toString(){ return network.getIp() + "/" + length; }
    }

    private final NavigableMap<Key, RouteEntry> connected = new TreeMap<>();
    private final NavigableMap<Key, RouteEntry> statics   = new TreeMap<>();
    private final NavigableMap<Key, RouteEntry> rip       = new TreeMap<>();

    private final List<RibListener> listeners = new CopyOnWriteArrayList<>();
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();


    @Override
    public void upsertConnected(IpAddres network, int length, String outIf) {
        var re = RouteEntry.builder()
                .network(network.networkAddress(length))
                .length(length)
                .outIf(outIf)
                .nextHop(null)
                .metric(0)
                .ad(AdminDistance.CONNECTED)
                .proto(Proto.CONNECTED)
                .build();
        put(connected, re);
    }

    @Override
    public void removeConnected(IpAddres network, int length) {
        remove(connected, new Key(network, length));
    }

    @Override
    public void upsertStatic(IpAddres network, int length, String outIf, IpAddres nextHop) {
        var re = RouteEntry.builder()
                .network(network.networkAddress(length))
                .length(length)
                .outIf(outIf)
                .nextHop(nextHop)
                .metric(0)
                .ad(AdminDistance.STATIC)
                .proto(Proto.STATIC)
                .build();
        put(statics, re);
    }

    @Override
    public void removeStatic(IpAddres network, int length) {
        remove(statics, new Key(network, length));
    }

    @Override
    public void upsertRip(RouteEntry r) {
        if (r.ad() != AdminDistance.RIP || r.proto() != Proto.RIP)
            throw new IllegalArgumentException("RIP route must have AD=RIP and proto=RIP");
        // нормалізуємо мережу, щоб key співпадав
        var norm = r.network().networkAddress(r.length());
        var fixed = RouteEntry.builder()
                .network(norm)
                .length(r.length())
                .outIf(r.outIf())
                .nextHop(r.nextHop())
                .metric(r.metric())
                .ad(r.ad())
                .proto(r.proto())
                .learnedFrom(r.learnedFrom())
                .build();
        put(rip, fixed);
    }

    @Override
    public void removeRip(IpAddres network, int length, IpAddres learnedFrom) {
        rw.writeLock().lock();
        try {
            Key k = new Key(network, length);
            RouteEntry curr = rip.get(k);
            if (curr != null && (learnedFrom == null ||
                    Objects.equals(curr.learnedFrom(), learnedFrom))) {
                rip.remove(k);
                fire(Collections.emptyList(), List.of(curr));
            }
        } finally {
            rw.writeLock().unlock();
        }
    }


    @Override
    public Optional<RouteEntry> lookup(IpAddres dst) {
        rw.readLock().lock();
        try {
            List<RouteEntry> matches = new ArrayList<>(4);
            collectMatches(connected, dst, matches);
            collectMatches(statics, dst, matches);
            collectMatches(rip, dst, matches);
            if (matches.isEmpty()) return Optional.empty();

            int bestLen = matches.stream().mapToInt(RouteEntry::length).max().orElse(0);
            List<RouteEntry> sameLen = matches.stream()
                    .filter(e -> e.length() == bestLen).collect(Collectors.toList());

            int bestAd = sameLen.stream().mapToInt(e -> e.ad().value).min().orElse(Integer.MAX_VALUE);
            List<RouteEntry> sameAd = sameLen.stream()
                    .filter(e -> e.ad().value == bestAd).collect(Collectors.toList());

            return sameAd.stream().min(Comparator.comparingInt(RouteEntry::metric));
        } finally {
            rw.readLock().unlock();
        }
    }

    @Override
    public List<RouteEntry> snapshot() {
        rw.readLock().lock();
        try {
            ArrayList<RouteEntry> all = new ArrayList<>(connected.size()+statics.size()+rip.size());
            all.addAll(connected.values());
            all.addAll(statics.values());
            all.addAll(rip.values());
            all.sort(Comparator
                    .<RouteEntry>comparingInt(e -> -e.length())     // LPM спочатку
                    .thenComparing(e -> e.network())                // далі за адресою
                    .thenComparingInt(e -> e.ad().value));          // далі за AD
            return all;
        } finally {
            rw.readLock().unlock();
        }
    }

    @Override public void addListener(RibListener l){ listeners.add(l); }
    @Override public void removeListener(RibListener l){ listeners.remove(l); }

    // ---------------- helpers ----------------

    private void put(NavigableMap<Key, RouteEntry> table, RouteEntry re){
        rw.writeLock().lock();
        try {
            Key k = new Key(re.network(), re.length());
            RouteEntry prev = table.put(k, re);
            fire(List.of(re), prev == null ? List.of() : List.of());
        } finally {
            rw.writeLock().unlock();
        }
    }

    private void remove(NavigableMap<Key, RouteEntry> table, Key k){
        rw.writeLock().lock();
        try {
            RouteEntry prev = table.remove(k);
            if (prev != null) fire(List.of(), List.of(prev));
        } finally {
            rw.writeLock().unlock();
        }
    }

    private static void collectMatches(NavigableMap<Key, RouteEntry> t, IpAddres ip, List<RouteEntry> out){
        for (var e : t.entrySet()){
            Key k = e.getKey();
            if (ip.inSubnet(k.network, k.length)) out.add(e.getValue());
        }
    }

    private void fire(List<RouteEntry> addedOrUpdated, List<RouteEntry> removed){
        if (listeners.isEmpty()) return;
        var evt = new RouteChangeEvent(addedOrUpdated, removed);
        for (var l : listeners) {
            try { l.onRouteChange(evt); } catch (Throwable ignored) {}
        }
    }
}
