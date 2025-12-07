package DHCP;

import network.IpAddres;
import network.IpMask;
import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;


public class DhcpServer {

    private final String ifName;
    private final IpAddres poolStart;
    private final IpAddres poolEnd;
    private final IpMask mask;
    private final IpAddres gateway;
    private final DhcpMode mode;

    private final DhcpTx tx;

    private final Map<MacAddress, IpAddres> manualBindings = new ConcurrentHashMap<>();
    private final Map<MacAddress, IpAddres> automaticBindings = new ConcurrentHashMap<>();
    private final Map<MacAddress, Lease> dynamicLeases = new ConcurrentHashMap<>();

    private static final long LEASE_MS = 10_000;
    private static final long MANUAL_LEASE_MS = 86_400_000;

    private final DhcpIpConflictDetector detector;


    private static class Lease {
        private final IpAddres ip;
        private final long expiresAt;

        Lease(IpAddres ip, long expiresAt) {
            this.ip = ip;
            this.expiresAt = expiresAt;
        }

        public IpAddres getIp() {
            return ip;
        }

        public long getExpiresAt() {
            return expiresAt;
        }
    }

    public DhcpServer(String ifName,
                      IpAddres poolStart,
                      IpAddres poolEnd,
                      IpMask mask,
                      IpAddres gateway,
                      DhcpMode mode,
                      DhcpTx tx,
                      DhcpIpConflictDetector detector) {

        this.ifName = ifName;
        this.poolStart = poolStart;
        this.poolEnd = poolEnd;
        this.mask = mask;
        this.gateway = gateway;
        this.mode = mode;
        this.tx = tx;
        this.detector = detector;

    }

    public void handleDhcpPacket(MacAddress mac, IpAddres srcIp, byte[] payload) {

        DhcpMessage msg = DhcpParser.parse(payload);

        int xid = 0;
        if (payload != null && payload.length >= 8) {
            xid =
                    ((payload[4] & 0xFF) << 24) |
                            ((payload[5] & 0xFF) << 16) |
                            ((payload[6] & 0xFF) << 8)  |
                            (payload[7] & 0xFF);
        }

        System.out.println("[DHCP] " + mode + " on " + ifName
                + " type=" + msg.getType() + " xid=" + xid);

        switch (msg.getType()) {
            case DISCOVER -> handleDiscover(mac, xid);
            case REQUEST  -> handleRequest(mac, xid, msg);
            case RELEASE  -> handleRelease(mac);
            default -> {
            }
        }
    }

    private void handleDiscover(MacAddress mac, int xid) {

        IpAddres offer = switch (mode) {
            case MANUAL    -> manualBindings.get(mac);
            case AUTOMATIC -> chooseAutomatic(mac);
            case DYNAMIC   -> chooseDynamic(mac);
        };

        if (offer == null) {
            System.out.println("No IP available for " + mac);
            return;
        }

        System.out.println("OFFER " + offer + " to " + mac);

        long lease = (mode == DhcpMode.MANUAL) ? MANUAL_LEASE_MS : LEASE_MS;

        if (tx != null) {
            tx.sendOffer(ifName, mac, xid, offer, mask, gateway, lease);
        }
    }

    private void handleRequest(MacAddress mac, int xid, DhcpMessage msg) {

        IpAddres requested = msg.getRequestedIp();

        if (requested == null) {
            requested = switch (mode) {
                case MANUAL    -> manualBindings.get(mac);
                case AUTOMATIC -> chooseAutomatic(mac);
                case DYNAMIC   -> chooseDynamic(mac);
            };
        }

        if (requested == null) {
            System.out.println("REQUEST but no IP available");
            return;
        }

        switch (mode) {
            case MANUAL -> {
                IpAddres correct = manualBindings.get(mac);
                if (correct == null || !correct.equals(requested)) {
                    System.out.println("MANUAL: forbidden IP requested: " + requested);
                    return;
                }
            }
            case AUTOMATIC -> {
                automaticBindings.putIfAbsent(mac, requested);
            }
            case DYNAMIC -> {
                dynamicLeases.put(
                        mac,
                        new Lease(requested, System.currentTimeMillis() + LEASE_MS)
                );
            }
        }

        long lease = (mode == DhcpMode.MANUAL) ? MANUAL_LEASE_MS : LEASE_MS;

        System.out.println("ACK " + requested + " to " + mac);
        if (tx != null) {
            tx.sendAck(ifName, mac, xid, requested, mask, gateway, lease);
        }
    }

    private void handleRelease(MacAddress mac) {
        switch (mode) {
            case DYNAMIC -> {
                dynamicLeases.remove(mac);
                System.out.println("RELEASE: removed lease for " + mac);
            }
            case MANUAL, AUTOMATIC -> {
                System.out.println("RELEASE ignored for mode " + mode + " for " + mac);
            }
        }
    }

    private IpAddres chooseAutomatic(MacAddress mac) {
        IpAddres existing = automaticBindings.get(mac);
        if (existing != null) return existing;

        IpAddres free = findFreeIp();
        if (free != null) {
            automaticBindings.put(mac, free);
        }
        return free;
    }

    private IpAddres chooseDynamic(MacAddress mac) {
        long now = System.currentTimeMillis();

        Lease l = dynamicLeases.get(mac);
        if (l != null && l.getExpiresAt() > now) {
            dynamicLeases.put(mac, new Lease(l.getIp(), now + LEASE_MS));
            return l.getIp();
        }

        IpAddres free = findFreeIp();
        if (free != null) {
            dynamicLeases.put(mac, new Lease(free, now + LEASE_MS));
        }
        return free;
    }

    private IpAddres findFreeIp() {

        int s = poolStart.toInt();
        int e = poolEnd.toInt();

        for (int i = s; i <= e; i++) {
            IpAddres ip = new IpAddres(intToStr(i));

            boolean used =
                    manualBindings.containsValue(ip) ||
                            automaticBindings.containsValue(ip) ||
                            dynamicLeases.values().stream()
                                    .anyMatch(l -> l.getIp().equals(ip));

            if (used) continue;

            try {
                boolean busy = detector
                        .probeIp(ifName, ip)
                        .get(20000, TimeUnit.MILLISECONDS);

                if (!busy) {
                    return ip;
                } else {
                    System.out.println("IP " + ip + " is busy according to ARP.");
                }

            } catch (Exception exception) {
                continue;
            }
        }

        return null;
    }

    private String intToStr(int v) {
        int b1 = (v >>> 24) & 0xFF;
        int b2 = (v >>> 16) & 0xFF;
        int b3 = (v >>> 8)  & 0xFF;
        int b4 = v & 0xFF;
        return b1 + "." + b2 + "." + b3 + "." + b4;
    }

    public void addManualIp(MacAddress mac, IpAddres ip) {
        manualBindings.put(mac, ip);
    }

    public void removeManualIp(MacAddress mac) {
        manualBindings.remove(mac);
    }

    public Map<String, String> getManualBindingsAsStrings() {
        return manualBindings.entrySet()
                .stream()
                .collect(Collectors.toMap(
                        e -> e.getKey().toString(),
                        e -> e.getValue().toString()
                ));
    }


    public List<DhcpLeaseInfo> getLeases() {
        List<DhcpLeaseInfo> result = new ArrayList<>();
        long now = System.currentTimeMillis();

        for (var e : manualBindings.entrySet()) {
            String macStr = e.getKey().toString();
            String ipStr  = e.getValue().toString();
            result.add(new DhcpLeaseInfo(
                    ifName,
                    ipStr,
                    macStr,
                    null,
                    DhcpMode.MANUAL
            ));
        }

        for (var e : automaticBindings.entrySet()) {
            String macStr = e.getKey().toString();
            String ipStr  = e.getValue().toString();
            result.add(new DhcpLeaseInfo(
                    ifName,
                    ipStr,
                    macStr,
                    null,
                    DhcpMode.AUTOMATIC
            ));
        }

        for (var e : dynamicLeases.entrySet()) {
            String macStr = e.getKey().toString();
            Lease lease   = e.getValue();
            String ipStr  = lease.getIp().toString();

            long diffMs = lease.getExpiresAt() - now;
            long remainingSec = diffMs <= 0 ? 0 : diffMs / 1000;

            result.add(new DhcpLeaseInfo(
                    ifName,
                    ipStr,
                    macStr,
                    remainingSec,
                    DhcpMode.DYNAMIC
            ));
        }

        return result;
    }

}
