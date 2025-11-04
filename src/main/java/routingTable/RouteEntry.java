package routingTable;

import network.IpAddres;
import java.util.Objects;

/**
 * Один запис маршруту в таблиці (RIB).
 * Тепер замість IpPrefix використовує пару (IpAddres network + int length).
 */
public final class RouteEntry {

    private final IpAddres network;    // мережа (нормалізована)
    private final int length;          // префікс /CIDR 0..32
    private final String outIf;        // інтерфейс виходу
    private final IpAddres nextHop;    // null => direct (0.0.0.0)
    private final int metric;          // 0 - CONNECTED/STATIC; 1..16 - RIP
    private final AdminDistance ad;    // адміністративна дистанція
    private final Proto proto;         // джерело маршруту
    private final IpAddres learnedFrom; // лише для RIP; інакше null

    private RouteEntry(Builder b) {
        this.network = Objects.requireNonNull(b.network);
        this.length = b.length;
        this.outIf = b.outIf;
        this.nextHop = b.nextHop;
        this.metric = b.metric;
        this.ad = Objects.requireNonNull(b.ad);
        this.proto = Objects.requireNonNull(b.proto);
        this.learnedFrom = b.learnedFrom;
    }

    public IpAddres network() { return network; }
    public int length() { return length; }
    public String outIf() { return outIf; }
    public IpAddres nextHop() { return nextHop; }
    public int metric() { return metric; }
    public AdminDistance ad() { return ad; }
    public Proto proto() { return proto; }
    public IpAddres learnedFrom() { return learnedFrom; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private IpAddres network;
        private int length;
        private String outIf;
        private IpAddres nextHop;
        private int metric;
        private AdminDistance ad;
        private Proto proto;
        private IpAddres learnedFrom;

        public Builder network(IpAddres n) { this.network = n; return this; }
        public Builder length(int len) { this.length = len; return this; }
        public Builder outIf(String of) { this.outIf = of; return this; }
        public Builder nextHop(IpAddres nh) { this.nextHop = nh; return this; }
        public Builder metric(int m) { this.metric = m; return this; }
        public Builder ad(AdminDistance a) { this.ad = a; return this; }
        public Builder proto(Proto p) { this.proto = p; return this; }
        public Builder learnedFrom(IpAddres lf) { this.learnedFrom = lf; return this; }

        public RouteEntry build() {
            if (network == null) throw new IllegalArgumentException("network == null");
            if (length < 0 || length > 32) throw new IllegalArgumentException("prefix length 0..32");
            return new RouteEntry(this);
        }
    }

    @Override
    public String toString() {
        String nh = (nextHop == null ? "0.0.0.0" : nextHop.getIp());
        return network.getIp() + "/" + length
                + " | " + (outIf == null ? "-" : outIf)
                + " | nextHop=" + nh
                + " | metric=" + metric
                + " | AD=" + ad.value
                + " | " + proto;
    }
}
