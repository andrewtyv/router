package dto;

import routingTable.RouteEntry;
import java.util.Objects;

/**
 * DTO для одного запису маршруту у таблиці.
 * Використовується для REST-відповідей (GET /api/routes).
 */
public class RDto {
    private final String destination;   // "10.1.2.0/24"
    private final String outIf;
    private final String nextHop;       // "0.0.0.0" якщо direct/null
    private final int metric;
    private final int adminDistance;
    private final String proto;

    public RDto(String destination,
                    String outIf,
                    String nextHop,
                    int metric,
                    int adminDistance,
                    String proto) {
        this.destination = Objects.requireNonNull(destination, "destination");
        this.outIf = outIf;
        this.nextHop = nextHop;
        this.metric = metric;
        this.adminDistance = adminDistance;
        this.proto = Objects.requireNonNull(proto, "proto");
    }

    /** Побудова DTO із RouteEntry */
    public static RDto from(RouteEntry e) {
        String nh = (e.nextHop() == null) ? "0.0.0.0" : e.nextHop().getIp();
        String destination = e.network().getIp() + "/" + e.length();

        return new RDto(
                destination,
                e.outIf(),
                nh,
                e.metric(),
                e.ad().value,
                e.proto().name()
        );
    }

    public String getDestination() { return destination; }
    public String getOutIf() { return outIf; }
    public String getNextHop() { return nextHop; }
    public int getMetric() { return metric; }
    public int getAdminDistance() { return adminDistance; }
    public String getProto() { return proto; }
}
