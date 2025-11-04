package rib;

import network.IpAddres;
import routingTable.RouteEntry;

import java.util.List;
import java.util.Optional;

public interface Rib {
    // --- CRUD джерел ---
    void upsertConnected(IpAddres network, int length, String outIf);         // nextHop=null, metric=0, AD=0
    void removeConnected(IpAddres network, int length);

    void upsertStatic(IpAddres network, int length, String outIf, IpAddres nextHop); // AD=1, nextHop може бути null (direct)
    void removeStatic(IpAddres network, int length);

    void upsertRip(RouteEntry ripRoute);                                       // AD=RIP, proto=RIP
    void removeRip(IpAddres network, int length, IpAddres learnedFrom);        // якщо learnedFrom=null — будь-який сусід

    // --- Lookup / View ---
    Optional<RouteEntry> lookup(IpAddres dst);
    List<RouteEntry> snapshot();

    // --- Слухачі змін ---
    void addListener(RibListener l);
    void removeListener(RibListener l);
}
