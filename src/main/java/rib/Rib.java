package rib;

import network.IpAddres;
import routingTable.RouteEntry;

import java.util.List;
import java.util.Optional;

public interface Rib {
    void upsertConnected(IpAddres network, int length, String outIf);
    void removeConnected(IpAddres network, int length);

    void upsertStatic(IpAddres network, int length, String outIf, IpAddres nextHop);
    void removeStatic(IpAddres network, int length);

    void upsertRip(RouteEntry ripRoute);
    void removeRip(IpAddres network, int length, IpAddres learnedFrom);

    Optional<RouteEntry> lookup(IpAddres dst);
    List<RouteEntry> snapshot();

    void addListener(RibListener l);
    void removeListener(RibListener l);
}
