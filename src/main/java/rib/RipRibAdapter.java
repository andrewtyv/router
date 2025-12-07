package rib;

import network.IpAddres;
import rib.Rib;
import rip.RipV2;
import routingTable.Proto;
import routingTable.RouteEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class RipRibAdapter {
    private RipRibAdapter(){}

    public static List<RipV2.RipRte> buildRtesForInterface(Rib rib, String outIfName, boolean poisonReverse) {

        var snapshot = rib.snapshot();
        List<RipV2.RipRte> out = new ArrayList<>(snapshot.size());

        for (RouteEntry e : snapshot) {
            if (e.proto() == Proto.STATIC) {
                continue;
            }

            boolean learnedOnThisIf = Objects.equals(e.outIf(), outIfName);
            int advMetric = e.metric();
            if (learnedOnThisIf) {
                if (!poisonReverse) {
                    continue;
                } else {
                    advMetric = 16;
                }
            }

            IpAddres network = e.network();
            int prefixLen    = e.length();

            IpAddres nextHop = e.nextHop() == null ? null : e.nextHop();

            int rteMetric = Math.min(Math.max(advMetric == 0 ? 1 : advMetric, 1), 16);

            out.add(new RipV2.RipRte(network, prefixLen, nextHop, rteMetric));
        }
        return out;
    }
}
