package rip;

import network.IpAddres;
import rib.Rib;
import routingTable.Proto;
import routingTable.RouteEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class RipRibAdapter {
    private RipRibAdapter(){}

    /**
     * Формує список RIPv2 RTE для конкретного вихідного інтерфейсу.
     * - Рекламуємо CONNECTED і RIP (STATIC за замовчуванням пропускаємо).
     * - split-horizon / poison-reverse за прапорцем.
     * - Метрика в RTE: 1..16 (0 мапимо в 1).
     */
    public static List<RipV2.RipRte> buildRtesForInterface(
            Rib rib, String outIfName, boolean poisonReverse) {

        var snapshot = rib.snapshot();
        List<RipV2.RipRte> out = new ArrayList<>(snapshot.size());

        for (RouteEntry e : snapshot) {
            // рекламувати лише потрібні джерела
            if (e.proto() == Proto.STATIC) {
                // якщо треба також статичні — прибери continue
                continue;
            }

            // split-horizon / poison-reverse
            boolean learnedOnThisIf = Objects.equals(e.outIf(), outIfName);
            int advMetric = e.metric();
            if (learnedOnThisIf) {
                if (!poisonReverse) {
                    // split-horizon: не рекламуємо назад у той самий інтерфейс
                    continue;
                } else {
                    // poison-reverse: рекламуємо з метрикою 16
                    advMetric = 16;
                }
            }

            // мережа та префікс із RouteEntry (без IpPrefix)
            IpAddres network = e.network();     // вже нормалізована мережева адреса
            int prefixLen    = e.length();

            // next-hop у RIP RTE: 0.0.0.0, якщо null
            IpAddres nextHop = e.nextHop() == null ? null : e.nextHop();

            // RIP-метрика в RTE має бути 1..16 (0 зарезервовано → мапимо в 1)
            int rteMetric = Math.min(Math.max(advMetric == 0 ? 1 : advMetric, 1), 16);

            out.add(new RipV2.RipRte(network, prefixLen, nextHop, rteMetric));
        }
        return out;
    }
}
