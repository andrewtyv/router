package rip;

import network.IpAddres;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

public final class RipV2 {
    private RipV2(){}

    public static final byte CMD_RESPONSE = 2;
    public static final byte VERSION_2 = 2;

    /** Повертає список RIP-пейлоадів (по 1 .. N), кожен містить до 25 RTE. */
    public static List<byte[]> buildRipResponsePayloads(List<RipRte> routes){
        List<byte[]> out = new ArrayList<>();
        final int MAX_RTE = 25;

        for (int i = 0; i < routes.size(); i += MAX_RTE) {
            int end = Math.min(i + MAX_RTE, routes.size());
            List<RipRte> chunk = routes.subList(i, end);

            int size = 4 + chunk.size() * 20; // header(4) + RTE(20*count)
            ByteBuffer bb = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);

            // RIP header: cmd=2(response), ver=2, zero=0
            bb.put(CMD_RESPONSE);
            bb.put(VERSION_2);
            bb.putShort((short)0);

            // RTEs
            for (RipRte r : chunk) {
                // AFI = 2 для IPv4 (network)
                bb.putShort((short)2);
                // Route Tag = 0 (за замовч.)
                bb.putShort((short)0);
                // IPv4 address
                bb.putInt(r.dest.networkAddress(r.prefixLen).toInt());
                // Subnet mask з /prefixLen
                bb.putInt(prefixMaskInt(r.prefixLen));
                // Next Hop (0.0.0.0 якщо null)
                bb.putInt(r.nextHop == null ? 0 : r.nextHop.toInt());
                // Metric (1..16), у Cisco-сумісних апдейтах 16 == unreachable
                bb.putInt(r.metric);
            }
            out.add(bb.array());
        }
        return out;
    }

    /** /len -> 32-бітна маска в мережевому порядку (BIG_ENDIAN). */
    public static int prefixMaskInt(int len){
        if (len < 0 || len > 32) throw new IllegalArgumentException("prefix 0..32");
        return len == 0 ? 0 : (int)(0xFFFFFFFFL << (32 - len));
    }

    /** Зручний контейнер для одного RTE. */
    public static final class RipRte {
        public final IpAddres dest;       // будь-яка адреса з префіксу
        public final int      prefixLen;  // 0..32
        public final IpAddres nextHop;    // null => 0.0.0.0
        public final int      metric;     // 1..16

        public RipRte(IpAddres dest, int prefixLen, IpAddres nextHop, int metric) {
            this.dest = dest;
            this.prefixLen = prefixLen;
            this.nextHop = nextHop;
            this.metric = metric;
        }
    }
}
