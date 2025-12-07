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

    public static List<byte[]> buildRipResponsePayloads(List<RipRte> routes){
        List<byte[]> out = new ArrayList<>();
        final int MAX_RTE = 25;

        for (int i = 0; i < routes.size(); i += MAX_RTE) {
            int end = Math.min(i + MAX_RTE, routes.size());
            List<RipRte> chunk = routes.subList(i, end);

            int size = 4 + chunk.size() * 20;
            ByteBuffer bb = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);

            bb.put(CMD_RESPONSE);
            bb.put(VERSION_2);
            bb.putShort((short)0);

            for (RipRte r : chunk) {
                bb.putShort((short)2);
                bb.putShort((short)0);
                bb.putInt(r.dest.networkAddress(r.prefixLen).toInt());
                bb.putInt(prefixMaskInt(r.prefixLen));
                bb.putInt(r.nextHop == null ? 0 : r.nextHop.toInt());
                bb.putInt(r.metric);
            }
            out.add(bb.array());
        }
        return out;
    }

    public static int prefixMaskInt(int len){
        if (len < 0 || len > 32) throw new IllegalArgumentException("prefix 0..32");
        return len == 0 ? 0 : (int)(0xFFFFFFFFL << (32 - len));
    }

    public static final class RipRte {
        public final IpAddres dest;
        public final int      prefixLen;
        public final IpAddres nextHop;
        public final int      metric;

        public RipRte(IpAddres dest, int prefixLen, IpAddres nextHop, int metric) {
            this.dest = dest;
            this.prefixLen = prefixLen;
            this.nextHop = nextHop;
            this.metric = metric;
        }
    }
}
