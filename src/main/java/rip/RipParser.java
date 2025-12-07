package rip;

import network.IpAddres;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;


public final class RipParser {

    public static final byte CMD_REQUEST  = 1;
    public static final byte CMD_RESPONSE = 2;
    public static final byte VERSION_2    = 2;

    private RipParser(){}

    public static RipMessage parse(byte[] payload) {
        if (payload == null || payload.length < 4) {
            throw new IllegalArgumentException("RIP payload too short: len=" + (payload == null ? -1 : payload.length));
        }

        int pos = 0;

        int cmdInt = payload[pos++] & 0xFF;
        int verInt = payload[pos++] & 0xFF;
        int zero = ((payload[pos++] & 0xFF) << 8)
                |  (payload[pos++] & 0xFF);

        byte cmd = (byte) cmdInt;
        byte ver = (byte) verInt;

        System.out.printf("[RIP PARSE] cmd=%d ver=%d first4=%02X %02X %02X %02X len=%d%n",
                cmdInt, verInt,
                payload[0] & 0xFF,
                payload[1] & 0xFF,
                payload[2] & 0xFF,
                payload[3] & 0xFF,
                payload.length
        );

        if (verInt != VERSION_2) {

            throw new IllegalArgumentException("Unsupported RIP version: " + verInt);
        }

        List<Rte> rtes = new ArrayList<>();

        while (pos + 20 <= payload.length) {
            int afi = readU16(payload, pos);       pos += 2;
            int routeTag = readU16(payload, pos);  pos += 2;
            int ipRaw = readS32(payload, pos);     pos += 4;
            int maskRaw = readS32(payload, pos);   pos += 4;
            int nhRaw = readS32(payload, pos);     pos += 4;
            int metric = readS32(payload, pos);    pos += 4;

            if (afi != 2) {
                continue;
            }
            if (metric < 1 || metric > 16) {
                continue;
            }

            int prefixLen = maskToPrefixLen(maskRaw);
            if (prefixLen < 0) {
                continue;
            }

            IpAddres ip = IpAddres.fromInt(ipRaw);
            IpAddres netAddr = ip.networkAddress(prefixLen);
            IpAddres nextHop = (nhRaw == 0) ? null : IpAddres.fromInt(nhRaw);

            Rte rte = new Rte(netAddr, prefixLen, nextHop, metric);
            rtes.add(rte);
        }

        return new RipMessage(cmd, ver, rtes);
    }


    private static int readU16(byte[] data, int pos) {
        return ((data[pos] & 0xFF) << 8)
                |  (data[pos + 1] & 0xFF);
    }

    private static int readS32(byte[] data, int pos) {
        return ((data[pos]     & 0xFF) << 24)
                | ((data[pos + 1] & 0xFF) << 16)
                | ((data[pos + 2] & 0xFF) << 8)
                |  (data[pos + 3] & 0xFF);
    }

    private static int maskToPrefixLen(int mask) {

        int cnt = Integer.bitCount(mask);
        if (cnt == 0) return 0;
        int ideal = cnt == 32 ? 0xFFFFFFFF : (int)(0xFFFFFFFFL << (32 - cnt));
        if (mask != ideal) return -1;
        return cnt;
    }


    public static final class RipMessage {
        private final byte cmd;
        private final byte version;
        private final List<Rte> rtes;

        public RipMessage(byte cmd, byte version, List<Rte> rtes) {
            this.cmd = cmd;
            this.version = version;
            this.rtes = (rtes == null) ? new ArrayList<>() : rtes;
        }

        public byte getCmd() { return cmd; }
        public byte getVersion() { return version; }
        public List<Rte> getRtes() { return rtes; }

        public boolean isRequest()  { return cmd == CMD_REQUEST; }
        public boolean isResponse() { return cmd == CMD_RESPONSE; }
    }

    public static final class Rte {
        private final IpAddres prefixNetwork;
        private final int prefixLen;
        private final IpAddres nextHop;
        private final int metric;

        public Rte(IpAddres prefixNetwork, int prefixLen, IpAddres nextHop, int metric) {
            this.prefixNetwork = prefixNetwork;
            this.prefixLen = prefixLen;
            this.nextHop = nextHop;
            this.metric = metric;
        }

        public IpAddres getPrefixNetwork() { return prefixNetwork; }
        public int getPrefixLen() { return prefixLen; }
        public IpAddres getNextHop() { return nextHop; }
        public int getMetric() { return metric; }
    }
}
