package rip;

import network.IpAddres;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Парсер RIPv2 payload (UDP data):
 * Header: 1B cmd, 1B version, 2B zero
 * RTE x N:  2B AFI (2 для IPv4), 2B RouteTag,
 *           4B IP, 4B Mask, 4B NextHop, 4B Metric (1..16)
 */
public final class RipParser {

    public static final byte CMD_REQUEST  = 1;
    public static final byte CMD_RESPONSE = 2;
    public static final byte VERSION_2    = 2;

    private RipParser(){}

    /** Розібрати UDP-пейлоад у структуру RipMessage з RTE. Кидає IllegalArgumentException при помилках. */
    public static RipMessage parse(byte[] payload) {
        if (payload == null || payload.length < 4)
            throw new IllegalArgumentException("RIP payload too short");

        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);

        byte cmd = bb.get();
        byte ver = bb.get();
        short zero = bb.getShort(); // має бути 0, але багато стеків ігнорують

        if (ver != VERSION_2)
            throw new IllegalArgumentException("Unsupported RIP version: " + ver);

        // Парсимо RTE (кратні 20 байт)
        List<Rte> rtes = new ArrayList<>();
        while (bb.remaining() >= 20) {
            short afi = bb.getShort();      // 2 -> IPv4
            short routeTag = bb.getShort(); // ігноруємо (0 зазвич.)
            int ipRaw = bb.getInt();
            int maskRaw = bb.getInt();
            int nhRaw = bb.getInt();
            int metric = bb.getInt();

            if (afi != 2) {
                // Пропускаємо не-IPv4 RTE (RIPng тощо) — або кидати помилку
                continue;
            }
            if (metric < 1 || metric > 16) {
                // Невалідна метрика
                continue;
            }
            int prefixLen = maskToPrefixLen(maskRaw);
            if (prefixLen < 0) {
                // Невалідна маска (небезперервні біти)
                continue;
            }

            IpAddres ip = IpAddres.fromInt(ipRaw);
            IpAddres maskNetAddr = ip.networkAddress(prefixLen); // нормалізуємо адресу до мережі
            IpAddres nextHop = (nhRaw == 0) ? null : IpAddres.fromInt(nhRaw);

            Rte rte = new Rte(maskNetAddr, prefixLen, nextHop, metric);
            rtes.add(rte);
        }

        RipMessage msg = new RipMessage(cmd, ver, rtes);
        return msg;
    }

    /** Маска (big-endian int) → довжина префікса; повертає -1 якщо маска не суцільна. */
    private static int maskToPrefixLen(int mask) {
        // приклад: /24 => 0xFFFFFF00
        // Перевіряємо, що біти виду 111..1100..00 (суцільна)
        int cnt = Integer.bitCount(mask);
        if (cnt == 0) return 0;
        // Побудуємо ідеальну маску з тією ж кількістю одиниць
        int ideal = cnt == 32 ? 0xFFFFFFFF : (int)(0xFFFFFFFFL << (32 - cnt));
        if (mask != ideal) return -1;
        return cnt;
    }

    // ------------------- DTO-класи -------------------

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
        private final IpAddres prefixNetwork; // нормалізована мережева адреса
        private final int prefixLen;          // 0..32
        private final IpAddres nextHop;       // null -> 0.0.0.0
        private final int metric;             // 1..16

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
