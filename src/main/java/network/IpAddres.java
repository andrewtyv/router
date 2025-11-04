package network;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Objects;

/**
 * IPv4 адреса з валідацією та корисними утилітами.
 * Назва лишена для сумісності з існуючим кодом.
 */
public class IpAddres implements Comparable<IpAddres> {

    private int o1;
    private int o2;
    private int o3;
    private int o4;

    /* -------------------- Конструктори -------------------- */

    /** Створити з рядка "A.B.C.D" (кидає IllegalArgumentException при невалідному форматі). */
    public IpAddres(String ip) {
        int[] t = parseIpv4(ip);
        this.o1 = t[0];
        this.o2 = t[1];
        this.o3 = t[2];
        this.o4 = t[3];
    }

    /** Створити з чотирьох октетів (кожен 0..255). */
    public IpAddres(int o1, int o2, int o3, int o4) {
        this.o1 = checkOctet(o1);
        this.o2 = checkOctet(o2);
        this.o3 = checkOctet(o3);
        this.o4 = checkOctet(o4);
    }

    /* -------------------- Представлення -------------------- */

    /** Канонічний рядок "A.B.C.D". */
    public String getIp() {
        return o1 + "." + o2 + "." + o3 + "." + o4;
    }

    @Override public String toString() { return getIp(); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IpAddres other)) return false;
        return this.toInt() == other.toInt();
    }

    /** Зручне порівняння з Inet4Address (не перевизначає equals(Object)). */
    public boolean equalsInet4(Inet4Address a) {
        return a != null && this.getIp().equals(a.getHostAddress());
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(toInt());
    }

    /* -------------------- Конвертації -------------------- */

    /** У масив байтів (big-endian): [A, B, C, D]. */
    public byte[] toBytes() {
        return new byte[] { (byte)o1, (byte)o2, (byte)o3, (byte)o4 };
    }

    /** До 32-бітного int (big-endian): A<<24 | B<<16 | C<<8 | D. */
    public int toInt() {
        return ((o1 & 0xFF) << 24) | ((o2 & 0xFF) << 16) | ((o3 & 0xFF) << 8) | (o4 & 0xFF);
    }

    /** З 32-бітного int (big-endian). */
    public static IpAddres fromInt(int val) {
        int a = (val >>> 24) & 0xFF;
        int b = (val >>> 16) & 0xFF;
        int c = (val >>> 8)  & 0xFF;
        int d =  val         & 0xFF;
        return new IpAddres(a, b, c, d);
    }

    /* -------------------- Класифікація адрес -------------------- */

    public boolean isLoopback()  { return o1 == 127; }                          // 127.0.0.0/8
    public boolean isLinkLocal() { return o1 == 169 && o2 == 254; }            // 169.254.0.0/16
    public boolean isMulticast() { return o1 >= 224 && o1 <= 239; }            // 224.0.0.0/4
    public boolean isBroadcast() { return o1 == 255 && o2 == 255 && o3 == 255 && o4 == 255; }
    public boolean isUnspecified(){ return o1 == 0 && o2 == 0 && o3 == 0 && o4 == 0; } // 0.0.0.0

    /** RFC1918 приватні: 10/8, 172.16/12, 192.168/16. */
    public boolean isPrivate() {
        if (o1 == 10) return true;                                             // 10.0.0.0/8
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) return true;                  // 172.16.0.0/12
        return (o1 == 192 && o2 == 168);                                       // 192.168.0.0/16
    }

    /** Спрощено: унікасний (не loopback/link-local/multicast/broadcast/unspecified). */
    public boolean isUnicast() {
        return !isLoopback() && !isLinkLocal() && !isMulticast() && !isBroadcast() && !isUnspecified();
    }

    /* -------------------- Підмережі / CIDR -------------------- */

    /** Чи належить адреса підмережі network/prefix. */
    public boolean inSubnet(IpAddres network, int prefix) {
        int mask = toPrefixMaskInt(prefix);
        return (this.toInt() & mask) == (network.toInt() & mask);
    }

    /** Мережева адреса для заданого префікса. */
    public IpAddres networkAddress(int prefix) {
        int mask = toPrefixMaskInt(prefix);
        return IpAddres.fromInt(this.toInt() & mask);
    }

    /** Broadcast-адреса для заданого префікса. */
    public IpAddres broadcastAddress(int prefix) {
        int mask = toPrefixMaskInt(prefix);
        return IpAddres.fromInt(this.toInt() | ~mask);
    }

    /** Чи є адреса саме мережевою для prefix. */
    public boolean isNetworkAddress(int prefix) {
        return this.equals(this.networkAddress(prefix));
    }

    /** Чи є адреса directed-broadcast для prefix. */
    public boolean isDirectedBroadcast(int prefix) {
        return this.equals(this.broadcastAddress(prefix));
    }

    /** Чи в одній підмережі з іншою адресою при prefix. */
    public boolean sameSubnet(IpAddres other, int prefix) {
        int mask = toPrefixMaskInt(prefix);
        return (this.toInt() & mask) == (other.toInt() & mask);
    }

    /** Маска з префікса як IP (напр. /24 -> 255.255.255.0). */
    public static IpAddres maskFromPrefix(int prefix) {
        int m = toPrefixMaskInt(prefix);
        return fromInt(m);
    }

    /** Префікс із маски (255.255.255.0 -> 24); -1 якщо маска не суцільна. */
    public static int prefixFromMask(IpAddres mask) {
        int m = mask.toInt();
        int ones = Integer.bitCount(m);
        if (!isContiguousMask(m)) return -1;
        return ones;
    }

    /** Перевірка, що маска суцільна 111..1100..00. */
    public static boolean isContiguousMask(int m) {
        if (m == 0) return true; // /0
        int ones = Integer.bitCount(m);
        int ideal = ones == 32 ? 0xFFFFFFFF : (int)(0xFFFFFFFFL << (32 - ones));
        return m == ideal;
    }

    /** Конвертація префікса у int-маску (BIG_ENDIAN). */
    public static int toPrefixMaskInt(int prefix) {
        if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("prefix 0..32: " + prefix);
        return prefix == 0 ? 0 : (int)(0xFFFFFFFFL << (32 - prefix));
    }

    /** Парсер "A.B.C.D/len" → Cidr(addr, len). Кидає IllegalArgumentException при помилці. */
    public static Cidr parseCidr(String s) {
        if (s == null) throw new IllegalArgumentException("cidr is null");
        String[] parts = s.trim().split("/");
        if (parts.length != 2) throw new IllegalArgumentException("Invalid CIDR: " + s);
        IpAddres ip = new IpAddres(parts[0]);
        int pfx;
        try { pfx = Integer.parseInt(parts[1]); }
        catch (NumberFormatException e){ throw new IllegalArgumentException("Invalid prefix in CIDR: " + s); }
        if (pfx < 0 || pfx > 32) throw new IllegalArgumentException("prefix 0..32: " + pfx);
        return new Cidr(ip, pfx);
    }

    /** Простий валідатор рядка IPv4. */
    public static boolean isValid(String ip) {
        try { parseIpv4(ip); return true; } catch (Exception e) { return false; }
    }

    /* -------------------- Ґетери/Сетери з валідацією -------------------- */

    public int getO1() { return o1; }
    public int getO2() { return o2; }
    public int getO3() { return o3; }
    public int getO4() { return o4; }

    public void setO1(Integer o1) { this.o1 = checkOctet(o1); }
    public void setO2(Integer o2) { this.o2 = checkOctet(o2); }
    public void setO3(Integer o3) { this.o3 = checkOctet(o3); }
    public void setO4(Integer o4) { this.o4 = checkOctet(o4); }

    /* -------------------- Порівняння/Сортування -------------------- */

    @Override
    public int compareTo(IpAddres o) {
        return Integer.compareUnsigned(this.toInt(), o.toInt());
    }

    /* -------------------- Хелпери -------------------- */

    private static int[] parseIpv4(String ip) {
        if (ip == null) throw new IllegalArgumentException("ip is null");
        String s = ip.trim();
        String[] parts = s.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4: " + ip);
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) {
            try {
                int v = Integer.parseInt(parts[i]);
                out[i] = checkOctet(v);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid octet in IPv4: " + ip);
            }
        }
        return out;
    }

    private static int checkOctet(Integer v) {
        if (v == null || v < 0 || v > 255) {
            throw new IllegalArgumentException("IPv4 octet must be 0..255: " + v);
        }
        return v;
    }

    /* -------------------- Вкладені типи -------------------- */

    /** Результат парсингу CIDR. */
    public static class Cidr {
        public final IpAddres address;
        public final int prefix;

        public Cidr(IpAddres address, int prefix) {
            this.address = Objects.requireNonNull(address);
            if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("prefix 0..32: " + prefix);
            this.prefix = prefix;
        }
    }
}
