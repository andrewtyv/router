package network;

import java.util.Objects;

/**
 * IPv4 адреса з валідацією та корисними утилітами.
 * Залишаємо назву IpAddres для сумісності, але рекомендується перейменувати на IpAddress.
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

    /** Залишено для сумісності зі старим кодом. */

    @Override public String toString() { return getIp(); }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IpAddres other)) return false;
        return Objects.equals(this.getIp(), other.getIp());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getIp());
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

    public boolean isLoopback() { return o1 == 127; }                          // 127.0.0.0/8
    public boolean isLinkLocal() { return o1 == 169 && o2 == 254; }            // 169.254.0.0/16
    public boolean isMulticast() { return o1 >= 224 && o1 <= 239; }            // 224.0.0.0/4
    public boolean isBroadcast() { return o1 == 255 && o2 == 255 && o3 == 255 && o4 == 255; }

    /** RFC1918 приватні: 10/8, 172.16/12, 192.168/16. */
    public boolean isPrivate() {
        if (o1 == 10) return true;                                             // 10.0.0.0/8
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) return true;                  // 172.16.0.0/12
        return (o1 == 192 && o2 == 168);                                       // 192.168.0.0/16
    }

    /* -------------------- Підмережі -------------------- */

    /** Чи належить адреса підмережі network/prefix. */
    public boolean inSubnet(IpAddres network, int prefix) {
        int mask = prefixMask(prefix);
        return (this.toInt() & mask) == (network.toInt() & mask);
    }

    /** Мережева адреса для заданого префікса. */
    public IpAddres networkAddress(int prefix) {
        int mask = prefixMask(prefix);
        return IpAddres.fromInt(this.toInt() & mask);
    }

    /** Broadcast-адреса для заданого префікса. */
    public IpAddres broadcastAddress(int prefix) {
        int mask = prefixMask(prefix);
        return IpAddres.fromInt(this.toInt() | ~mask);
    }

    private static int prefixMask(int prefix) {
        if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("prefix 0..32: " + prefix);
        return prefix == 0 ? 0 : (int)(0xFFFFFFFFL << (32 - prefix));
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
}
