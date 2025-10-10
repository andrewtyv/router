package util;

public class Parser  {

    private Parser() {
        // приватний конструктор, щоб не створювали інстанс
    }

    public static int[] parseIpv4(String ipStr) {
        if (ipStr == null) {
            throw new IllegalArgumentException(" null row ");
        }
        String[] parts = ipStr.trim().split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("bad ip format ");
        }

        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i].trim();
            if (!p.matches("\\d+")) {
                throw new IllegalArgumentException("is not a number:  " + p);
            }
            int val = Integer.parseInt(p);
            if (val < 0 || val > 255) {
                throw new IllegalArgumentException("is > 255: " + val);
            }
            octets[i] = val;
        }
        return octets;
    }
}
