package ports;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class IfconfigLink {

    public static boolean isCablePlugged(String iface) {
        try {
            Process p = new ProcessBuilder("ifconfig", iface).start();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (line.startsWith("status:")) {
                        return line.contains("active");
                    }
                }
            }
        } catch (Exception e) {

        }
        return false;
    }
}
