package DHCP;

public class DhcpLeaseInfo {
    private final String ifName;
    private final String ip;
    private final String mac;
    private final Long remainingSeconds;
    private final DhcpMode mode;

    public DhcpLeaseInfo(String ifName,
                         String ip,
                         String mac,
                         Long remainingSeconds,
                         DhcpMode mode) {
        this.ifName = ifName;
        this.ip = ip;
        this.mac = mac;
        this.remainingSeconds = remainingSeconds;
        this.mode = mode;
    }

    public String getIfName() { return ifName; }
    public String getIp() { return ip; }
    public String getMac() { return mac; }
    public Long getRemainingSeconds() { return remainingSeconds; }
    public DhcpMode getMode() { return mode; }
}
