package DHCP;

import network.IpAddres;

public class DhcpMessage {

    private final DhcpMessageType type;
    private final IpAddres requestedIp;

    public DhcpMessage(DhcpMessageType type, IpAddres requestedIp) {
        this.type = type;
        this.requestedIp = requestedIp;
    }

    public DhcpMessageType getType() {
        return type;
    }

    public IpAddres getRequestedIp() {
        return requestedIp;
    }
}
