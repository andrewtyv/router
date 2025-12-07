package DHCP;

import network.IpAddres;

public class DhcpParser {

    private static final int DHCP_MAGIC_COOKIE = 0x63825363;
    private static final int OPT_DHCP_MESSAGE_TYPE = 53;
    private static final int OPT_REQUESTED_IP     = 50;
    private static final int OPT_END              = 255;

    public static DhcpMessage parse(byte[] payload) {
        if (payload == null || payload.length < 240) {
            return new DhcpMessage(DhcpMessageType.OTHER, null);
        }

        int cookie = ((payload[236] & 0xFF) << 24)
                | ((payload[237] & 0xFF) << 16)
                | ((payload[238] & 0xFF) << 8)
                | (payload[239] & 0xFF);

        if (cookie != DHCP_MAGIC_COOKIE) {
            return new DhcpMessage(DhcpMessageType.OTHER, null);
        }

        DhcpMessageType msgType = DhcpMessageType.OTHER;
        IpAddres requestedIp = null;

        int i = 240;
        while (i < payload.length) {
            int code = payload[i] & 0xFF;
            if (code == OPT_END) {
                break;
            }
            if (code == 0) {
                i++;
                continue;
            }
            if (i + 1 >= payload.length) break;
            int len = payload[i + 1] & 0xFF;
            if (i + 2 + len > payload.length) break;

            if (code == OPT_DHCP_MESSAGE_TYPE && len == 1) {
                int v = payload[i + 2] & 0xFF;
                msgType = switch (v) {
                    case 1 -> DhcpMessageType.DISCOVER;
                    case 3 -> DhcpMessageType.REQUEST;
                    case 7 -> DhcpMessageType.RELEASE;
                    default -> DhcpMessageType.OTHER;
                };
            }
            else if (code == OPT_REQUESTED_IP && len == 4) {
                int b1 = payload[i + 2] & 0xFF;
                int b2 = payload[i + 3] & 0xFF;
                int b3 = payload[i + 4] & 0xFF;
                int b4 = payload[i + 5] & 0xFF;
                String ipStr = b1 + "." + b2 + "." + b3 + "." + b4;
                requestedIp = new IpAddres(ipStr);
            }

            i += 2 + len;
        }

        return new DhcpMessage(msgType, requestedIp);
    }
}
