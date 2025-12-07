package DHCP;

import network.IpAddres;
import network.IpMask;
import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class DHCPEngine {

    private final Map<String, DhcpServer> serversByIf = new ConcurrentHashMap<>();
    private final DhcpTx tx;
    private final DhcpIpConflictDetector detector;


    public DHCPEngine(DhcpTx tx, DhcpIpConflictDetector detector) {
        this.tx = tx;
        this.detector = detector;
    }
    public void addServer(String ifName,
                          IpAddres poolStart,
                          IpAddres poolEnd,
                          IpMask mask,
                          IpAddres gateway,
                          DhcpMode mode) {

        Objects.requireNonNull(ifName);
        DhcpServer srv = new DhcpServer(ifName, poolStart, poolEnd, mask, gateway, mode, tx, detector);
        serversByIf.put(ifName, srv);
    }

    public void removeServer(String ifName) {
        serversByIf.remove(ifName);
    }

    public void onDhcpPacket(String ifName,
                             MacAddress srcMac,
                             IpAddres srcIp,
                             byte[] udpPayload) {

        DhcpServer srv = serversByIf.get(ifName);
        if (srv == null) {
            System.out.println("cannot find ifname or dhcp disabled on this ifname");
            return;
        }

        srv.handleDhcpPacket(srcMac, srcIp, udpPayload);
    }

    public void addManualBinding(String ifName, String macStr, String ipStr) {
        DhcpServer srv = serversByIf.get(ifName);
        if (srv == null) {
            throw new IllegalStateException("DHCP not enabled on " + ifName);
        }

        MacAddress mac = MacAddress.getByName(macStr);
        IpAddres ip     = new IpAddres(ipStr);

        srv.addManualIp(mac, ip);
    }

    public void removeManualBinding(String ifName, String macStr) {
        DhcpServer srv = serversByIf.get(ifName);
        if (srv == null) {
            throw new IllegalStateException("DHCP not enabled on " + ifName);
        }
        srv.removeManualIp(MacAddress.getByName(macStr));
    }

    public Map<String, String> getManualBindings(String ifName) {
        DhcpServer srv = serversByIf.get(ifName);
        if (srv == null) {
            throw new IllegalStateException("DHCP not enabled on " + ifName);
        }
        return srv.getManualBindingsAsStrings();
    }
    public List<DhcpLeaseInfo> getAllLeases() {
       List<DhcpLeaseInfo> res = new ArrayList<>();
        for (DhcpServer srv : serversByIf.values()) {
            res.addAll(srv.getLeases());
        }
        return res;
    }

    public List<DhcpLeaseInfo> getLeases(String ifName) {
        DhcpServer srv = serversByIf.get(ifName);
        if (srv == null) {
            throw new IllegalStateException("DHCP not enabled on " + ifName);
        }
        return srv.getLeases();
    }

}
