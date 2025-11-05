package ARP;

import network.IpAddres;
import org.pcap4j.util.MacAddress;

public interface IfAddressBook {
    IpAddres getIp(String ifName);     // logical IP,
    MacAddress getMac(String ifName);      // MAC
}
