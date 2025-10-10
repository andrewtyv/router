package ARP;

import network.IpAddres;
import org.pcap4j.util.MacAddress;

public interface IfAddressBook {
    IpAddres getIp(String ifName);     // логічний IP, який ти призначив порту
    MacAddress getMac(String ifName);      // MAC прив'язаного NIC (можеш делегувати в IfBindingManager)
}
