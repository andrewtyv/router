package ARP;

import network.IpAddres;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;
import ports.TxSender;

import java.net.Inet4Address;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import network.IpAddres;


public class ArpEngine {

    private final IfAddressBook ifBook;
    private final ArpCache cache;
    private final ArpRequestScheduler scheduler;
    private final TxSender tx;

    public ArpEngine(IfAddressBook ifBook, ArpCache cache, ArpRequestScheduler scheduler, TxSender tx) {
        this.ifBook = Objects.requireNonNull(ifBook);
        this.cache = Objects.requireNonNull(cache);
        this.scheduler = Objects.requireNonNull(scheduler);
        this.tx = Objects.requireNonNull(tx);
    }

    /** Викликається з PacketRxLoop для кожного Ethernet кадру. */
    public void onEthernetFrame(EthernetPacket eth, String ifName) {
        System.out.println("etype=" + eth.getHeader().getType());
        if (eth.getHeader().getType() != EtherType.ARP) {
            System.out.println("here1");

            return;
            }
        if (!(eth.getPayload() instanceof ArpPacket arp)) {
            System.out.println("here2");
               return;

        }

        ArpPacket.ArpHeader h = arp.getHeader();
        IpAddres spa = new IpAddres((h.getSrcProtocolAddr().getHostAddress()));
        MacAddress sha    = h.getSrcHardwareAddr();
        Inet4Address tpa = (Inet4Address) h.getDstProtocolAddr();

        MacAddress selfMac = ifBook.getMac(ifName);
        IpAddres   selfIp  = ifBook.getIp(ifName);
        if (sha != null && sha.equals(selfMac)) {
            return;
        }

        if (spa.equals(selfIp)) {
                return;
        }

        boolean weWaitForSpa = cache.get(spa)
                .map(e -> e.state == ArpCache.State.INCOMPLETE)
                .orElse(false);

        boolean askedUs = h.getOperation().equals(ArpOperation.REQUEST) && isLocalTarget(ifName, tpa);

        if (weWaitForSpa || askedUs) {
            // Запам'ятати хто нам написав (лише у дозволених кейсах)
            cache.learned(spa, sha);
            // Пінгнути scheduler: якщо чекали — завершить future
            scheduler.onLearned(ifName, spa, sha);
        }

/*
        // 1) Запам'ятати хто нам написав
        cache.learned(spa, sha);
        // Пінгнути scheduler: якщо чекали цю адресу — завершай future
        scheduler.onLearned(ifName, spa, sha);

 */

        // 2) Якщо це ARP-REQUEST до нашого локального IP — відповідаємо (без proxy)
        if (h.getOperation().equals(ArpOperation.REQUEST) && isLocalTarget(ifName, tpa)) {
            try {
                MacAddress myMac = ifBook.getMac(ifName);
                IpAddres myIp = ifBook.getIp(ifName);
                EthernetPacket reply = ArpFrameBuilder.buildReply(myMac, myIp, sha, spa);
                tx.send(ifName, reply);
            } catch (Exception ignored) {}
        }
    }

    /** Активно дістати MAC для IP через ARP (з кешем і retry). */
    public CompletableFuture<MacAddress> resolve(String ifName, IpAddres target) {
        return cache.get(target)
                .filter(e -> e.state == ArpCache.State.REACHABLE && e.mac != null)
                .map(e -> CompletableFuture.completedFuture(e.mac))
                .orElseGet(() -> {
                    cache.beginResolve(target);
                    return scheduler.kick(ifName, target)
                            .whenComplete((mac, err) -> {
                                if (mac != null) cache.learned(target, mac);
                                else cache.markFailed(target);
                            });
                });
    }

    /** Чи належить ip цьому логічному інтерфейсу (щоб відповісти на ARP request). */
    public boolean isLocalTarget(String ifName, Inet4Address ip) {
        IpAddres local = ifBook.getIp(ifName);
        return local != null && local.equals(ip);
    }

}
