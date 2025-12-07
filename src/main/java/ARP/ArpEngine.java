package ARP;

import network.IpAddres;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;
import ports.TxSender;
import rib.Rib;

import java.net.Inet4Address;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

public class ArpEngine {

    private final IfAddressBook ifBook;
    private final ArpCache cache;
    private final ArpRequestScheduler scheduler;
    private final TxSender tx;

    private final Rib rib;
    private final ProxyArpConfig proxyCfg;

    public ArpEngine(IfAddressBook ifBook,
                     ArpCache cache,
                     ArpRequestScheduler scheduler,
                     TxSender tx,
                     Rib rib,
                     ProxyArpConfig proxyCfg) {
        this.ifBook = Objects.requireNonNull(ifBook);
        this.cache = Objects.requireNonNull(cache);
        this.scheduler = Objects.requireNonNull(scheduler);
        this.tx = Objects.requireNonNull(tx);
        this.rib = Objects.requireNonNull(rib);
        this.proxyCfg = Objects.requireNonNull(proxyCfg);
    }

    public void onEthernetFrame(EthernetPacket eth, String ifName) {
        System.out.println("EtherType: " + eth.getHeader().getType());
        if (eth.getHeader().getType() != EtherType.ARP) return;
        if (!(eth.getPayload() instanceof ArpPacket arp)) return;

        ArpPacket.ArpHeader h = arp.getHeader();
        IpAddres spa = new IpAddres(h.getSrcProtocolAddr().getHostAddress());
        MacAddress sha = h.getSrcHardwareAddr();
        Inet4Address tpa = (Inet4Address) h.getDstProtocolAddr();
        System.out.println("tpa host:"+ tpa.getHostAddress()+"\n\n\n" );


        MacAddress selfMac = ifBook.getMac(ifName);
        IpAddres   selfIp  = ifBook.getIp(ifName);

        if (sha != null && sha.equals(selfMac)) return;
        if (selfIp != null && selfIp.equalsInet4((Inet4Address) h.getSrcProtocolAddr())) return;

        boolean isRequest = h.getOperation().equals(ArpOperation.REQUEST);
        System.out.println("isREq:"+ isRequest );
        System.out.println("\n");
        System.out.printf("[ARP] Got request for %s, my %s on %s%n", tpa, selfIp, ifName);


        boolean weWaitForSpa = cache.get(spa)
                .map(e -> e.state == ArpCache.State.INCOMPLETE)
                .orElse(false);
        boolean askedUs = isRequest && isLocalTarget(ifName, tpa);

        if (weWaitForSpa || askedUs) {
            cache.learned(spa, sha);
            scheduler.onLearned(ifName, spa, sha);
        }

        if (isRequest && isLocalTarget(ifName, tpa)) {
            System.out.println("asked us");
            try {
                EthernetPacket reply = ArpFrameBuilder.buildReply(selfMac, selfIp, sha, spa);
                tx.send(ifName, reply);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;
        }
        System.out.println("isRequested:" + isRequest + "\nshouldProxyfor:" + shouldProxyFor(ifName,tpa));
        if (isRequest && shouldProxyFor(ifName, tpa)) {
            try {
                System.out.println("Sending reply for proxy with:selfMac:" + selfMac + "tpa:" + tpa.getHostAddress() + " sha:" + sha+ " spa:" +spa );
                EthernetPacket reply = ArpFrameBuilder.buildReply(selfMac,
                        new IpAddres(tpa.getHostAddress()), sha, spa);
                tx.send(ifName, reply);

                cache.learned(new IpAddres(tpa.getHostAddress()), selfMac);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

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

    public boolean isLocalTarget(String ifName, Inet4Address ip) {
        IpAddres local = ifBook.getIp(ifName);
        return local != null && local.equalsInet4(ip);
    }


    private boolean shouldProxyFor(String inIf, Inet4Address targetIpRaw){
        final String t = targetIpRaw.getHostAddress();

        boolean en = proxyCfg.isEnabledOn(inIf);
        if (!en) {
            System.out.printf("[PARP] inIf=%s target=%s -> NO (disabled on inIf)%n", inIf, t);
            return false;
        }

        IpAddres target = new IpAddres(t);
        if (!target.isUnicast()) {
            System.out.printf("[PARP] inIf=%s target=%s -> NO (not unicast)%n", inIf, t);
            return false;
        }

        IpAddres self = ifBook.getIp(inIf);
        if (self != null && self.equals(target)) {
            System.out.printf("[PARP] inIf=%s target=%s -> NO (target is self IP=%s)%n", inIf, t, self);
            return false;
        }

        var bestOpt = rib.lookup(target);
        if (bestOpt.isEmpty()) {
            System.out.printf("[PARP] inIf=%s target=%s -> NO (RIB: no route)%n", inIf, t);
            return false;
        }

        var best = bestOpt.get();
        System.out.printf("[PARP] inIf=%s target=%s RIB -> %s/%d via %s outIf=%s ad=%s proto=%s metric=%d%n",
                inIf, t,
                best.network().getIp(), best.length(),
                (best.nextHop()==null ? "-" : best.nextHop().getIp()),
                best.outIf(),
                best.ad(), best.proto(), best.metric());


        if (best.outIf() != null && best.outIf().equals(inIf)) {
            System.out.printf("[PARP] inIf=%s target=%s -> NO (best.outIf==inIf: %s)%n", inIf, t, inIf);
            return false;
        }


        System.out.printf("[PARP] inIf=%s target=%s -> YES (route exits via %s)%n",
                inIf, t, best.outIf());

        return true;
    }

}
