package ARP;

import network.IpAddres;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;
import ports.TxSender;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;

public class ArpRequestScheduler {

    private static final class Job {
        final String ifName;
        final IpAddres target;
        final CompletableFuture<MacAddress> future = new CompletableFuture<>();
        int attempt = 0;
        ScheduledFuture<?> timer;
        Job(String ifName, IpAddres target) { this.ifName = ifName; this.target = target; }
    }

    private final IfAddressBook ifBook;
    private final TxSender tx;
    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "arp-resolve"); t.setDaemon(true); return t;
    });

    private final int[] DELAYS_MS = {1000, 1000, 2000};

    public ArpRequestScheduler(IfAddressBook ifBook, TxSender tx) {
        this.ifBook = Objects.requireNonNull(ifBook);
        this.tx = Objects.requireNonNull(tx);
    }

    private static String key(String ifName, IpAddres ip) { return ifName + "|" + ip.getIp(); }

    public CompletableFuture<MacAddress> kick(String ifName, IpAddres target) {
        String k = key(ifName, target);
        Job existing = jobs.get(k);
        if (existing != null) return existing.future;

        Job job = new Job(ifName, target);
        jobs.put(k, job);
        sendOnce(job);
        return job.future;
    }

    private void sendOnce(Job job) {
        try {
            MacAddress srcMac = ifBook.getMac(job.ifName);
            IpAddres srcIp = ifBook.getIp(job.ifName);
            EthernetPacket req = ArpFrameBuilder.buildRequest(srcMac, srcIp, job.target);
            tx.send(job.ifName, req);
        } catch (Exception e) {
            completeExceptionally(job, e);
            return;
        }

        if (job.attempt >= DELAYS_MS.length) {
            completeExceptionally(job, new TimeoutException("ARP no reply after retries"));
            return;
        }
        int delay = DELAYS_MS[job.attempt++];
        job.timer = ses.schedule(() -> sendOnce(job), delay, TimeUnit.MILLISECONDS);
    }

    private void complete(Job job, MacAddress mac) {
        cancelTimer(job);
        jobs.remove(key(job.ifName, job.target));
        job.future.complete(mac);
    }

    private void completeExceptionally(Job job, Throwable t) {
        cancelTimer(job);
        jobs.remove(key(job.ifName, job.target));
        job.future.completeExceptionally(t);
    }

    private void cancelTimer(Job job) {
        if (job.timer != null) { job.timer.cancel(true); job.timer = null; }
    }

    public void onLearned(String ifName, IpAddres ip, MacAddress mac) {
        Job j = jobs.get(key(ifName, ip));
        if (j != null) complete(j, mac);
    }

    public void shutdown() { ses.shutdownNow(); }
}
