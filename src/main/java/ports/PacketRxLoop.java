package ports;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;

public class PacketRxLoop {

    private static final Logger log = LoggerFactory.getLogger(PacketRxLoop.class);

    private final IfBindingManager binding;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "rx-loop"); t.setDaemon(true); return t;
    });

    private final Map<String, Future<?>> loops = new ConcurrentHashMap<>();

    public PacketRxLoop(IfBindingManager binding) {
        this.binding = Objects.requireNonNull(binding);
    }

    public synchronized void start(String ifName, PacketHandler handler) {
        if (loops.containsKey(ifName)) return;

        PcapHandle handle = binding.getHandle(ifName);
        if (handle == null) throw new IllegalStateException("No pcap handle for " + ifName);

        PacketListener listener = pkt -> {
            if (pkt instanceof EthernetPacket eth) {
                handler.onPacket(eth, ifName);
            } else {
                // якщо драйвер раптом не повернув EthernetPacket
                try {
                    Packet top = pkt.get(EthernetPacket.class);
                    if (top != null) handler.onPacket((EthernetPacket) top, ifName);
                } catch (Exception ignored) {}
            }
        };

        Future<?> fut = pool.submit(() -> {
            try {
                handle.loop(-1, listener);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (NotOpenException noe) {
                log.debug("Handle closed for {}: {}", ifName, noe.toString());
            } catch (Throwable t) {
                log.warn("RX loop error on {}: {}", ifName, t.toString());
            } finally {
                loops.remove(ifName);
                log.info("RX loop stopped: {}", ifName);
            }
        });

        loops.put(ifName, fut);
        log.info("RX loop started: {}", ifName);
    }

    public synchronized void stop(String ifName) {
        Future<?> fut = loops.get(ifName);
        PcapHandle handle = binding.getHandle(ifName);
        if (handle != null) {
            try { handle.breakLoop(); } catch (Throwable ignored) {}
        }
        if (fut != null) {
            try { fut.get(2, TimeUnit.SECONDS); } catch (Exception ignored) {}
            loops.remove(ifName);
        }
    }
}
