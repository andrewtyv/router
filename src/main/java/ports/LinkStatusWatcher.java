package ports;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;

@Component
public class LinkStatusWatcher {

    private static final Logger log = LoggerFactory.getLogger(LinkStatusWatcher.class);

    private static final long PERIOD_MS = 1000;

    private final ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor();
    private final Map<String, Boolean> last = new ConcurrentHashMap<>();
    private final List<LinkListener> listeners = new CopyOnWriteArrayList<>();


    public Set<String> snapshotActiveIfaces() {
        return last.entrySet().stream()
                .filter(e -> Boolean.TRUE.equals(e.getValue()))
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
    }

    public boolean isActive(String iface) {
        return Boolean.TRUE.equals(last.get(iface));
    }

    public interface LinkListener {
        void onLinkChange(LinkEvent ev);
    }

    public static class LinkEvent {
        public final String iface;
        public final boolean plugged;
        public final Instant ts;

        public LinkEvent(String iface, boolean plugged, Instant ts) {
            this.iface = iface;
            this.plugged = plugged;
            this.ts = ts;
        }

        @Override
        public String toString() {
            return "LinkEvent{iface=%s, plugged=%s, ts=%s}".formatted(iface, plugged, ts);
        }
    }

    public void addListener(LinkListener l) {
        listeners.add(l);
    }

    public void removeListener(LinkListener l) {
        listeners.remove(l);
    }

    public void start() {
        // перший прогін одразу
        ses.scheduleAtFixedRate(this::pollOnceSafe, 0, PERIOD_MS, TimeUnit.MILLISECONDS);
        log.info("LinkStatusWatcher started ({} ms period).", PERIOD_MS);
    }

    @PreDestroy
    public void stop() {
        ses.shutdownNow();
        log.info("LinkStatusWatcher stopped.");
    }

    private void pollOnceSafe() {
        try {
            pollOnce();
        } catch (Throwable t) {
            log.warn("Link poll error: {}", t.toString());
        }
    }

    private void pollOnce() {
        Set<String> current = listCandidates();
        for (String ifn : current) {
            boolean plugged = IfconfigLink.isCablePlugged(ifn);
            Boolean prev = last.put(ifn, plugged);
            if (prev == null) {
                fire(new LinkEvent(ifn, plugged, Instant.now()));
            } else if (prev.booleanValue() != plugged) {
                fire(new LinkEvent(ifn, plugged, Instant.now()));
            }
        }
        Iterator<Map.Entry<String, Boolean>> it = last.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Boolean> e = it.next();
            if (!current.contains(e.getKey())) {
                fire(new LinkEvent(e.getKey(), false, Instant.now()));
                it.remove();
            }
        }
    }

    private void fire(LinkEvent ev) {
        log.info("LINK {}", ev);
        for (LinkListener l : listeners) {
            try {
                l.onLinkChange(ev);
            } catch (Throwable t) {
                log.warn("listener err: {}", t.toString());
            }
        }
    }

    private static Set<String> listCandidates() {
        Set<String> out = new java.util.LinkedHashSet<>();
        try {
            Process p = new ProcessBuilder("ifconfig", "-l").start();
            try (var br = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()))) {
                String line = br.readLine();
                if (line != null) {
                    for (String name : line.trim().split("\\s+")) {
                        if (isEnGreaterThan6(name)) {
                            out.add(name);
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return out;
    }

    //NOT USE!!!!!!
    private static boolean isEnGreaterThan6(String name) {
        /*if (!name.startsWith("en")) return false;
        try {
            int num = Integer.parseInt(name.substring(2));
            return num > 6;
        } catch (NumberFormatException e) {
            return false;
        }
        */
         return true;
    }


}
