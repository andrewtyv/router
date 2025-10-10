package ports;

import org.pcap4j.core.*;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Зв'язує логічний інтерфейс (ifName) з фізичним NIC (nicName),
 * відкриває/закриває pcap handle і ставить базовий фільтр.
 *
 * Політика:
 *  - дозволяємо bind тільки до enN, де N > 6;
 *  - дозволяємо bind тільки якщо LinkStatusWatcher показує, що NIC активний (carrier).
 */
public class IfBindingManager {

    private static final Logger log = LoggerFactory.getLogger(IfBindingManager.class);

    /** snaplen, mode і timeout можна винести в конфіг за бажанням */
    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT_MS = 10;

    private final LinkStatusWatcher watcher;

    /** runtime прив'язки: ifName -> Binding */
    private final ConcurrentHashMap<String, Binding> bindings = new ConcurrentHashMap<>();

    public IfBindingManager(LinkStatusWatcher watcher) {

        this.watcher = Objects.requireNonNull(watcher, "watcher");
    }

    /** Внутрішній контейнер для активної прив'язки */
    private static final class Binding {
        final String ifName;            // логічна назва (напр. "port1")
        final String nicName;           // системна назва (напр. "en8")
        final PcapNetworkInterface nif; // Pcap4J інтерфейс
        final MacAddress mac;           // MAC NIC-а
        final PcapHandle handle;        // відкритий live handle

        Binding(String ifName, String nicName, PcapNetworkInterface nif, MacAddress mac, PcapHandle handle) {
            this.ifName = ifName;
            this.nicName = nicName;
            this.nif = nif;
            this.mac = mac;
            this.handle = handle;
        }
    }

    /** Дозволяємо тільки enN, де N > 6 */
    private static boolean isAllowedEn(String nicName) {
        if (nicName == null || !nicName.startsWith("en")) return false;
        try {
            int n = Integer.parseInt(nicName.substring(2));
            return n > 6;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Прив'язати логічний інтерфейс до фізичного NIC і відкрити pcap.
     * Якщо вже був прив'язаний — спершу розриваємо попередній бінд.
     */
    public synchronized void bind(String ifName, String nicName) throws Exception {
        Objects.requireNonNull(ifName, "ifName");
        Objects.requireNonNull(nicName, "nicName");

        if (!isAllowedEn(nicName)) {
            throw new IllegalStateException("NIC not allowed by policy (need enN, N>6): " + nicName);
        }
        if (!watcher.isActive(nicName)) {
            throw new IllegalStateException("NIC " + nicName + " is not active (no carrier) — refusing bind");
        }

        // Якщо вже є бінд на цей ifName — спершу прибери
        unbind(ifName);

        PcapNetworkInterface nif = Pcaps.getDevByName(nicName);
        if (nif == null) {
            throw new IllegalArgumentException("NIC not found: " + nicName);
        }
        if (nif.getLinkLayerAddresses().isEmpty()) {
            throw new IllegalStateException("NIC has no MAC address: " + nicName);
        }

        // Відкриваємо live handle
        PcapHandle handle = nif.openLive(
                SNAPLEN,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                TIMEOUT_MS
        );

        // Базовий фільтр: ловимо ARP і все, що адресовано нашому MAC (можеш підмінити за потреби)
        MacAddress mac = (MacAddress) nif.getLinkLayerAddresses().get(0);
        String bpf = "arp or (ether dst " + mac + ")";
        handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);

        bindings.put(ifName, new Binding(ifName, nicName, nif, mac, handle));
        log.info("Bound {} -> {} (MAC={}, filter='{}')", ifName, nicName, mac, bpf);
    }

    /**
     * Розірвати прив'язку: закрити handle і прибрати з мапи.
     * Якщо не було — нічого не робимо.
     */
    public synchronized void unbind(String ifName) {
        Binding b = bindings.remove(ifName);
        if (b == null) return;

        try {
            // коректно зупинити loop має код, який його запускав;
            // тут закриваємо handle, щоб порт звільнити
            b.handle.breakLoop();
        } catch (Throwable ignored) {
        }
        try {
            b.handle.close();
        } catch (Throwable ignored) {
        }
        log.info("Unbound {} (was {})", ifName, b.nicName);
    }

    /** Отримати відкритий PcapHandle для логічного інтерфейсу */
    public PcapHandle getHandle(String ifName) {
        Binding b = bindings.get(ifName);
        return b == null ? null : b.handle;
    }

    /** Отримати MAC адрес NIC-а, до якого прив'язано логічний інтерфейс */
    public MacAddress getMac(String ifName) {
        Binding b = bindings.get(ifName);
        return b == null ? null : b.mac;
    }

    /** (Опційно) отримати назву NIC-а для логічного інтерфейсу */
    public String getNicName(String ifName) {
        Binding b = bindings.get(ifName);
        return b == null ? null : b.nicName;
    }

    /** (Опційно) змінити фільтр на льоту для конкретного ifName */
    public void setFilter(String ifName, String bpf){
        try {
            Binding b = bindings.get(ifName);
            if (b == null) throw new IllegalStateException("Not bound: " + ifName);
            b.handle.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
            log.info("Updated BPF for {} -> {}", ifName, bpf);
        }
        catch (Exception e  ) {
            e.printStackTrace();
        }
    }
}

