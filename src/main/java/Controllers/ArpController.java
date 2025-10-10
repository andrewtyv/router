package Controllers;

import ARP.ArpCache;
import ARP.ArpCache.ArpRow;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Locale;

@RestController
@RequestMapping("/api/arp")
public class ArpController {

    private final ArpCache cache;

    public ArpController(ArpCache cache) {
        this.cache = cache;
    }

    /** GET /api/arp  (опційно: ?state=REACHABLE|STALE|INCOMPLETE|FAILED) */
    @GetMapping("/table")
    public List<ArpRow> getTable(@RequestParam(required = false) String state) {
        List<ArpRow> rows = cache.snapshot();
        if (state == null || state.isBlank()) return rows;

        String s = state.toUpperCase(Locale.ROOT).trim();
        return rows.stream()
                .filter(r -> r.state.equals(s))
                .toList();
    }
}
