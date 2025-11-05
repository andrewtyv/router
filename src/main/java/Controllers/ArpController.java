package Controllers;

import ARP.ArpCache;
import ARP.ArpCache.ArpRow;
import ARP.ArpEngine;
import ARP.ProxyArpConfig;
import dto.ResolveReq;
import network.IpAddres;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.concurrent.TimeUnit;

import java.net.InetAddress;
import java.util.List;
import java.util.Locale;

@RestController
@RequestMapping("/api/arp")
public class ArpController {

    @Autowired
    private final ArpCache cache;

    @Autowired
    private final ArpEngine arp;

    private final ProxyArpConfig cfg;

    public ArpController(ArpCache cache, ArpEngine arp, ProxyArpConfig cfg) {
        this.cache = cache;
        this.arp = arp ;
        this.cfg = cfg;
    }

    @GetMapping("/table")
    public List<ArpRow> getTable(@RequestParam(required = false) String state) {
        List<ArpRow> rows = cache.snapshot();
        if (state == null || state.isBlank()) return rows;

        String s = state.toUpperCase(Locale.ROOT).trim();
        return rows.stream()
                .filter(r -> r.state.equals(s))
                .toList();
    }

    @PostMapping("/resolve")
    public ResponseEntity<?> resolve(@RequestBody ResolveReq req) {
        try {
            var ip  = new IpAddres(InetAddress.getByName(req.getIp()).getHostAddress());
            var mac = arp.resolve(req.getIfName(), ip).get(1500, TimeUnit.MILLISECONDS);
            return ResponseEntity.ok(mac == null ? "-" : mac.toString());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping(value = "/delete", consumes = {"text/plain", "application/json"})
    public ResponseEntity<?> deleteByBody(@RequestBody String body) {
        try {
            String raw = body == null ? "" : body.trim();
            // якщо прийшов JSON-рядок в лапках — знімаємо їх
            if (raw.startsWith("\"") && raw.endsWith("\"") && raw.length() >= 2) {
                raw = raw.substring(1, raw.length() - 1);
            }
            if (raw.isEmpty()) return ResponseEntity.badRequest().body("Empty IP");

            String norm = InetAddress.getByName(raw).getHostAddress(); // нормалізація
            IpAddres key = new IpAddres(norm);

            boolean existed = cache.get(key).isPresent();
            cache.remove(key);
            return ResponseEntity.ok(existed ? ("Deleted " + norm) : ("No such ARP entry: " + norm));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/enable")
    public ResponseEntity<String> setGlobal(@RequestParam boolean enabled) {
        cfg.setEnabled(enabled);
        return ResponseEntity.ok("proxy-arp global=" + enabled);
    }

    @PostMapping("/if/{ifName}/enable")
    public ResponseEntity<String> setOnIf(@PathVariable String ifName, @RequestParam boolean enabled) {
        if (enabled) cfg.enableOn(ifName); else cfg.disableOn(ifName);
        return ResponseEntity.ok("proxy-arp " + ifName + "=" + enabled);
    }

    @GetMapping("/status")
    public ResponseEntity<String> status() {
        return ResponseEntity.ok("proxy-arp global=" + cfg.isEnabled());
    }

}
