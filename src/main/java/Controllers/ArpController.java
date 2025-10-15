package Controllers;

import ARP.ArpCache;
import ARP.ArpCache.ArpRow;
import ARP.ArpEngine;
import dto.ResolveReq;
import network.IpAddres;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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

    public ArpController(ArpCache cache, ArpEngine arp) {
        this.cache = cache;
        this.arp = arp ;
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

}
