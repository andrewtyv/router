package Controllers;

import dto.NewInterfaceDTO;
import dto.ApiResponseWrapper;
import network.Interface;
import network.RouterInterfaces;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import ports.*;
import ARP.ArpEngine;
import rib.Rib;
import rip.RipEngine;   // <<< додали

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/interfaces")
public class InterfaceController {

    private final IfBindingManager ifbm;
    private final PacketRxLoop rx;
    private final ArpEngine arp;
    private final RipEngine rip;
    private final LinkStatusWatcher watcher;
    private final Rib rib;
    private final Forwarder fwd;


    public InterfaceController(
            IfBindingManager ifbm,
            PacketRxLoop rx,
            ArpEngine arp,
            RipEngine rip,
            LinkStatusWatcher watcher,
            Rib rib,
            Forwarder fwd
    ) {
        this.ifbm = ifbm;
        this.rx = rx;
        this.arp = arp;
        this.rip = rip;
        this.watcher = watcher;
        this.rib = rib;
        this.fwd = fwd;

    }

    @PostMapping("/add_new")
    public ResponseEntity<ApiResponseWrapper<String>> setIp(@RequestBody NewInterfaceDTO req) {
        // 1) оновити логічний інтерфейс
        Interface existing = RouterInterfaces.get(req.name);
        if (existing != null) {
            // зупиняємо RX і розв’язуємо старий бінд перед оновленням IP/маски
            rx.stop(req.name);
            ifbm.unbind(req.name);
            RouterInterfaces.remove(req.name);
        }

        Interface ni = new Interface(req.ip, req.mask, req.name);
        RouterInterfaces.Add_Interface(ni);

        // 2) вибір NIC
        String nic = req.nic;
        if (nic == null || nic.isBlank()) {
            Set<String> active = watcher.snapshotActiveIfaces();
            nic = active.stream().findFirst().orElse(null);
        }

        if (nic == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponseWrapper<>("saved_no_bind", "no active NIC available"));
        }

        // 3) bind → start RX
        try {
            ifbm.bind(req.name, nic);

            DemuxPacketHandler demux = new DemuxPacketHandler(arp, rip, fwd);
            rx.start(req.name, demux); // запустить loop(-1, ...)
            var ip    = new network.IpAddres(req.ip);
            var mask  = new network.IpAddres(req.mask);            // mask "255.255.255.0"
            int len   = network.IpAddres.prefixFromMask(mask);     // 24
            var net   = ip.networkAddress(len);                    // 192.168.1.0

            rib.upsertConnected(net, len, req.name);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponseWrapper<>("bind_failed", e.getMessage()));
        }

        return ResponseEntity.ok(new ApiResponseWrapper<>("saved_and_bound", req.name + " -> " + nic));
    }

    @GetMapping("/get_intf")
    public ResponseEntity<ApiResponseWrapper<String>> getIntf() {
        List<String> items = RouterInterfaces.getAll()
                .stream()
                .map(Interface::toString)
                .toList();

        StringBuilder sb = new StringBuilder();
        for (String item : items) sb.append(item).append('\n');

        return ResponseEntity.ok(new ApiResponseWrapper<>("ok", sb.toString()));
    }

    @DeleteMapping("/{name}")
    public ResponseEntity<?> deleteInterface(@PathVariable String name) {
        try {

                var intf = RouterInterfaces.get(name);
                if (intf != null) {
                    var ip = new network.IpAddres(intf.getIpAddres().toString());
                    var mask = new network.IpAddres(intf.getIpMask().toString());
                    int len = network.IpAddres.prefixFromMask(mask);
                    var net = ip.networkAddress(len);

                    rib.removeConnected(net, len);
                    rx.stop(name);
                    ifbm.unbind(name);
                    RouterInterfaces.remove(name);
                    return ResponseEntity.ok().build();
                }
            } catch(Exception e){
                return ResponseEntity.badRequest().body(e.getMessage());
            }
        return ResponseEntity.ok().body("ok");
    }
}
