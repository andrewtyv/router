package Controllers;

import DHCP.DHCPEngine;
import DHCP.DhcpMode;
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
import rip.RipEngine;

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
    private final DHCPEngine dhcp;


    public InterfaceController(
            IfBindingManager ifbm,
            PacketRxLoop rx,
            ArpEngine arp,
            RipEngine rip,
            LinkStatusWatcher watcher,
            Rib rib,
            Forwarder fwd,
            DHCPEngine dhcp
    ) {
        this.ifbm = ifbm;
        this.rx = rx;
        this.arp = arp;
        this.rip = rip;
        this.watcher = watcher;
        this.rib = rib;
        this.fwd = fwd;
        this.dhcp = dhcp;

    }

    @PostMapping("/add_new")
    public ResponseEntity<ApiResponseWrapper<String>> setIp(@RequestBody NewInterfaceDTO req) {
        Interface existing = RouterInterfaces.get(req.name);
        if (existing != null) {
            rx.stop(req.name);
            ifbm.unbind(req.name);
            RouterInterfaces.remove(req.name);
        }

        Interface ni = new Interface(req.ip, req.mask, req.name);
        RouterInterfaces.Add_Interface(ni);

        String nic = req.nic;
        if (nic == null || nic.isBlank()) {
            Set<String> active = watcher.snapshotActiveIfaces();
            nic = active.stream().findFirst().orElse(null);
        }

        if (nic == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponseWrapper<>("saved_no_bind", "no active NIC available"));
        }

        try {
            ifbm.bind(req.name, nic);

            DemuxPacketHandler demux = new DemuxPacketHandler(arp, rip, fwd, dhcp);
            rx.start(req.name, demux);
            var ip    = new network.IpAddres(req.ip);
            var mask  = new network.IpAddres(req.mask);
            int len   = network.IpAddres.prefixFromMask(mask);
            var net   = ip.networkAddress(len);

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
    @PostMapping("/{name}/rip/enable")
    public ResponseEntity<ApiResponseWrapper<String>> enableRip(@PathVariable String name) {
        Interface intf = RouterInterfaces.get(name);
        if (intf == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponseWrapper<>("no_such_interface", "Interface " + name + " not found"));
        }

        try {
            var ifIp = new network.IpAddres(intf.getIpAddres().toString());

            var ifMac = ifbm.getMac(name);          // MacAddress
            var txHandle = ifbm.getHandle(name);  // PcapHandle

            if (ifMac == null || txHandle == null) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(new ApiResponseWrapper<>(
                                "rip_enable_failed",
                                "no MAC or txHandle for interface " + name + " (is it bound?)"
                        ));
            }

            rip.enableOnInterface(name, ifMac, ifIp);
            return ResponseEntity.ok(
                    new ApiResponseWrapper<>("rip_enabled", "RIP enabled on " + name)
            );
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseWrapper<>("rip_enable_error", e.getMessage()));
        }
    }

    @PostMapping("/{name}/rip/disable")
    public ResponseEntity<ApiResponseWrapper<String>> disableRip(@PathVariable String name) {
        Interface intf = RouterInterfaces.get(name);
        if (intf == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponseWrapper<>("no_such_interface", "Interface " + name + " not found"));
        }

        rip.disableOnInterface(name);
        return ResponseEntity.ok(
                new ApiResponseWrapper<>("rip_disabled", "RIP disabled on " + name)
        );
    }
    @PostMapping("/{name}/dhcp/enable")
    public ResponseEntity<ApiResponseWrapper<String>> enableDhcp(@PathVariable String name, @RequestParam("mode") String modeStr) {
        Interface intf = RouterInterfaces.get(name);
        if (intf == null) {
            System.out.println("no such intf \n");
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponseWrapper<>("no_such_interface", "Interface " + name + " not found"));
        }

        DhcpMode mode;
        try {
            mode = DhcpMode.valueOf(modeStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.out.println("here 1 \n");

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponseWrapper<>(
                            "invalid_mode",
                            "mode must be one of: manual, automatic, dynamic"
                    ));
        }

        try {
            var ifIp   = new network.IpAddres(intf.getIpAddres().toString());
            var ifMask = new network.IpMask(intf.getIpMask().toString());

            int ipInt   = ifIp.toInt();
            int maskInt = ifMask.toInt();

            int netInt  = ipInt & maskInt;
            int bcastInt = netInt | ~maskInt;

            int startInt = netInt + 10;
            int endInt   = bcastInt - 1;

            if (startInt >= endInt) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponseWrapper<>(
                                "pool_too_small",
                                "Cannot build DHCP pool on " + name + " (subnet too small)"
                        ));
            }

            var poolStart = new network.IpAddres(intToStr(startInt));
            var poolEnd   = new network.IpAddres(intToStr(endInt));
            var gateway   = ifIp;

            dhcp.addServer(name, poolStart, poolEnd, ifMask, gateway, mode);

            return ResponseEntity.ok(
                    new ApiResponseWrapper<>(
                            "dhcp_enabled",
                            String.format(
                                    "DHCP (%s) enabled on %s, pool %s - %s",
                                    mode, name, poolStart, poolEnd
                            )
                    )
            );

        } catch (Exception e) {
            System.out.println("here 3 \n");
            e.printStackTrace();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponseWrapper<>("dhcp_enable_error", e.getMessage()));
        }

    }
    @PostMapping("/{name}/dhcp/disable")
    public ResponseEntity<ApiResponseWrapper<String>> disableDhcp(@PathVariable String name) {
        Interface intf = RouterInterfaces.get(name);
        if (intf == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponseWrapper<>("no_such_interface", "Interface " + name + " not found"));
        }

        dhcp.removeServer(name);
        return ResponseEntity.ok(
                new ApiResponseWrapper<>("dhcp_disabled", "DHCP disabled on " + name)
        );
    }


    private static String intToStr(int v) {
        int b1 = (v >>> 24) & 0xFF;
        int b2 = (v >>> 16) & 0xFF;
        int b3 = (v >>> 8)  & 0xFF;
        int b4 = v & 0xFF;
        return b1 + "." + b2 + "." + b3 + "." + b4;
    }

}

