package Controllers;

import dto.NewInterfaceDTO;
import dto.ApiResponseWrapper;
import network.Interface;
import network.RouterInterfaces;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ports.IfBindingManager;
import ports.PacketRxLoop;
import ARP.ArpEngine;
import ports.LinkStatusWatcher;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/interfaces")
public class InterfaceController {

    private final IfBindingManager ifbm;
    private final PacketRxLoop rx;
    private final ArpEngine arp;
    private final LinkStatusWatcher watcher;

    public InterfaceController(IfBindingManager ifbm, PacketRxLoop rx, ArpEngine arp, LinkStatusWatcher watcher) {
        this.ifbm = ifbm;
        this.rx = rx;
        this.arp = arp;
        this.watcher = watcher;
        // переконайся, що десь у конфігурації ти вже викликаєш watcher.start()
    }

    @PostMapping("/add_new")
    public ResponseEntity<ApiResponseWrapper<String>> setIp(@RequestBody NewInterfaceDTO req) {
        // 1) зберегти/оновити логічний інтерфейс
        Interface existing = RouterInterfaces.get(req.name);
        if (existing != null) {
            // зупиняємо RX і розв'язуємо старий бінд перед оновленням IP/маски
            rx.stop(req.name);
            ifbm.unbind(req.name);
            RouterInterfaces.remove(req.name);
        }

        Interface ni = new Interface(req.ip, req.mask, req.name);
        RouterInterfaces.Add_Interface(ni);

        // 2) вибрати NIC
        String nic = req.nic; // ДОДАЙ це поле в NewInterfaceDTO (опційно)
        if (nic == null || nic.isBlank()) {
            // авто-вибір: перший активний enN, N>6
            Set<String> active = watcher.snapshotActiveIfaces(); // вже відфільтровані enN>6 у твоїй реалізації
            nic = active.stream().findFirst().orElse(null);
        }

        if (nic == null) {
            // немає доступних активних NIC — IP збережено, але бінд не зроблено
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponseWrapper<>("saved_no_bind", "no active NIC (enN, N>6)"));
        }

        // 3) bind → start RX
        try {
            ifbm.bind(req.name, nic);                 // відкриє pcap і поставить базовий BPF
            rx.start(req.name, arp::onEthernetFrame); // запустить loop(-1, ...)
        } catch (Exception e) {
            // якщо NIC неактивний або не дозволений — сюди
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

        String responce= new String("");
        for (String item : items) {
            responce+=item + '\n';
        }

        return ResponseEntity.ok(new ApiResponseWrapper<>("ok", responce));
    }
    @DeleteMapping("/{name}")
    public ResponseEntity<?> deleteInterface(@PathVariable String name) {
        try {
            rx.stop(name);
            ifbm.unbind(name);
            RouterInterfaces.remove(name); // твій сторедж логічних інтерфейсів
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }



}

