// Controllers/StaticRoutesController.java
package Controllers;

import dto.ApiResponseWrapper;
import dto.RDto;
import dto.RouteDTO;
import network.Interface;
import network.IpAddres;
import network.RouterInterfaces;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rib.Rib;
import routingTable.AdminDistance;
import routingTable.Proto;
import routingTable.RouteEntry;

import java.util.List;

@RestController
@RequestMapping("/api/routes")
public class RoutesController {

    private final Rib rib;

    public RoutesController(Rib rib) {
        this.rib = rib;
    }
    @GetMapping("/get_all")
    public List<RDto> routes(){
        return rib.snapshot().stream().map(dto.RDto::from).toList();
    }

    @PostMapping("/add_static")
    public ResponseEntity<?> add(@RequestBody RouteDTO dto) {
        try {
            IpAddres.Cidr cidr = IpAddres.parseCidr(dto.getDestination());
            IpAddres net = cidr.address.networkAddress(cidr.prefix);

            boolean hasOutIf  = dto.getOutIf() != null && !dto.getOutIf().isBlank();
            boolean hasNextHop = dto.getNextHop() != null && !dto.getNextHop().isBlank();
            if (!hasOutIf && !hasNextHop) {
                System.out.println("hereio");
                return ResponseEntity.badRequest()
                        .body(new ApiResponseWrapper<>("err", "need outIf and/or nextHop"));
            }

            IpAddres nh = hasNextHop ? new IpAddres(dto.getNextHop()) : null;
            String outIf = hasOutIf ? dto.getOutIf() : inferOutIfFromNextHop(nh);

            if (outIf == null) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponseWrapper<>("err", "cannot infer outIf for nextHop " + nh));
            }

            RouteEntry re = RouteEntry.builder()
                    .network(net)
                    .length(cidr.prefix)
                    .outIf(outIf)
                    .nextHop(nh)
                    .metric(0)
                    .ad(AdminDistance.STATIC)
                    .proto(Proto.STATIC)
                    .build();

            rib.upsertStatic(net, cidr.prefix, outIf, nh);
            return ResponseEntity.ok(new ApiResponseWrapper<>("ok", re.toString()));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new ApiResponseWrapper<>("err", e.getMessage()));
        }
    }

    @DeleteMapping("/delete_route")
    public ResponseEntity<?> remove(@RequestParam String destination) {
        try {
            IpAddres.Cidr cidr = IpAddres.parseCidr(destination);
            IpAddres net = cidr.address.networkAddress(cidr.prefix);
            rib.removeStatic(net, cidr.prefix);
            return ResponseEntity.ok(new ApiResponseWrapper<>("ok", "removed " + net.getIp()+"/"+cidr.prefix));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new ApiResponseWrapper<>("err", e.getMessage()));
        }
    }

    private String inferOutIfFromNextHop(IpAddres nextHop) {
        if (nextHop == null) return null;

        var best = rib.lookup(nextHop);
        if (best.isPresent() && best.get().proto() == Proto.CONNECTED) {
            return best.get().outIf();
        }

        return RouterInterfaces.getAll().stream()
                .filter(ifc -> {
                    int len = IpAddres.prefixFromMask(new IpAddres(ifc.getIpMask().toString()));
                    return nextHop.inSubnet(new IpAddres(ifc.getIpAddres().toString()).networkAddress(len), len);
                })
                .map(Interface::getName)
                .findFirst()
                .orElse(null);
    }
}
