package Controllers;

import DHCP.DHCPEngine;
import DHCP.DhcpLeaseInfo;
import dto.ApiResponseWrapper;
import dto.ManualDhcpDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dhcp")
public class DhcpController {

    private final DHCPEngine dhcp;

    public DhcpController(DHCPEngine dhcp) {
        this.dhcp = dhcp;
    }

    @PostMapping("/manual")
    public ResponseEntity<ApiResponseWrapper<String>> addManual(@RequestBody ManualDhcpDTO req) {
        try {
            dhcp.addManualBinding(req.ifName, req.mac, req.ip);

            String msg = String.format(
                    "Manual binding added: if=%s mac=%s ip=%s",
                    req.ifName, req.mac, req.ip
            );
            return ResponseEntity.ok(new ApiResponseWrapper<>("manual_added", msg));
        }
        catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponseWrapper<>("dhcp_not_enabled", e.getMessage()));
        }
        catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponseWrapper<>("manual_add_failed", e.getMessage()));
        }
    }

    @DeleteMapping("/manual/{ifName}/{mac}")
    public ResponseEntity<ApiResponseWrapper<String>> deleteManual(
            @PathVariable String ifName,
            @PathVariable String mac
    ) {
        try {
            dhcp.removeManualBinding(ifName, mac);
            String msg = String.format("Manual binding removed: if=%s mac=%s", ifName, mac);
            return ResponseEntity.ok(new ApiResponseWrapper<>("manual_removed", msg));
        }
        catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponseWrapper<>("dhcp_not_enabled", e.getMessage()));
        }
        catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponseWrapper<>("manual_remove_failed", e.getMessage()));
        }
    }

    @GetMapping("/manual/{ifName}")
    public ResponseEntity<ApiResponseWrapper<Map<String, String>>> listManual(
            @PathVariable String ifName
    ) {
        try {
            Map<String, String> bindings = dhcp.getManualBindings(ifName);
            return ResponseEntity.ok(new ApiResponseWrapper<>("ok", bindings));
        }
        catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponseWrapper<>("dhcp_not_enabled", null));
        }
        catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponseWrapper<>("manual_list_failed", null));
        }
    }
    @GetMapping("/leases")
    public List<DhcpLeaseInfo> listAllLeases() {
        return dhcp.getAllLeases();
    }

    @GetMapping("/leases/{ifName}")
    public List<DhcpLeaseInfo> listLeasesForIf(@PathVariable String ifName) {
        return dhcp.getLeases(ifName);
    }

}
