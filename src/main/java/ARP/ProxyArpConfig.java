package ARP;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;


public class ProxyArpConfig {
    private volatile boolean enabled = true;
    private final Set<String> disabledIfs = ConcurrentHashMap.newKeySet();

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean en) { this.enabled = en; }

    public void disableOn(String ifName){ disabledIfs.add(ifName); }
    public void enableOn(String ifName){ disabledIfs.remove(ifName); }
    public boolean isEnabledOn(String ifName)
    {
        return enabled && !disabledIfs.contains(ifName);
    }
}
