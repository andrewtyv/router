package rib;

import rip.RouteChangeEvent;

public interface RibListener {
    void onRouteChange(RouteChangeEvent evt);
}