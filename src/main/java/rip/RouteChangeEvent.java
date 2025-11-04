package rip;


import routingTable.RouteEntry;

import java.util.List;

import java.util.Objects;

public class RouteChangeEvent {
    private final List<RouteEntry> addedOrUpdated;
    private final List<RouteEntry> removed;

    public RouteChangeEvent(List<RouteEntry> addedOrUpdated, List<RouteEntry> removed) {
        this.addedOrUpdated = Objects.requireNonNull(addedOrUpdated, "addedOrUpdated");
        this.removed = Objects.requireNonNull(removed, "removed");
    }

    public List<RouteEntry> getAddedOrUpdated() { return addedOrUpdated; }
    public List<RouteEntry> getRemoved() { return removed; }
}
