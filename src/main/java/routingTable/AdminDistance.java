package routingTable;

public enum AdminDistance {
    CONNECTED(0),
    STATIC(1),
    RIP(120);

    public final int value;
    AdminDistance (int v){
        this.value = v;
    }
}
