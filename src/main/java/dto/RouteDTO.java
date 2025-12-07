package dto;


public class RouteDTO {
    private String destination;  // "A.B.C.D/len"
    private String outIf;
    private String nextHop;      // "A.B.C.D"

    public String getDestination() { return destination; }
    public String getOutIf() { return outIf; }
    public String getNextHop() { return nextHop; }

    public void setDestination(String destination) { this.destination = destination; }
    public void setOutIf(String outIf) { this.outIf = outIf; }
    public void setNextHop(String nextHop) { this.nextHop = nextHop; }
}
