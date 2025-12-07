package dto;

public class ResolveReq {
    private String ifName;
    private String ip;

    public ResolveReq() {}

    public ResolveReq(String ifName, String ip) {
        this.ifName = ifName;
        this.ip = ip;
    }

    public String getIfName() {
        return ifName;
    }

    public void setIfName(String ifName) {
        this.ifName = ifName;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    @Override
    public String toString() {
        return "ResolveReq{" +
                "ifName='" + ifName + '\'' +
                ", ip='" + ip + '\'' +
                '}';
    }
}
