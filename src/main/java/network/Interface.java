package network;

public class Interface {
    private IpAddres ipAddres;
    private IpMask ipMask;
    private String name;

    public Interface(IpAddres ipAddres, IpMask ipMask,String name ){
        this.ipAddres=ipAddres;
        this.ipMask = ipMask;
        this.name = name;

    }
    public Interface (String ipAddres , String ipMask, String name){
        this.ipAddres = new IpAddres(ipAddres);
        this.ipMask = new IpMask(ipMask);
        this.name = name;

    }

    public IpMask getIpMask() {
        return ipMask;
    }

    public IpAddres getIpAddres() {
        return ipAddres;
    }

    public String getName() {
        return name;
    }


    @Override
    public String toString(){
        return this.ipAddres.getIp() + " " +  this.ipMask.get_Mask() + " " +  this.name;
    }

    public void setIpAddres(IpAddres ipAddres) {
        this.ipAddres = ipAddres;
    }

    public void setIpMask(IpMask ipMask) {
        this.ipMask = ipMask;
    }

    public void setName(String name) {
        this.name = name;
    }

}
