package network;
import util.*;

public class IpMask {

    private Integer o1;
    private Integer o2;
    private Integer o3;
    private Integer o4;

    public IpMask(String mask){
        int tmp[] =  Parser.parseIpv4(mask);
        this.o1= tmp[0];
        this.o2 = tmp[1];
        this.o3 = tmp[2];
        this.o4 = tmp[3];
    }

    public IpMask (int o1, int o2, int o3, int o4){
        this.o1= o1;
        this.o2 = o2;
        this.o3 = o3;
        this.o4 = o4;
    }


    public String get_Mask(){
        return (o1.toString() + "." + o2.toString() + "." + o3.toString() + "." + o4.toString());
    }

    public void setO1(Integer o1) {
        this.o1 = o1;
    }

    public void setO2(Integer o2) {
        this.o2 = o2;
    }

    public void setO3(Integer o3) {
        this.o3 = o3;
    }

    public void setO4(Integer o4) {
        this.o4 = o4;
    }


}
