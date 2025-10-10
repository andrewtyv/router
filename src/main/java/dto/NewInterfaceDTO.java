package dto;

public class NewInterfaceDTO {
    public String ip;   // "10.0.0.1"
    public String mask; // "255.255.255.0"
    public String name;

    public NewInterfaceDTO() {}
    public NewInterfaceDTO(String ip, String mask, String name) { this.ip = ip; this.mask = mask;this.name = name; }
}