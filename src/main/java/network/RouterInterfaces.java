package network;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public  class RouterInterfaces {
    static final Map<String, Interface> interfaces = new ConcurrentHashMap<>();

    public static Collection<Interface> getAll() {
        return interfaces.values();
    }
    public static boolean Add_Interface(Interface a){

        return interfaces.putIfAbsent(a.getName(), a) == null;
        
    }
    public static Interface get(String name) {
        return interfaces.get(name);
    }
    public static void remove(String name){
        interfaces.remove(name);
    }





}
