package com.server.demo; // <-- той самий пакет, що й DemoApplication

import ARP.*;
import network.Interface;
import network.IpAddres;
import network.RouterInterfaces;
import org.pcap4j.util.MacAddress;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import ports.*;
import rib.InMemoryRib;
import rib.Rib;
import rip.RipEngine;

@Configuration
public class Config {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())                 // без CSRF для простих REST
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/**").permitAll()   // дозволити все під /api/**
                        .anyRequest().permitAll()
                )
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable());
        return http.build();

    }


    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins("http://localhost:8080");
            }
        };
    }

    @Bean
    public LinkStatusWatcher linkStatusWatcher() {
        return new LinkStatusWatcher();
    }


    @EventListener(ApplicationReadyEvent.class)
    public void onReady(ApplicationReadyEvent ev) {
        LinkStatusWatcher watcher = ev.getApplicationContext().getBean(LinkStatusWatcher.class);
        watcher.addListener(e -> System.out.println(">>> " + e));
        watcher.start();
    }

    @Bean
    public IfBindingManager ifBindingManager(LinkStatusWatcher watcher) {
        return new IfBindingManager(watcher);
    }

    @Bean
    public PacketRxLoop packetRxLoop(IfBindingManager ifbm) {
        return new PacketRxLoop(ifbm);
    }

    @Bean
    public TxSender txSender(IfBindingManager ifbm) {
        return new TxSender(ifbm);
    }

    @Bean
    public ArpCache arpCache() {
        return new ArpCache();
    }

    /** IP беремо з твоєї моделі, MAC — із IfBindingManager */
    @Bean
    public IfAddressBook ifAddressBook(IfBindingManager ifbm) {
        return new IfAddressBook() {
            @Override public IpAddres getIp(String ifName) {
                Interface ni = RouterInterfaces.get(ifName);
                return ni != null ? ni.getIpAddres() : null;
            }
            @Override public MacAddress getMac(String ifName) {
                return ifbm.getMac(ifName);
            }
        };
    }

    @Bean
    public ArpRequestScheduler arpRequestScheduler(IfAddressBook book, TxSender tx) {
        return new ArpRequestScheduler(book, tx);
    }

    @Bean
    public ProxyArpConfig proxyArpConfig() { return new ProxyArpConfig(); }

    @Bean
    public ArpEngine arpEngine(IfAddressBook ifBook,
                               ArpCache cache,
                               ArpRequestScheduler scheduler,
                               TxSender tx,
                               Rib rib,
                               ProxyArpConfig proxyCfg) {
        return new ArpEngine(ifBook, cache, scheduler, tx, rib, proxyCfg);
    }
    @Bean
    public Rib rib(){ return new InMemoryRib(); }

    @Bean
    public RipEngine ripEngine(Rib rib){
        return new RipEngine(rib);
    }

    @Bean
    public Forwarder forwarder(Rib rib, ArpEngine arpEngine, TxSender txSender, IfAddressBook ifAddressBook) {
        return new Forwarder(rib, arpEngine, txSender, ifAddressBook);
    }

}