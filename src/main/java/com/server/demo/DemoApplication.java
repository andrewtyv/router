package com.server.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import ports.LinkStatusWatcher;

@SpringBootApplication(
		scanBasePackages = {
				"com.server.demo", // сам застосунок
				"Controllers",     // твій контролер тут
				"network",         // сервіси/сховища
				"dto",
				"util",
				"ports",
				"ARP"
		}
)

public class DemoApplication {


	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);

	}
}
