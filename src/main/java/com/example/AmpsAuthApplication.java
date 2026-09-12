package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Standalone runner. It lives one package above the feature package {@code com.example.ampsauth},
 * so that folder is a self-contained feature that can be copied into another application without
 * bringing a second {@code @SpringBootApplication} along. Component scanning starts from this class's
 * package and therefore covers the feature package; nothing else is wired here.
 */
@SpringBootApplication
public class AmpsAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AmpsAuthApplication.class, args);
    }
}
