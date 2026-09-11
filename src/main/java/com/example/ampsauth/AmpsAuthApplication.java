package com.example.ampsauth;

import com.example.ampsauth.tools.PasswordHashTool;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point. {@code @SpringBootApplication} and {@code @ConfigurationPropertiesScan} scan from this
 * class's package, so the package root is never spelled out as a string in Java code (it is defined
 * once, as {@code base.package} in {@code pom.xml}).
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class AmpsAuthApplication {

    public static void main(String[] args) {
        if (PasswordHashTool.isRequested(args)) {
            // Hashing tool: runs entirely before Spring, so Tomcat is never started.
            System.exit(PasswordHashTool.run(args, PasswordHashTool::readFromConsole, System.out, System.err));
        }
        SpringApplication.run(AmpsAuthApplication.class, args);
    }
}
