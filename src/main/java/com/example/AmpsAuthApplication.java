package com.example;

import com.example.ampsauth.PasswordHashTool;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Standalone runner. It lives one package above the feature package {@code com.example.ampsauth},
 * so that folder is a self-contained feature that can be copied into another application without
 * bringing a second {@code @SpringBootApplication} along. Component scanning starts from this class's
 * package and therefore covers the feature package; nothing else is wired here.
 * <p>
 * A host application that wants the {@code --hash-password} tool copies the two lines below into
 * its own {@code main}.
 */
@SpringBootApplication
public class AmpsAuthApplication {

    public static void main(String[] args) {
        if (PasswordHashTool.isRequested(args)) {
            // Hashing tool: runs entirely before Spring, so Tomcat is never started.
            System.exit(PasswordHashTool.run(args, PasswordHashTool::readFromConsole, System.out, System.err));
        }
        SpringApplication.run(AmpsAuthApplication.class, args);
    }
}
