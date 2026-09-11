package com.example.ampsauth.config;

import com.example.ampsauth.permissions.PermissionsDocument;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

/** Loads the permissions document from {@code amps.permissions.template} once, at startup. */
@Configuration(proxyBeanMethods = false)
public class PermissionsConfiguration {

    @Bean
    PermissionsDocument permissionsDocument(AmpsProperties properties, ResourceLoader resourceLoader) {
        return new PermissionsDocument(properties.permissions().template(), resourceLoader);
    }
}
