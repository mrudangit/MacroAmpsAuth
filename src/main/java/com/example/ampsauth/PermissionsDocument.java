package com.example.ampsauth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The permissions document returned to AMPS on a successful logon. Loaded exactly once at startup
 * from {@code amps.permissions.template} (a Spring resource location such as {@code classpath:...}
 * or {@code file:...}); startup fails if the resource is missing or is not a JSON object. The bytes
 * are served verbatim. Created as a bean by {@link AmpsAuthConfiguration}.
 */
class PermissionsDocument {

    private static final Logger log = LoggerFactory.getLogger(PermissionsDocument.class);

    private final String location;
    private final byte[] bytes;

    /**
     * @param location       a Spring resource location ({@code classpath:...}, {@code file:...})
     * @param resourceLoader the loader used to resolve it
     * @throws IllegalStateException if the resource is missing, unreadable or not a JSON object
     */
    public PermissionsDocument(String location, ResourceLoader resourceLoader) {
        this.location = location;
        this.bytes = load(location, resourceLoader);
        log.info("permissions document loaded from {} ({} bytes)", location, bytes.length);
    }

    /** The exact bytes of the template (a fresh copy). */
    public byte[] bytes() {
        return bytes.clone();
    }

    /** Where the document was loaded from. */
    public String location() {
        return location;
    }

    private static byte[] load(String location, ResourceLoader resourceLoader) {
        if (location == null || location.isBlank()) {
            throw new IllegalStateException("amps.permissions.template must not be empty");
        }
        Resource resource = resourceLoader.getResource(location);
        if (!resource.exists()) {
            throw new IllegalStateException("permissions template not found: " + location
                    + " (amps.permissions.template)");
        }
        byte[] content;
        try (InputStream in = resource.getInputStream()) {
            content = in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("permissions template could not be read: " + location, e);
        }
        validate(content, location);
        return content;
    }

    private static void validate(byte[] content, String location) {
        JsonNode root;
        try {
            root = JsonMapper.builder()
                    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .build()
                    .readTree(content);
        } catch (JacksonException e) {
            throw new IllegalStateException("permissions template is not valid JSON: " + location
                    + " (" + e.getOriginalMessage() + ")", e);
        }
        if (root == null || root.isMissingNode() || !root.isObject()) {
            throw new IllegalStateException("permissions template must be a JSON object: " + location);
        }
        JsonNode logon = root.get("logon");
        if (logon == null || !logon.isBoolean() || !logon.booleanValue()) {
            log.warn("permissions template {} does not contain a true \"logon\" flag; every authenticated "
                    + "logon will be refused by AMPS", location);
        }
        if (log.isDebugEnabled()) {
            log.debug("permissions template content: {}", new String(content, StandardCharsets.UTF_8));
        }
    }
}
