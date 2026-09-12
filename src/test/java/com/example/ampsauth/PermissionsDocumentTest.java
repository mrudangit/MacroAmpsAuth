package com.example.ampsauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PermissionsDocumentTest {

    private static final String DEFAULT_TEMPLATE = "classpath:amps/permissions-logon-only.json";

    private final ResourceLoader resourceLoader = new DefaultResourceLoader();

    @Test
    void loadsTheDefaultTemplate() {
        PermissionsDocument document = new PermissionsDocument(DEFAULT_TEMPLATE, resourceLoader);

        JsonNode root = JsonMapper.builder().build().readTree(document.bytes());
        assertThat(root.get("logon").booleanValue()).isTrue();
        assertThat(root.get("replication-logon").booleanValue()).isFalse();
        assertThat(document.location()).isEqualTo(DEFAULT_TEMPLATE);
    }

    @Test
    void servesTheExactBytesOfTheResource() throws IOException {
        byte[] expected = new ClassPathResource("amps/permissions-logon-only.json").getContentAsByteArray();

        PermissionsDocument document = new PermissionsDocument(DEFAULT_TEMPLATE, resourceLoader);

        assertThat(document.bytes()).isEqualTo(expected);
    }

    @Test
    void returnedBytesAreACopy() {
        PermissionsDocument document = new PermissionsDocument(DEFAULT_TEMPLATE, resourceLoader);

        byte[] first = document.bytes();
        first[0] = 'X';

        assertThat(document.bytes()[0]).isEqualTo((byte) '{');
    }

    @Test
    void invalidJsonResourceFailsStartup() {
        assertThatThrownBy(() -> new PermissionsDocument("classpath:amps-test/invalid.json", resourceLoader))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not valid JSON")
                .hasMessageContaining("amps-test/invalid.json");
    }

    @Test
    void trailingGarbageIsInvalid(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("doc.json");
        Files.writeString(file, "{\"logon\": true} trailing", StandardCharsets.UTF_8);

        assertThatThrownBy(() -> new PermissionsDocument(file.toUri().toString(), resourceLoader))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not valid JSON");
    }

    @Test
    void nonObjectJsonIsRejected(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("doc.json");
        Files.writeString(file, "[true]", StandardCharsets.UTF_8);

        assertThatThrownBy(() -> new PermissionsDocument(file.toUri().toString(), resourceLoader))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JSON object");
    }

    @Test
    void emptyFileIsRejected(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("doc.json");
        Files.writeString(file, "", StandardCharsets.UTF_8);

        assertThatThrownBy(() -> new PermissionsDocument(file.toUri().toString(), resourceLoader))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void missingResourceFailsStartup() {
        assertThatThrownBy(() -> new PermissionsDocument("classpath:amps/does-not-exist.json", resourceLoader))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not found")
                .hasMessageContaining("does-not-exist.json");
    }

    @Test
    void blankLocationFailsStartup() {
        assertThatThrownBy(() -> new PermissionsDocument(" ", resourceLoader))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("amps.permissions.template");
    }

    @Test
    void fileResourceIsServedVerbatim(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("custom.json");
        String content = "{\"logon\":true,\"topic\":[{\"topic\":\"orders\",\"read\":true,\"write\":false}]}\n";
        Files.writeString(file, content, StandardCharsets.UTF_8);

        PermissionsDocument document = new PermissionsDocument("file:" + file.toAbsolutePath(), resourceLoader);

        assertThat(new String(document.bytes(), StandardCharsets.UTF_8)).isEqualTo(content);
    }
}
