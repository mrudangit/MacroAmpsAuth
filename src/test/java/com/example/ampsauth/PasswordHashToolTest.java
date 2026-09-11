package com.example.ampsauth;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordHashToolTest {

    private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    private final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    private final ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    private final PrintStream out = new PrintStream(stdout, true, StandardCharsets.UTF_8);
    private final PrintStream err = new PrintStream(stderr, true, StandardCharsets.UTF_8);

    private String stdout() {
        return stdout.toString(StandardCharsets.UTF_8);
    }

    private String stderr() {
        return stderr.toString(StandardCharsets.UTF_8);
    }

    @Test
    void detectsTheOptionWithAndWithoutValue() {
        assertThat(PasswordHashTool.isRequested(new String[] {"--hash-password"})).isTrue();
        assertThat(PasswordHashTool.isRequested(new String[] {"--spring.profiles.active=local", "--hash-password=x"})).isTrue();
        assertThat(PasswordHashTool.isRequested(new String[] {"--spring.profiles.active=local"})).isFalse();
        assertThat(PasswordHashTool.isRequested(new String[] {"--hash-passwords"})).isFalse();
        assertThat(PasswordHashTool.isRequested(new String[0])).isFalse();
        assertThat(PasswordHashTool.isRequested(null)).isFalse();
    }

    @Test
    void inlineValueIsHashedWithBcryptInDelegatingFormat() {
        int exit = PasswordHashTool.run(new String[] {"--hash-password=Tr4der!:pass"}, () -> null, out, err);

        assertThat(exit).isZero();
        String printed = stdout().strip();
        assertThat(printed).startsWith("{bcrypt}$2");
        assertThat(printed).doesNotContain("Tr4der");
        assertThat(encoder.matches("Tr4der!:pass", printed)).isTrue();
        assertThat(encoder.matches("wrong", printed)).isFalse();
        assertThat(stderr()).isEmpty();
    }

    @Test
    void promptedValueIsHashed() {
        int exit = PasswordHashTool.run(new String[] {"--hash-password"}, () -> "prompted".toCharArray(), out, err);

        assertThat(exit).isZero();
        assertThat(encoder.matches("prompted", stdout().strip())).isTrue();
    }

    @Test
    void emptyOrUnavailablePasswordFails() {
        assertThat(PasswordHashTool.run(new String[] {"--hash-password="}, () -> null, out, err)).isEqualTo(1);
        assertThat(PasswordHashTool.run(new String[] {"--hash-password"}, () -> null, out, err)).isEqualTo(1);
        assertThat(PasswordHashTool.run(new String[] {"--hash-password"}, () -> new char[0], out, err)).isEqualTo(1);

        assertThat(stdout()).isEmpty();
        assertThat(stderr()).contains("empty passwords are not allowed");
    }

    @Test
    void passwordLongerThanBcryptLimitFailsCleanly() {
        int exit = PasswordHashTool.run(new String[] {"--hash-password=" + "a".repeat(73)}, () -> null, out, err);

        assertThat(exit).isEqualTo(1);
        assertThat(stdout()).isEmpty();
        assertThat(stderr()).contains("72 bytes").doesNotContain("aaaa");
    }

    @Test
    void passwordAtTheBcryptLimitIsHashed() {
        String password = "b".repeat(72);

        int exit = PasswordHashTool.run(new String[] {"--hash-password=" + password}, () -> null, out, err);

        assertThat(exit).isZero();
        assertThat(encoder.matches(password, stdout().strip())).isTrue();
    }

    @Test
    void eachRunProducesADifferentSaltButBothVerify() {
        PasswordHashTool.run(new String[] {"--hash-password=same"}, () -> null, out, err);
        String first = stdout().strip();
        stdout.reset();
        PasswordHashTool.run(new String[] {"--hash-password=same"}, () -> null, out, err);
        String second = stdout().strip();

        assertThat(first).isNotEqualTo(second);
        assertThat(encoder.matches("same", first)).isTrue();
        assertThat(encoder.matches("same", second)).isTrue();
    }
}
