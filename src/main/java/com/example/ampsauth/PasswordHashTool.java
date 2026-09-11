package com.example.ampsauth;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;

/**
 * {@code java -jar amps-auth-service.jar --hash-password} prints a {@code {bcrypt}...} value for
 * {@code amps.auth.inmemory.users[].password} and exits without starting the web server.
 * {@code --hash-password=<value>} skips the prompt (for scripting; beware of shell history).
 */
public final class PasswordHashTool {

    public static final String OPTION = "--hash-password";
    private static final String PROMPT = "Password to hash: ";

    /** Where the password comes from when it is not given on the command line. */
    @FunctionalInterface
    public interface PasswordSource {
        /** @return the password, or {@code null} if none could be read */
        char[] read();
    }

    private PasswordHashTool() {
    }

    /** True if {@code args} contain {@code --hash-password} or {@code --hash-password=...}. */
    public static boolean isRequested(String[] args) {
        if (args == null) {
            return false;
        }
        for (String arg : args) {
            if (OPTION.equals(arg) || arg.startsWith(OPTION + "=")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Runs the tool.
     *
     * @return the process exit code: 0 on success (hash printed to {@code out}), 1 otherwise
     */
    public static int run(String[] args, PasswordSource source, PrintStream out, PrintStream err) {
        char[] password = null;
        try {
            String inline = inlineValue(args);
            password = inline != null ? inline.toCharArray() : source.read();
            if (password == null || password.length == 0) {
                err.println("error: no password given (empty passwords are not allowed)");
                return 1;
            }
            String encoded;
            try {
                encoded = PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(new String(password));
            } catch (IllegalArgumentException e) {
                // bcrypt hashes at most 72 bytes; never echo the value itself
                err.println("error: bcrypt supports passwords of at most 72 bytes (UTF-8); choose a shorter one");
                return 1;
            }
            out.println(encoded);
            return 0;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /** Interactive source: {@link Console#readPassword} when attached to a terminal, else one stdin line. */
    public static char[] readFromConsole() {
        Console console = System.console();
        if (console != null && isTerminal(console)) {
            return console.readPassword(PROMPT);
        }
        System.err.print(PROMPT + "(no terminal detected; input is not hidden) ");
        System.err.flush();
        try {
            String line = new BufferedReader(new InputStreamReader(System.in, Charset.defaultCharset())).readLine();
            return line == null ? null : line.toCharArray();
        } catch (IOException e) {
            return null;
        }
    }

    private static String inlineValue(String[] args) {
        if (args == null) {
            return null;
        }
        for (String arg : args) {
            if (arg.startsWith(OPTION + "=")) {
                return arg.substring(OPTION.length() + 1);
            }
        }
        return null;
    }

    /**
     * {@code Console.isTerminal()} exists from Java 22 (where {@code System.console()} may be non-null
     * even without a terminal); on Java 21 a non-null Console implies a terminal.
     */
    private static boolean isTerminal(Console console) {
        try {
            Method isTerminal = Console.class.getMethod("isTerminal");
            return Boolean.TRUE.equals(isTerminal.invoke(console));
        } catch (NoSuchMethodException e) {
            return true;
        } catch (ReflectiveOperationException e) {
            return true;
        }
    }
}
