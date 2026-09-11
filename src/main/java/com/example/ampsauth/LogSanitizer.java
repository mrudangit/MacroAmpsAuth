package com.example.ampsauth;

/**
 * Makes request-supplied strings safe for the single-line {@code key=value} log format: control
 * characters, all whitespace, Unicode line/paragraph separators, format characters (bidi overrides,
 * zero-width characters) and {@code =} are replaced by {@code _}, and the value is truncated. A value
 * therefore can never break a line, start a new line, or forge another {@code key=value} token.
 */
final class LogSanitizer {

    /** Default maximum length of a sanitised value. */
    public static final int DEFAULT_MAX_LENGTH = 128;

    private static final String NONE = "-";
    private static final String ELLIPSIS = "...";
    private static final char REPLACEMENT = '_';

    private LogSanitizer() {
    }

    /** {@code -} for null/empty; otherwise the sanitised value, truncated to {@link #DEFAULT_MAX_LENGTH}. */
    public static String clean(String value) {
        return clean(value, DEFAULT_MAX_LENGTH);
    }

    /** {@code -} for null/empty; otherwise the sanitised value, truncated to {@code maxLength} (plus {@code ...}). */
    public static String clean(String value, int maxLength) {
        if (value == null || value.isEmpty()) {
            return NONE;
        }
        StringBuilder out = new StringBuilder(Math.min(value.length(), maxLength));
        int i = 0;
        for (; i < value.length() && out.length() < maxLength; i++) {
            char c = value.charAt(i);
            out.append(unsafe(c) ? REPLACEMENT : c);
        }
        if (i < value.length()) {
            if (Character.isHighSurrogate(out.charAt(out.length() - 1))) {
                out.setLength(out.length() - 1);
            }
            out.append(ELLIPSIS);
        }
        return out.toString();
    }

    private static boolean unsafe(char c) {
        if (c == '=' || Character.isISOControl(c) || Character.isWhitespace(c) || Character.isSpaceChar(c)) {
            return true;
        }
        int type = Character.getType(c);
        return type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR
                || type == Character.FORMAT;
    }
}
