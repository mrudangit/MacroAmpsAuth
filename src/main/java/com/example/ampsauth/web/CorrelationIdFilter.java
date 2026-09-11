package com.example.ampsauth.web;

import java.io.IOException;

import com.example.ampsauth.auth.LogSanitizer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Per-request hygiene for every response of the service:
 * <ul>
 *   <li>{@code X-AMPS-Correlation-Id} request header -> echoed back verbatim as the same response
 *       header, and put (sanitised and bounded to {@value #MDC_MAX_LENGTH} characters) into the MDC
 *       under {@code ampsCorrelationId}, which the console log pattern prints as {@code corr=...}</li>
 *   <li>{@code Cache-Control: no-store} on every response</li>
 * </ul>
 */
@Component
public class CorrelationIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-AMPS-Correlation-Id";
    public static final String MDC_KEY = "ampsCorrelationId";
    public static final int MDC_MAX_LENGTH = 256;
    private static final String NO_STORE = "no-store";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader(HttpHeaders.CACHE_CONTROL, NO_STORE);
        String correlationId = correlationId(request);
        if (correlationId != null) {
            MDC.put(MDC_KEY, LogSanitizer.clean(correlationId, MDC_MAX_LENGTH));
            response.setHeader(HEADER, correlationId);
        }
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }

    private static String correlationId(HttpServletRequest request) {
        String value = request.getHeader(HEADER);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }
}
