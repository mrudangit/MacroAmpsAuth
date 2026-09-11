package com.example.ampsauth;

import java.util.concurrent.atomic.AtomicReference;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CorrelationIdFilterTest {

    private final CorrelationIdFilter filter = new CorrelationIdFilter();

    private MockHttpServletResponse run(MockHttpServletRequest request, AtomicReference<String> mdcDuringRequest)
            throws ServletException, java.io.IOException {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> mdcDuringRequest.set(MDC.get(CorrelationIdFilter.MDC_KEY));
        filter.doFilter(request, response, chain);
        return response;
    }

    @Test
    void correlationIdIsEchoedVerbatimAndPutInMdcOnlyForTheRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/amps/v1/permissions/trader1");
        request.addHeader(CorrelationIdFilter.HEADER, "corr-42");
        AtomicReference<String> mdc = new AtomicReference<>();

        MockHttpServletResponse response = run(request, mdc);

        assertThat(mdc.get()).isEqualTo("corr-42");
        assertThat(MDC.get(CorrelationIdFilter.MDC_KEY)).isNull();
        assertThat(response.getHeader(CorrelationIdFilter.HEADER)).isEqualTo("corr-42");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    void longIdIsEchoedVerbatimButBoundedInTheMdc() throws Exception {
        String id = "c".repeat(400);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/amps/v1/permissions");
        request.addHeader(CorrelationIdFilter.HEADER, id);
        AtomicReference<String> mdc = new AtomicReference<>();

        MockHttpServletResponse response = run(request, mdc);

        assertThat(response.getHeader(CorrelationIdFilter.HEADER)).isEqualTo(id);
        assertThat(mdc.get()).hasSize(CorrelationIdFilter.MDC_MAX_LENGTH + 3).endsWith("...");
    }

    @Test
    void mdcValueIsSanitised() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/amps/v1/permissions");
        request.addHeader(CorrelationIdFilter.HEADER, "abc\ndef corr=forged");
        AtomicReference<String> mdc = new AtomicReference<>();

        run(request, mdc);

        assertThat(mdc.get()).isEqualTo("abc_def_corr_forged");
    }

    @Test
    void missingOrBlankHeaderIsNotEchoed() throws Exception {
        AtomicReference<String> mdc = new AtomicReference<>();
        MockHttpServletResponse response = run(new MockHttpServletRequest("GET", "/actuator/health"), mdc);
        assertThat(mdc.get()).isNull();
        assertThat(response.getHeader(CorrelationIdFilter.HEADER)).isNull();
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");

        MockHttpServletRequest blank = new MockHttpServletRequest("GET", "/actuator/health");
        blank.addHeader(CorrelationIdFilter.HEADER, "   ");
        response = run(blank, mdc);
        assertThat(response.getHeader(CorrelationIdFilter.HEADER)).isNull();
    }

    @Test
    void mdcIsClearedEvenWhenTheChainThrows() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/amps/v1/permissions");
        request.addHeader(CorrelationIdFilter.HEADER, "corr-boom");
        FilterChain failing = (req, res) -> {
            throw new ServletException("boom");
        };

        assertThatThrownBy(() -> filter.doFilter(request, new MockHttpServletResponse(), failing))
                .isInstanceOf(ServletException.class);
        assertThat(MDC.get(CorrelationIdFilter.MDC_KEY)).isNull();
    }
}
