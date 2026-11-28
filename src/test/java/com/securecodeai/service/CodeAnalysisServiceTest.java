package com.securecodeai.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import com.securecodeai.model.ScanResponse;
import com.securecodeai.model.VulnerabilityFinding;

public class CodeAnalysisServiceTest {

    private final CodeAnalysisService codeAnalysisService =
            new CodeAnalysisService();

    @Test
    public void testHardcodedPasswordDetection() {

        String sourceCode = "String password = \"admin123\";";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(1, response.getTotalFindings());
        assertEquals("VULNERABILITY_DETECTED", response.getStatus());

        VulnerabilityFinding finding = response.getFindings().get(0);

        assertEquals("Hardcoded Password", finding.getVulnerabilityName());
        assertEquals("HIGH", finding.getSeverity());
    }

    @Test
    public void testSafeCode() {

        String sourceCode =
                "public class Hello { System.out.println(\"Hello\"); }";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(0, response.getTotalFindings());
        assertEquals("NO_VULNERABILITIES_FOUND", response.getStatus());
        assertTrue(response.getFindings().isEmpty());
    }

    @Test
    public void testEmptyInput() {

        ScanResponse response =
                codeAnalysisService.analyzeCode("");

        assertEquals(0, response.getTotalFindings());
        assertEquals("INVALID_INPUT", response.getStatus());
        assertTrue(response.getFindings().isEmpty());
    }

    @Test
    public void testNullInput() {

        ScanResponse response =
                codeAnalysisService.analyzeCode(null);

        assertEquals(0, response.getTotalFindings());
        assertEquals("INVALID_INPUT", response.getStatus());
        assertTrue(response.getFindings().isEmpty());
    }
}