
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

    @Test
    public void testHardcodedApiKeyDetection() {

        String sourceCode = "String apiKey = \"ABC123XYZ\";";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(1, response.getTotalFindings());
        assertEquals(
                "Hardcoded API Key",
                response.getFindings().get(0).getVulnerabilityName()
        );
    }

    @Test
    public void testHardcodedSecretDetection() {

        String sourceCode = "String secret = \"mySecret123\";";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(1, response.getTotalFindings());
        assertEquals(
                "Hardcoded Secret",
                response.getFindings().get(0).getVulnerabilityName()
        );
    }

    @Test
    public void testHardcodedTokenDetection() {

        String sourceCode = "String token = \"XYZ789\";";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(1, response.getTotalFindings());
        assertEquals(
                "Hardcoded Token",
                response.getFindings().get(0).getVulnerabilityName()
        );
    }

    @Test
    public void testCaseInsensitivePasswordDetection() {

        String sourceCode = "String PASSWORD=\"admin123\";";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(1, response.getTotalFindings());
        assertEquals(
                "Hardcoded Password",
                response.getFindings().get(0).getVulnerabilityName()
        );
    }

    @Test
    public void testSqlInjectionDetection() {

        String sourceCode =
                "String query = \"SELECT * FROM users WHERE name = '\" + userInput + \"'\";";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(1, response.getTotalFindings());
        assertEquals(
                "SQL Injection",
                response.getFindings().get(0).getVulnerabilityName()
        );
    }

    @Test
    public void testMultipleVulnerabilitiesDetection() {

        String sourceCode =
                "String password = \"admin123\";\n"
                + "String query = \"SELECT * FROM users WHERE name = '\" + userInput + \"'\";";

        ScanResponse response =
                codeAnalysisService.analyzeCode(sourceCode);

        assertEquals(2, response.getTotalFindings());

        assertEquals(
                "VULNERABILITY_DETECTED",
                response.getStatus()
        );

        assertTrue(
                response.getFindings().stream()
                        .anyMatch(f -> f.getVulnerabilityName()
                                .equals("Hardcoded Password"))
        );

        assertTrue(
                response.getFindings().stream()
                        .anyMatch(f -> f.getVulnerabilityName()
                                .equals("SQL Injection"))
        );
    }
}
