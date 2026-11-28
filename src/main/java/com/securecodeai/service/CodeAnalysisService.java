
package com.securecodeai.service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

import com.securecodeai.model.ScanResponse;
import com.securecodeai.model.VulnerabilityFinding;

@Service
public class CodeAnalysisService {

    private static final Pattern CREDENTIAL_PATTERN = Pattern.compile(
        "(?i)\\b(password|passwd|pwd|api[_-]?key|secret|token)\\b\\s*=\\s*(['\"])[^'\"]+['\"]"
    );

    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "(?i)(SELECT|UPDATE|DELETE|INSERT)\\b[^;\\n]*\\+\\s*[a-zA-Z_$][a-zA-Z0-9_$]*"
    );

    public ScanResponse analyzeCode(String sourceCode) {

        ScanResponse response = new ScanResponse();

        List<VulnerabilityFinding> findings = new ArrayList<>();

        if (sourceCode == null || sourceCode.isBlank()) {
            response.setTotalFindings(0);
            response.setStatus("INVALID_INPUT");
            response.setFindings(findings);

            return response;
        }

        // Detect hardcoded credentials

        Matcher matcher = CREDENTIAL_PATTERN.matcher(sourceCode);

        while (matcher.find()) {

            String credentialType = matcher.group(1).toLowerCase();

            VulnerabilityFinding finding = new VulnerabilityFinding();

            if (credentialType.contains("password")
                    || credentialType.equals("passwd")
                    || credentialType.equals("pwd")) {

                finding.setVulnerabilityName("Hardcoded Password");

            } else if (credentialType.contains("api")) {

                finding.setVulnerabilityName("Hardcoded API Key");

            } else if (credentialType.equals("secret")) {

                finding.setVulnerabilityName("Hardcoded Secret");

            } else {

                finding.setVulnerabilityName("Hardcoded Token");
            }

            finding.setSeverity("HIGH");

            finding.setDescription(
                "A hardcoded credential appears to be directly written in the source code."
            );

            finding.setRecommendation(
                "Remove hardcoded credentials and use environment variables or a secure secrets manager."
            );

            findings.add(finding);
        }

        // Detect potential SQL Injection

        Matcher sqlMatcher = SQL_INJECTION_PATTERN.matcher(sourceCode);

        while (sqlMatcher.find()) {

            VulnerabilityFinding finding = new VulnerabilityFinding();

            finding.setVulnerabilityName("SQL Injection");

            finding.setSeverity("HIGH");

            finding.setDescription(
                "A SQL statement appears to be concatenated with a variable, "
                + "which may allow untrusted input to alter the SQL query."
            );

            finding.setRecommendation(
                "Use prepared statements with parameterized queries instead of "
                + "concatenating user input directly into SQL statements."
            );

            findings.add(finding);
        }

        response.setTotalFindings(findings.size());
        response.setFindings(findings);

        if (findings.isEmpty()) {
            response.setStatus("NO_VULNERABILITIES_FOUND");
        } else {
            response.setStatus("VULNERABILITY_DETECTED");
        }

        return response;
    }
}
