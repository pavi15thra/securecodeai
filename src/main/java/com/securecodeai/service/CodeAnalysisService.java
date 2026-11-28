
package com.securecodeai.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.securecodeai.model.ScanResponse;
import com.securecodeai.model.VulnerabilityFinding;

@Service
public class CodeAnalysisService {

    public ScanResponse analyzeCode(String sourceCode) {

        ScanResponse response = new ScanResponse();

        List<VulnerabilityFinding> findings = new ArrayList<>();

        if (sourceCode == null || sourceCode.isBlank()) {
            response.setTotalFindings(0);
            response.setStatus("INVALID_INPUT");
            response.setFindings(findings);

            return response;
        }

        if (sourceCode.contains("password =")) {

            VulnerabilityFinding finding = new VulnerabilityFinding();

            finding.setVulnerabilityName("Hardcoded Password");
            finding.setSeverity("HIGH");
            finding.setDescription(
                "A password appears to be directly written in the source code."
            );
            finding.setRecommendation(
                "Remove the hardcoded password and use environment variables or a secure secrets manager."
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
