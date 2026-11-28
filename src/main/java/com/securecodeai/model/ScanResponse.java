package com.securecodeai.model;

import java.util.List;

public class ScanResponse {

    private int totalFindings;
    private String status;
    private List<VulnerabilityFinding> findings;

    // Getter and Setter for totalFindings
    public int getTotalFindings() {
        return totalFindings;
    }

    public void setTotalFindings(int totalFindings) {
        this.totalFindings = totalFindings;
    }

    // Getter and Setter for status
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    // Getter and Setter for findings
    public List<VulnerabilityFinding> getFindings() {
        return findings;
    }

    public void setFindings(List<VulnerabilityFinding> findings) {
        this.findings = findings;
    }
}