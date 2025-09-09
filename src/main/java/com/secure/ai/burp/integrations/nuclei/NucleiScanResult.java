package com.secure.ai.burp.integrations.nuclei;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

class NucleiScanResult {
    private final String target;
    private final List<NucleiFinding> findings;
    private final boolean successful;
    private final String rawOutput;
    private final LocalDateTime scanTime;
    private final long scanDurationMs;
    
    public NucleiScanResult(String target, List<NucleiFinding> findings, boolean successful, String rawOutput) {
        this.target = target;
        this.findings = findings;
        this.successful = successful;
        this.rawOutput = rawOutput;
        this.scanTime = LocalDateTime.now();
        this.scanDurationMs = System.currentTimeMillis(); // This would be calculated properly
    }
    
    public List<NucleiFinding> getCriticalFindings() {
        return findings.stream()
                      .filter(NucleiFinding::isCritical)
                      .collect(Collectors.toList());
    }
    
    public List<NucleiFinding> getHighRiskFindings() {
        return findings.stream()
                      .filter(NucleiFinding::isHighRisk)
                      .collect(Collectors.toList());
    }
    
    public Map<String, Long> getFindingsBySeverity() {
        return findings.stream()
                      .collect(Collectors.groupingBy(
                          NucleiFinding::getSeverity,
                          Collectors.counting()
                      ));
    }
    
    public double getOverallRiskScore() {
        return findings.stream()
                      .mapToDouble(NucleiFinding::getRiskScore)
                      .average()
                      .orElse(0.0);
    }
    
    public boolean hasVulnerabilities() {
        return findings.stream().anyMatch(f -> f.getRiskScore() > 3.0);
    }
    
    public int getVulnerabilityCount() {
        return (int) findings.stream().filter(f -> f.getRiskScore() > 3.0).count();
    }
    
    // Getters
    public String getTarget() { return target; }
    public List<NucleiFinding> getFindings() { return findings; }
    public boolean isSuccessful() { return successful; }
    public String getRawOutput() { return rawOutput; }
    public LocalDateTime getScanTime() { return scanTime; }
    public long getScanDurationMs() { return scanDurationMs; }
    
    @Override
    public String toString() {
        return String.format("NucleiScanResult{target='%s', findings=%d, successful=%s, riskScore=%.2f}", 
                           target, findings.size(), successful, getOverallRiskScore());
    }
}