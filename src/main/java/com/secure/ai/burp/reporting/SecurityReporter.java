package com.secure.ai.burp.reporting;

import burp.api.montoya.MontoyaApi;
import com.secure.ai.burp.scanner.VulnerabilityScanner;
import java.util.*;

public class SecurityReporter {
    private final MontoyaApi api;
    
    public SecurityReporter(MontoyaApi api) {
        this.api = api;
    }
    
    public void reportFindings(List<VulnerabilityScanner.ScanResult> results) {
        // Report security findings to Burp Suite
        for (VulnerabilityScanner.ScanResult result : results) {
            if (result.isVulnerable()) {
                api.logging().logToOutput("[VULNERABILITY] " + result.getVulnerabilityType());
            }
        }
    }
}