package com.secure.ai.burp.testing.poc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

class POCResults {
    private int targetsAnalyzed;
    private int technologiesDetected;
    private int payloadsGenerated;
    private int vulnerabilitiesFound;
    private int anomaliesDetected;
    private int patternsDiscovered;
    private double overallScore;
    private Map<String, Object> detailedMetrics;
    
    public POCResults() {
        this.detailedMetrics = new ConcurrentHashMap<>();
    }
    
    // Getters and setters
    public int getTargetsAnalyzed() { return targetsAnalyzed; }
    public void setTargetsAnalyzed(int targetsAnalyzed) { this.targetsAnalyzed = targetsAnalyzed; }
    
    public int getTechnologiesDetected() { return technologiesDetected; }
    public void setTechnologiesDetected(int technologiesDetected) { this.technologiesDetected = technologiesDetected; }
    
    public int getPayloadsGenerated() { return payloadsGenerated; }
    public void setPayloadsGenerated(int payloadsGenerated) { this.payloadsGenerated = payloadsGenerated; }
    
    public int getVulnerabilitiesFound() { return vulnerabilitiesFound; }
    public void setVulnerabilitiesFound(int vulnerabilitiesFound) { this.vulnerabilitiesFound = vulnerabilitiesFound; }
    
    public int getAnomaliesDetected() { return anomaliesDetected; }
    public void setAnomaliesDetected(int anomaliesDetected) { this.anomaliesDetected = anomaliesDetected; }
    
    public int getPatternsDiscovered() { return patternsDiscovered; }
    public void setPatternsDiscovered(int patternsDiscovered) { this.patternsDiscovered = patternsDiscovered; }
    
    public double getOverallScore() { return overallScore; }
    public void setOverallScore(double overallScore) { this.overallScore = overallScore; }
    
    public Map<String, Object> getDetailedMetrics() { return detailedMetrics; }
    public void addMetric(String key, Object value) { detailedMetrics.put(key, value); }
}