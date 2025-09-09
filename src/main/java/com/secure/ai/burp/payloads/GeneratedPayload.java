package com.secure.ai.burp.payloads;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class GeneratedPayload {
    private final String payload;
    private final String vulnerabilityType;
    private final String generationMethod;
    private final LocalDateTime createdAt;
    private final PayloadContext context;
    
    // Scoring
    private double effectivenessScore;
    private double contextRelevanceScore;
    private double finalScore;
    private double actualEffectiveness = -1.0; // Set after testing
    
    // Metadata
    private final Map<String, Object> metadata;
    private String targetParameter;
    private String targetLocation; // header, body, url, etc.
    private boolean requiresEncoding;
    private String encodingType;
    
    // Testing results
    private boolean wasTested = false;
    private boolean wasSuccessful = false;
    private String testResult;
    private LocalDateTime testedAt;
    
    public GeneratedPayload(String payload, String vulnerabilityType, String generationMethod, 
                           double effectivenessScore, PayloadContext context) {
        this.payload = payload;
        this.vulnerabilityType = vulnerabilityType;
        this.generationMethod = generationMethod;
        this.effectivenessScore = effectivenessScore;
        this.context = context;
        this.createdAt = LocalDateTime.now();
        this.metadata = new ConcurrentHashMap<>();
        this.finalScore = effectivenessScore;
    }
    
    // Builder pattern for complex payload creation
    public static class Builder {
        private String payload;
        private String vulnerabilityType;
        private String generationMethod = "unknown";
        private double effectivenessScore = 0.5;
        private PayloadContext context;
        private String targetParameter;
        private String targetLocation = "parameter";
        private boolean requiresEncoding = false;
        private String encodingType = "none";
        private final Map<String, Object> metadata = new ConcurrentHashMap<>();
        
        public Builder(String payload, String vulnerabilityType, PayloadContext context) {
            this.payload = payload;
            this.vulnerabilityType = vulnerabilityType;
            this.context = context;
        }
        
        public Builder generationMethod(String method) {
            this.generationMethod = method;
            return this;
        }
        
        public Builder effectivenessScore(double score) {
            this.effectivenessScore = score;
            return this;
        }
        
        public Builder targetParameter(String parameter) {
            this.targetParameter = parameter;
            return this;
        }
        
        public Builder targetLocation(String location) {
            this.targetLocation = location;
            return this;
        }
        
        public Builder requiresEncoding(boolean requires, String encodingType) {
            this.requiresEncoding = requires;
            this.encodingType = encodingType;
            return this;
        }
        
        public Builder addMetadata(String key, Object value) {
            this.metadata.put(key, value);
            return this;
        }
        
        public GeneratedPayload build() {
            GeneratedPayload payload = new GeneratedPayload(this.payload, this.vulnerabilityType, 
                                                          this.generationMethod, this.effectivenessScore, 
                                                          this.context);
            payload.targetParameter = this.targetParameter;
            payload.targetLocation = this.targetLocation;
            payload.requiresEncoding = this.requiresEncoding;
            payload.encodingType = this.encodingType;
            payload.metadata.putAll(this.metadata);
            return payload;
        }
    }
    
    public String getEncodedPayload() {
        if (!requiresEncoding) {
            return payload;
        }
        
        switch (encodingType.toLowerCase()) {
            case "url":
                return urlEncode(payload);
            case "html":
                return htmlEncode(payload);
            case "base64":
                return base64Encode(payload);
            case "unicode":
                return unicodeEncode(payload);
            default:
                return payload;
        }
    }
    
    private String urlEncode(String input) {
        try {
            return java.net.URLEncoder.encode(input, "UTF-8");
        } catch (Exception e) {
            return input;
        }
    }
    
    private String htmlEncode(String input) {
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;");
    }
    
    private String base64Encode(String input) {
        return java.util.Base64.getEncoder().encodeToString(input.getBytes());
    }
    
    private String unicodeEncode(String input) {
        StringBuilder encoded = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c > 127) {
                encoded.append("\\u").append(String.format("%04x", (int) c));
            } else {
                encoded.append(c);
            }
        }
        return encoded.toString();
    }
    
    public void markTested(boolean successful, String result) {
        this.wasTested = true;
        this.wasSuccessful = successful;
        this.testResult = result;
        this.testedAt = LocalDateTime.now();
    }
    
    public void setActualEffectiveness(double effectiveness) {
        this.actualEffectiveness = effectiveness;
        
        // Update final score based on actual results
        if (effectiveness >= 0) {
            this.finalScore = (effectivenessScore * 0.3) + (effectiveness * 0.7);
        }
    }
    
    public boolean isHighPriority() {
        return finalScore >= 0.7 && contextRelevanceScore >= 0.6;
    }
    
    public boolean isMediumPriority() {
        return finalScore >= 0.4 && finalScore < 0.7;
    }
    
    public boolean isLowPriority() {
        return finalScore < 0.4;
    }
    
    public PayloadRisk getRiskLevel() {
        if (finalScore >= 0.8) return PayloadRisk.CRITICAL;
        if (finalScore >= 0.6) return PayloadRisk.HIGH;
        if (finalScore >= 0.4) return PayloadRisk.MEDIUM;
        if (finalScore >= 0.2) return PayloadRisk.LOW;
        return PayloadRisk.INFO;
    }
    
    public boolean isRelevantForContext() {
        return contextRelevanceScore >= 0.5;
    }
    
    public String getFormattedPayload() {
        StringBuilder formatted = new StringBuilder();
        formatted.append("Payload: ").append(payload).append("\n");
        formatted.append("Type: ").append(vulnerabilityType).append("\n");
        formatted.append("Method: ").append(generationMethod).append("\n");
        formatted.append("Score: ").append(String.format("%.3f", finalScore)).append("\n");
        formatted.append("Target: ").append(targetParameter != null ? targetParameter : "generic").append("\n");
        
        if (requiresEncoding) {
            formatted.append("Encoded: ").append(getEncodedPayload()).append("\n");
        }
        
        if (wasTested) {
            formatted.append("Tested: ").append(wasSuccessful ? "SUCCESS" : "FAILED").append("\n");
            if (testResult != null) {
                formatted.append("Result: ").append(testResult).append("\n");
            }
        }
        
        return formatted.toString();
    }
    
    // Getters and Setters
    public String getPayload() { return payload; }
    public String getVulnerabilityType() { return vulnerabilityType; }
    public String getGenerationMethod() { return generationMethod; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public PayloadContext getContext() { return context; }
    
    public double getEffectivenessScore() { return effectivenessScore; }
    public void setEffectivenessScore(double effectivenessScore) { this.effectivenessScore = effectivenessScore; }
    
    public double getContextRelevanceScore() { return contextRelevanceScore; }
    public void setContextRelevanceScore(double contextRelevanceScore) { this.contextRelevanceScore = contextRelevanceScore; }
    
    public double getFinalScore() { return finalScore; }
    public void setFinalScore(double finalScore) { this.finalScore = finalScore; }
    
    public double getActualEffectiveness() { return actualEffectiveness; }
    
    public Map<String, Object> getMetadata() { return new ConcurrentHashMap<>(metadata); }
    public void addMetadata(String key, Object value) { metadata.put(key, value); }
    public Object getMetadata(String key) { return metadata.get(key); }
    
    public String getTargetParameter() { return targetParameter; }
    public void setTargetParameter(String targetParameter) { this.targetParameter = targetParameter; }
    
    public String getTargetLocation() { return targetLocation; }
    public void setTargetLocation(String targetLocation) { this.targetLocation = targetLocation; }
    
    public boolean requiresEncoding() { return requiresEncoding; }
    public void setRequiresEncoding(boolean requiresEncoding) { this.requiresEncoding = requiresEncoding; }
    
    public String getEncodingType() { return encodingType; }
    public void setEncodingType(String encodingType) { this.encodingType = encodingType; }
    
    public boolean wasTested() { return wasTested; }
    public boolean wasSuccessful() { return wasSuccessful; }
    public String getTestResult() { return testResult; }
    public LocalDateTime getTestedAt() { return testedAt; }
    
    @Override
    public String toString() {
        return String.format("GeneratedPayload{type='%s', method='%s', score=%.3f, payload='%s'}", 
                           vulnerabilityType, generationMethod, finalScore, 
                           payload.length() > 50 ? payload.substring(0, 50) + "..." : payload);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        GeneratedPayload that = (GeneratedPayload) obj;
        return payload.equals(that.payload) && vulnerabilityType.equals(that.vulnerabilityType);
    }
    
    @Override
    public int hashCode() {
        return payload.hashCode() + vulnerabilityType.hashCode();
    }
    
    public enum PayloadRisk {
        CRITICAL(9.0, 10.0, "Critical"),
        HIGH(7.0, 8.9, "High"),
        MEDIUM(4.0, 6.9, "Medium"),
        LOW(1.0, 3.9, "Low"),
        INFO(0.0, 0.9, "Info");
        
        private final double minScore;
        private final double maxScore;
        private final String displayName;
        
        PayloadRisk(double minScore, double maxScore, String displayName) {
            this.minScore = minScore;
            this.maxScore = maxScore;
            this.displayName = displayName;
        }
        
        public double getMinScore() { return minScore; }
        public double getMaxScore() { return maxScore; }
        public String getDisplayName() { return displayName; }
    }
}