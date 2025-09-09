package com.secure.ai.burp.analyzers.traffic;

/**
 * Configuration for real-time traffic analyzer
 */
class TrafficAnalyzerConfig {
    private final int analysisThreads;
    private final double vulnerabilityThreshold;
    private final int maxRecentAnalyses;
    private final int maxPayloadsPerType;
    private final int maxTotalPayloads;
    private final int sessionTimeoutMinutes;
    private final boolean enableMLAnalysis;
    private final boolean enablePatternAnalysis;
    private final boolean enableContextAnalysis;
    private final boolean enablePayloadGeneration;
    private final int queueCapacity;
    private final long analysisTimeoutMs;
    
    public TrafficAnalyzerConfig(Builder builder) {
        this.analysisThreads = builder.analysisThreads;
        this.vulnerabilityThreshold = builder.vulnerabilityThreshold;
        this.maxRecentAnalyses = builder.maxRecentAnalyses;
        this.maxPayloadsPerType = builder.maxPayloadsPerType;
        this.maxTotalPayloads = builder.maxTotalPayloads;
        this.sessionTimeoutMinutes = builder.sessionTimeoutMinutes;
        this.enableMLAnalysis = builder.enableMLAnalysis;
        this.enablePatternAnalysis = builder.enablePatternAnalysis;
        this.enableContextAnalysis = builder.enableContextAnalysis;
        this.enablePayloadGeneration = builder.enablePayloadGeneration;
        this.queueCapacity = builder.queueCapacity;
        this.analysisTimeoutMs = builder.analysisTimeoutMs;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private int analysisThreads = 4;
        private double vulnerabilityThreshold = 0.7;
        private int maxRecentAnalyses = 1000;
        private int maxPayloadsPerType = 5;
        private int maxTotalPayloads = 20;
        private int sessionTimeoutMinutes = 60;
        private boolean enableMLAnalysis = true;
        private boolean enablePatternAnalysis = true;
        private boolean enableContextAnalysis = true;
        private boolean enablePayloadGeneration = true;
        private int queueCapacity = 10000;
        private long analysisTimeoutMs = 30000;
        
        public Builder withAnalysisThreads(int threads) {
            this.analysisThreads = threads;
            return this;
        }
        
        public Builder withVulnerabilityThreshold(double threshold) {
            this.vulnerabilityThreshold = threshold;
            return this;
        }
        
        public Builder withMaxRecentAnalyses(int maxAnalyses) {
            this.maxRecentAnalyses = maxAnalyses;
            return this;
        }
        
        public Builder withMaxPayloadsPerType(int maxPayloads) {
            this.maxPayloadsPerType = maxPayloads;
            return this;
        }
        
        public Builder withMaxTotalPayloads(int maxPayloads) {
            this.maxTotalPayloads = maxPayloads;
            return this;
        }
        
        public Builder withSessionTimeoutMinutes(int timeoutMinutes) {
            this.sessionTimeoutMinutes = timeoutMinutes;
            return this;
        }
        
        public Builder enableMLAnalysis(boolean enable) {
            this.enableMLAnalysis = enable;
            return this;
        }
        
        public Builder enablePatternAnalysis(boolean enable) {
            this.enablePatternAnalysis = enable;
            return this;
        }
        
        public Builder enableContextAnalysis(boolean enable) {
            this.enableContextAnalysis = enable;
            return this;
        }
        
        public Builder enablePayloadGeneration(boolean enable) {
            this.enablePayloadGeneration = enable;
            return this;
        }
        
        public Builder withQueueCapacity(int capacity) {
            this.queueCapacity = capacity;
            return this;
        }
        
        public Builder withAnalysisTimeoutMs(long timeoutMs) {
            this.analysisTimeoutMs = timeoutMs;
            return this;
        }
        
        public TrafficAnalyzerConfig build() {
            return new TrafficAnalyzerConfig(this);
        }
    }
    
    // Getters
    public int getAnalysisThreads() { return analysisThreads; }
    public double getVulnerabilityThreshold() { return vulnerabilityThreshold; }
    public int getMaxRecentAnalyses() { return maxRecentAnalyses; }
    public int getMaxPayloadsPerType() { return maxPayloadsPerType; }
    public int getMaxTotalPayloads() { return maxTotalPayloads; }
    public int getSessionTimeoutMinutes() { return sessionTimeoutMinutes; }
    public boolean isMLAnalysisEnabled() { return enableMLAnalysis; }
    public boolean isPatternAnalysisEnabled() { return enablePatternAnalysis; }
    public boolean isContextAnalysisEnabled() { return enableContextAnalysis; }
    public boolean isPayloadGenerationEnabled() { return enablePayloadGeneration; }
    public int getQueueCapacity() { return queueCapacity; }
    public long getAnalysisTimeoutMs() { return analysisTimeoutMs; }
}