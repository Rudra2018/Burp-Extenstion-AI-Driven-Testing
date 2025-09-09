package com.secure.ai.burp.detectors.anomaly;

/**
 * Configuration for anomaly detection engine
 */
class AnomalyDetectionConfig {
    private final int baselineUpdateInterval; // minutes
    private final int correlationInterval; // minutes
    private final double alertThreshold; // 0.0 - 1.0
    private final int maxActiveAlerts;
    private final boolean enableRealTimeMonitoring;
    private final boolean enableBehavioralAnalysis;
    private final boolean enableThreatIntelligence;
    private final boolean enablePatternDetection;
    private final int historyRetentionDays;
    private final double statisticalSensitivity; // 0.0 - 1.0
    
    public AnomalyDetectionConfig(Builder builder) {
        this.baselineUpdateInterval = builder.baselineUpdateInterval;
        this.correlationInterval = builder.correlationInterval;
        this.alertThreshold = builder.alertThreshold;
        this.maxActiveAlerts = builder.maxActiveAlerts;
        this.enableRealTimeMonitoring = builder.enableRealTimeMonitoring;
        this.enableBehavioralAnalysis = builder.enableBehavioralAnalysis;
        this.enableThreatIntelligence = builder.enableThreatIntelligence;
        this.enablePatternDetection = builder.enablePatternDetection;
        this.historyRetentionDays = builder.historyRetentionDays;
        this.statisticalSensitivity = builder.statisticalSensitivity;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private int baselineUpdateInterval = 15;
        private int correlationInterval = 5;
        private double alertThreshold = 0.7;
        private int maxActiveAlerts = 100;
        private boolean enableRealTimeMonitoring = true;
        private boolean enableBehavioralAnalysis = true;
        private boolean enableThreatIntelligence = true;
        private boolean enablePatternDetection = true;
        private int historyRetentionDays = 30;
        private double statisticalSensitivity = 0.8;
        
        public Builder withBaselineUpdateInterval(int minutes) {
            this.baselineUpdateInterval = minutes;
            return this;
        }
        
        public Builder withCorrelationInterval(int minutes) {
            this.correlationInterval = minutes;
            return this;
        }
        
        public Builder withAlertThreshold(double threshold) {
            this.alertThreshold = threshold;
            return this;
        }
        
        public Builder withMaxActiveAlerts(int maxAlerts) {
            this.maxActiveAlerts = maxAlerts;
            return this;
        }
        
        public Builder enableRealTimeMonitoring(boolean enable) {
            this.enableRealTimeMonitoring = enable;
            return this;
        }
        
        public Builder enableBehavioralAnalysis(boolean enable) {
            this.enableBehavioralAnalysis = enable;
            return this;
        }
        
        public Builder enableThreatIntelligence(boolean enable) {
            this.enableThreatIntelligence = enable;
            return this;
        }
        
        public Builder enablePatternDetection(boolean enable) {
            this.enablePatternDetection = enable;
            return this;
        }
        
        public Builder withHistoryRetentionDays(int days) {
            this.historyRetentionDays = days;
            return this;
        }
        
        public Builder withStatisticalSensitivity(double sensitivity) {
            this.statisticalSensitivity = sensitivity;
            return this;
        }
        
        public AnomalyDetectionConfig build() {
            return new AnomalyDetectionConfig(this);
        }
    }
    
    // Getters
    public int getBaselineUpdateInterval() { return baselineUpdateInterval; }
    public int getCorrelationInterval() { return correlationInterval; }
    public double getAlertThreshold() { return alertThreshold; }
    public int getMaxActiveAlerts() { return maxActiveAlerts; }
    public boolean isRealTimeMonitoringEnabled() { return enableRealTimeMonitoring; }
    public boolean isBehavioralAnalysisEnabled() { return enableBehavioralAnalysis; }
    public boolean isThreatIntelligenceEnabled() { return enableThreatIntelligence; }
    public boolean isPatternDetectionEnabled() { return enablePatternDetection; }
    public int getHistoryRetentionDays() { return historyRetentionDays; }
    public double getStatisticalSensitivity() { return statisticalSensitivity; }
}