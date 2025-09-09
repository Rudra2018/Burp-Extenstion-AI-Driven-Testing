package com.secure.ai.burp.models.data;

import com.secure.ai.burp.models.ml.*;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

// Main result class for real-time traffic analysis
@JsonIgnoreProperties(ignoreUnknown = true)
class RealTimeAnalysisResult {
    @JsonProperty("request_id")
    private String requestId;
    
    @JsonProperty("session_id") 
    private String sessionId;
    
    @JsonProperty("timestamp")
    private LocalDateTime timestamp;
    
    @JsonProperty("anomaly_result")
    private MultiLayerAnomalyResult anomalyResult;
    
    @JsonProperty("ml_predictions")
    private List<VulnerabilityPrediction> mlPredictions;
    
    @JsonProperty("correlated_vulnerabilities")
    private List<CorrelatedVulnerability> correlatedVulnerabilities;
    
    @JsonProperty("adaptive_test_cases")
    private List<AdaptiveTestCase> adaptiveTestCases;
    
    @JsonProperty("generated_payloads")
    private List<GeneratedPayload> generatedPayloads;
    
    @JsonProperty("application_context")
    private ApplicationContext applicationContext;
    
    @JsonProperty("session_context")
    private SessionContext sessionContext;
    
    @JsonProperty("security_assessment")
    private SecurityAssessment securityAssessment;
    
    @JsonProperty("recommendations")
    private List<String> recommendations;
    
    @JsonProperty("processing_time_ms")
    private long processingTimeMs;
    
    @JsonProperty("overall_risk_score")
    private double overallRiskScore;
    
    @JsonProperty("has_vulnerabilities")
    private boolean hasVulnerabilities;
    
    @JsonProperty("performance_metrics")
    private Map<String, Object> performanceMetrics;
    
    public RealTimeAnalysisResult() {}
    
    public RealTimeAnalysisResult(String requestId, String sessionId, LocalDateTime timestamp,
                                 MultiLayerAnomalyResult anomalyResult, List<VulnerabilityPrediction> mlPredictions,
                                 List<CorrelatedVulnerability> correlatedVulnerabilities, List<AdaptiveTestCase> adaptiveTestCases,
                                 List<GeneratedPayload> generatedPayloads, ApplicationContext applicationContext,
                                 SessionContext sessionContext, SecurityAssessment securityAssessment,
                                 List<String> recommendations, long processingTimeMs, double overallRiskScore,
                                 boolean hasVulnerabilities, Map<String, Object> performanceMetrics) {
        this.requestId = requestId;
        this.sessionId = sessionId;
        this.timestamp = timestamp;
        this.anomalyResult = anomalyResult;
        this.mlPredictions = mlPredictions != null ? new ArrayList<>(mlPredictions) : new ArrayList<>();
        this.correlatedVulnerabilities = correlatedVulnerabilities != null ? new ArrayList<>(correlatedVulnerabilities) : new ArrayList<>();
        this.adaptiveTestCases = adaptiveTestCases != null ? new ArrayList<>(adaptiveTestCases) : new ArrayList<>();
        this.generatedPayloads = generatedPayloads != null ? new ArrayList<>(generatedPayloads) : new ArrayList<>();
        this.applicationContext = applicationContext;
        this.sessionContext = sessionContext;
        this.securityAssessment = securityAssessment;
        this.recommendations = recommendations != null ? new ArrayList<>(recommendations) : new ArrayList<>();
        this.processingTimeMs = processingTimeMs;
        this.overallRiskScore = overallRiskScore;
        this.hasVulnerabilities = hasVulnerabilities;
        this.performanceMetrics = performanceMetrics != null ? new HashMap<>(performanceMetrics) : new HashMap<>();
    }
    
    // Getters and setters
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public MultiLayerAnomalyResult getAnomalyResult() { return anomalyResult; }
    public void setAnomalyResult(MultiLayerAnomalyResult anomalyResult) { this.anomalyResult = anomalyResult; }
    
    public List<VulnerabilityPrediction> getMlPredictions() { return mlPredictions; }
    public void setMlPredictions(List<VulnerabilityPrediction> mlPredictions) { this.mlPredictions = mlPredictions; }
    
    public List<CorrelatedVulnerability> getCorrelatedVulnerabilities() { return correlatedVulnerabilities; }
    public void setCorrelatedVulnerabilities(List<CorrelatedVulnerability> correlatedVulnerabilities) { this.correlatedVulnerabilities = correlatedVulnerabilities; }
    
    public List<AdaptiveTestCase> getAdaptiveTestCases() { return adaptiveTestCases; }
    public void setAdaptiveTestCases(List<AdaptiveTestCase> adaptiveTestCases) { this.adaptiveTestCases = adaptiveTestCases; }
    
    public List<GeneratedPayload> getGeneratedPayloads() { return generatedPayloads; }
    public void setGeneratedPayloads(List<GeneratedPayload> generatedPayloads) { this.generatedPayloads = generatedPayloads; }
    
    public ApplicationContext getApplicationContext() { return applicationContext; }
    public void setApplicationContext(ApplicationContext applicationContext) { this.applicationContext = applicationContext; }
    
    public SessionContext getSessionContext() { return sessionContext; }
    public void setSessionContext(SessionContext sessionContext) { this.sessionContext = sessionContext; }
    
    public SecurityAssessment getSecurityAssessment() { return securityAssessment; }
    public void setSecurityAssessment(SecurityAssessment securityAssessment) { this.securityAssessment = securityAssessment; }
    
    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
    
    public long getProcessingTimeMs() { return processingTimeMs; }
    public void setProcessingTimeMs(long processingTimeMs) { this.processingTimeMs = processingTimeMs; }
    
    public double getOverallRiskScore() { return overallRiskScore; }
    public void setOverallRiskScore(double overallRiskScore) { this.overallRiskScore = overallRiskScore; }
    
    public boolean hasVulnerabilities() { return hasVulnerabilities; }
    public void setHasVulnerabilities(boolean hasVulnerabilities) { this.hasVulnerabilities = hasVulnerabilities; }
    
    public Map<String, Object> getPerformanceMetrics() { return performanceMetrics; }
    public void setPerformanceMetrics(Map<String, Object> performanceMetrics) { this.performanceMetrics = performanceMetrics; }
}

// Vulnerability prediction from ML models
@JsonIgnoreProperties(ignoreUnknown = true)
class VulnerabilityPrediction {
    @JsonProperty("type")
    private String type;
    
    @JsonProperty("confidence")
    private double confidence;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    @JsonProperty("detection_method")
    private String detectionMethod;
    
    @JsonProperty("severity")
    private String severity;
    
    public VulnerabilityPrediction() {
        this.metadata = new HashMap<>();
    }
    
    public VulnerabilityPrediction(String type, double confidence, String description, Map<String, Object> metadata) {
        this();
        this.type = type;
        this.confidence = confidence;
        this.description = description;
        this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
        this.detectionMethod = "ML_MODEL";
        this.severity = calculateSeverity(type, confidence);
    }
    
    private String calculateSeverity(String type, double confidence) {
        if (confidence >= 0.9) return "CRITICAL";
        if (confidence >= 0.7) return "HIGH";
        if (confidence >= 0.5) return "MEDIUM";
        return "LOW";
    }
    
    // Getters and setters
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    
    public String getDetectionMethod() { return detectionMethod; }
    public void setDetectionMethod(String detectionMethod) { this.detectionMethod = detectionMethod; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
}

// Correlated vulnerability from multiple detection sources
@JsonIgnoreProperties(ignoreUnknown = true)
class CorrelatedVulnerability {
    @JsonProperty("type")
    private String type;
    
    @JsonProperty("predictions")
    private List<VulnerabilityPrediction> predictions;
    
    @JsonProperty("supporting_indicators")
    private List<AnomalyIndicator> supportingIndicators;
    
    @JsonProperty("correlation_confidence")
    private double correlationConfidence;
    
    @JsonProperty("correlation_evidence")
    private Map<String, Object> correlationEvidence;
    
    @JsonProperty("impact_assessment")
    private String impactAssessment;
    
    @JsonProperty("mitigation_recommendations")
    private List<String> mitigationRecommendations;
    
    @JsonProperty("exploitation_likelihood")
    private String exploitationLikelihood;
    
    public CorrelatedVulnerability() {}
    
    public CorrelatedVulnerability(String type, List<VulnerabilityPrediction> predictions,
                                  List<AnomalyIndicator> supportingIndicators, double correlationConfidence,
                                  Map<String, Object> correlationEvidence, String impactAssessment,
                                  List<String> mitigationRecommendations) {
        this.type = type;
        this.predictions = predictions != null ? new ArrayList<>(predictions) : new ArrayList<>();
        this.supportingIndicators = supportingIndicators != null ? new ArrayList<>(supportingIndicators) : new ArrayList<>();
        this.correlationConfidence = correlationConfidence;
        this.correlationEvidence = correlationEvidence != null ? new HashMap<>(correlationEvidence) : new HashMap<>();
        this.impactAssessment = impactAssessment;
        this.mitigationRecommendations = mitigationRecommendations != null ? new ArrayList<>(mitigationRecommendations) : new ArrayList<>();
        this.exploitationLikelihood = calculateExploitationLikelihood(correlationConfidence, impactAssessment);
    }
    
    private String calculateExploitationLikelihood(double confidence, String impact) {
        if (confidence >= 0.8 && ("CRITICAL".equals(impact) || "HIGH".equals(impact))) return "HIGH";
        if (confidence >= 0.6) return "MEDIUM";
        return "LOW";
    }
    
    // Getters and setters
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public List<VulnerabilityPrediction> getPredictions() { return predictions; }
    public void setPredictions(List<VulnerabilityPrediction> predictions) { this.predictions = predictions; }
    
    public List<AnomalyIndicator> getSupportingIndicators() { return supportingIndicators; }
    public void setSupportingIndicators(List<AnomalyIndicator> supportingIndicators) { this.supportingIndicators = supportingIndicators; }
    
    public double getCorrelationConfidence() { return correlationConfidence; }
    public void setCorrelationConfidence(double correlationConfidence) { this.correlationConfidence = correlationConfidence; }
    
    public Map<String, Object> getCorrelationEvidence() { return correlationEvidence; }
    public void setCorrelationEvidence(Map<String, Object> correlationEvidence) { this.correlationEvidence = correlationEvidence; }
    
    public String getImpactAssessment() { return impactAssessment; }
    public void setImpactAssessment(String impactAssessment) { this.impactAssessment = impactAssessment; }
    
    public List<String> getMitigationRecommendations() { return mitigationRecommendations; }
    public void setMitigationRecommendations(List<String> mitigationRecommendations) { this.mitigationRecommendations = mitigationRecommendations; }
    
    public String getExploitationLikelihood() { return exploitationLikelihood; }
    public void setExploitationLikelihood(String exploitationLikelihood) { this.exploitationLikelihood = exploitationLikelihood; }
}

// Generated payload for testing
@JsonIgnoreProperties(ignoreUnknown = true)
class GeneratedPayload {
    @JsonProperty("payload")
    private String payload;
    
    @JsonProperty("target_vulnerability")
    private String targetVulnerability;
    
    @JsonProperty("score")
    private double score;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    @JsonProperty("generation_timestamp")
    private LocalDateTime generationTimestamp;
    
    @JsonProperty("encoding_type")
    private String encodingType;
    
    @JsonProperty("complexity_level")
    private String complexityLevel;
    
    public GeneratedPayload() {
        this.metadata = new HashMap<>();
    }
    
    public GeneratedPayload(String payload, String targetVulnerability, double score, 
                           Map<String, Object> metadata, LocalDateTime generationTimestamp) {
        this();
        this.payload = payload;
        this.targetVulnerability = targetVulnerability;
        this.score = score;
        this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
        this.generationTimestamp = generationTimestamp;
        this.encodingType = detectEncodingType(payload);
        this.complexityLevel = calculateComplexityLevel(payload);
    }
    
    private String detectEncodingType(String payload) {
        if (payload.contains("%")) return "URL_ENCODED";
        if (payload.contains("&lt;") || payload.contains("&gt;")) return "HTML_ENCODED";
        if (payload.contains("\\x")) return "HEX_ENCODED";
        return "PLAIN";
    }
    
    private String calculateComplexityLevel(String payload) {
        if (payload.length() > 200) return "HIGH";
        if (payload.length() > 100) return "MEDIUM";
        return "LOW";
    }
    
    // Getters and setters
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    
    public String getTargetVulnerability() { return targetVulnerability; }
    public void setTargetVulnerability(String targetVulnerability) { this.targetVulnerability = targetVulnerability; }
    
    public double getScore() { return score; }
    public void setScore(double score) { this.score = score; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    
    public LocalDateTime getGenerationTimestamp() { return generationTimestamp; }
    public void setGenerationTimestamp(LocalDateTime generationTimestamp) { this.generationTimestamp = generationTimestamp; }
    
    public String getEncodingType() { return encodingType; }
    public void setEncodingType(String encodingType) { this.encodingType = encodingType; }
    
    public String getComplexityLevel() { return complexityLevel; }
    public void setComplexityLevel(String complexityLevel) { this.complexityLevel = complexityLevel; }
}

// Adaptive test case
@JsonIgnoreProperties(ignoreUnknown = true)
class AdaptiveTestCase {
    @JsonProperty("vulnerability_type")
    private String vulnerabilityType;
    
    @JsonProperty("confidence_score")
    private double confidenceScore;
    
    @JsonProperty("test_payloads")
    private List<GeneratedPayload> testPayloads;
    
    @JsonProperty("test_parameters")
    private Map<String, Object> testParameters;
    
    @JsonProperty("validation_criteria")
    private List<String> validationCriteria;
    
    @JsonProperty("test_metadata")
    private Map<String, Object> testMetadata;
    
    @JsonProperty("priority")
    private String priority;
    
    public AdaptiveTestCase() {}
    
    public AdaptiveTestCase(String vulnerabilityType, double confidenceScore, List<GeneratedPayload> testPayloads,
                           Map<String, Object> testParameters, List<String> validationCriteria,
                           Map<String, Object> testMetadata) {
        this.vulnerabilityType = vulnerabilityType;
        this.confidenceScore = confidenceScore;
        this.testPayloads = testPayloads != null ? new ArrayList<>(testPayloads) : new ArrayList<>();
        this.testParameters = testParameters != null ? new HashMap<>(testParameters) : new HashMap<>();
        this.validationCriteria = validationCriteria != null ? new ArrayList<>(validationCriteria) : new ArrayList<>();
        this.testMetadata = testMetadata != null ? new HashMap<>(testMetadata) : new HashMap<>();
        this.priority = calculatePriority(confidenceScore);
    }
    
    private String calculatePriority(double confidence) {
        if (confidence >= 0.8) return "HIGH";
        if (confidence >= 0.6) return "MEDIUM";
        return "LOW";
    }
    
    // Getters and setters
    public String getVulnerabilityType() { return vulnerabilityType; }
    public void setVulnerabilityType(String vulnerabilityType) { this.vulnerabilityType = vulnerabilityType; }
    
    public double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }
    
    public List<GeneratedPayload> getTestPayloads() { return testPayloads; }
    public void setTestPayloads(List<GeneratedPayload> testPayloads) { this.testPayloads = testPayloads; }
    
    public Map<String, Object> getTestParameters() { return testParameters; }
    public void setTestParameters(Map<String, Object> testParameters) { this.testParameters = testParameters; }
    
    public List<String> getValidationCriteria() { return validationCriteria; }
    public void setValidationCriteria(List<String> validationCriteria) { this.validationCriteria = validationCriteria; }
    
    public Map<String, Object> getTestMetadata() { return testMetadata; }
    public void setTestMetadata(Map<String, Object> testMetadata) { this.testMetadata = testMetadata; }
    
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
}

// Application context
@JsonIgnoreProperties(ignoreUnknown = true)

// Session context
@JsonIgnoreProperties(ignoreUnknown = true)
class SessionContext {
    @JsonProperty("session_id")
    private String sessionId;
    
    @JsonProperty("start_time")
    private LocalDateTime startTime;
    
    @JsonProperty("last_activity")
    private LocalDateTime lastActivity;
    
    @JsonProperty("request_count")
    private AtomicInteger requestCount;
    
    @JsonProperty("vulnerability_findings")
    private Map<String, Integer> vulnerabilityFindings;
    
    @JsonProperty("anomaly_scores")
    private List<Double> anomalyScores;
    
    @JsonProperty("user_behavior_profile")
    private Map<String, Object> userBehaviorProfile;
    
    @JsonProperty("session_risk_level")
    private String sessionRiskLevel;
    
    public SessionContext(String sessionId, LocalDateTime startTime) {
        this.sessionId = sessionId;
        this.startTime = startTime;
        this.lastActivity = startTime;
        this.requestCount = new AtomicInteger(0);
        this.vulnerabilityFindings = new ConcurrentHashMap<>();
        this.anomalyScores = Collections.synchronizedList(new ArrayList<>());
        this.userBehaviorProfile = new ConcurrentHashMap<>();
        this.sessionRiskLevel = "LOW";
    }
    
    public void updateActivity() {
        this.lastActivity = LocalDateTime.now();
        this.requestCount.incrementAndGet();
    }
    
    public void addVulnerabilityFinding(String vulnerabilityType) {
        vulnerabilityFindings.merge(vulnerabilityType, 1, Integer::sum);
        updateRiskLevel();
    }
    
    public void addAnomalyScore(double score) {
        anomalyScores.add(score);
        if (anomalyScores.size() > 100) { // Keep only recent scores
            anomalyScores.remove(0);
        }
        updateRiskLevel();
    }
    
    private void updateRiskLevel() {
        int totalFindings = vulnerabilityFindings.values().stream().mapToInt(Integer::intValue).sum();
        double avgAnomalyScore = anomalyScores.stream().mapToDouble(d -> d).average().orElse(0.0);
        
        if (totalFindings > 5 || avgAnomalyScore > 0.8) {
            sessionRiskLevel = "HIGH";
        } else if (totalFindings > 2 || avgAnomalyScore > 0.6) {
            sessionRiskLevel = "MEDIUM";
        } else {
            sessionRiskLevel = "LOW";
        }
    }
    
    // Getters and setters
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public LocalDateTime getStartTime() { return startTime; }
    public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }
    
    public LocalDateTime getLastActivity() { return lastActivity; }
    public void setLastActivity(LocalDateTime lastActivity) { this.lastActivity = lastActivity; }
    
    public int getRequestCount() { return requestCount.get(); }
    
    public Map<String, Integer> getVulnerabilityFindings() { return new HashMap<>(vulnerabilityFindings); }
    
    public List<Double> getAnomalyScores() { return new ArrayList<>(anomalyScores); }
    
    public Map<String, Object> getUserBehaviorProfile() { return new HashMap<>(userBehaviorProfile); }
    public void setUserBehaviorProfile(Map<String, Object> userBehaviorProfile) { this.userBehaviorProfile = userBehaviorProfile; }
    
    public String getSessionRiskLevel() { return sessionRiskLevel; }
    public void setSessionRiskLevel(String sessionRiskLevel) { this.sessionRiskLevel = sessionRiskLevel; }
}

// Security assessment
@JsonIgnoreProperties(ignoreUnknown = true)
class SecurityAssessment {
    @JsonProperty("overall_risk_score")
    private double overallRiskScore;
    
    @JsonProperty("vulnerability_count")
    private int vulnerabilityCount;
    
    @JsonProperty("security_posture")
    private String securityPosture;
    
    @JsonProperty("security_recommendations")
    private List<String> securityRecommendations;
    
    @JsonProperty("compliance_status")
    private Map<String, String> complianceStatus;
    
    @JsonProperty("threat_level")
    private String threatLevel;
    
    public SecurityAssessment(double overallRiskScore, int vulnerabilityCount, String securityPosture, 
                             List<String> securityRecommendations) {
        this.overallRiskScore = overallRiskScore;
        this.vulnerabilityCount = vulnerabilityCount;
        this.securityPosture = securityPosture;
        this.securityRecommendations = securityRecommendations != null ? new ArrayList<>(securityRecommendations) : new ArrayList<>();
        this.complianceStatus = new HashMap<>();
        this.threatLevel = calculateThreatLevel(overallRiskScore, vulnerabilityCount);
        
        // Initialize compliance assessments
        assessCompliance();
    }
    
    private String calculateThreatLevel(double riskScore, int vulnCount) {
        if (riskScore >= 0.8 || vulnCount > 5) return "CRITICAL";
        if (riskScore >= 0.6 || vulnCount > 3) return "HIGH";
        if (riskScore >= 0.4 || vulnCount > 1) return "MEDIUM";
        return "LOW";
    }
    
    private void assessCompliance() {
        // OWASP Top 10 compliance
        if (vulnerabilityCount == 0) {
            complianceStatus.put("OWASP_TOP_10", "COMPLIANT");
        } else if (vulnerabilityCount <= 3) {
            complianceStatus.put("OWASP_TOP_10", "PARTIAL");
        } else {
            complianceStatus.put("OWASP_TOP_10", "NON_COMPLIANT");
        }
        
        // Basic security compliance
        if (overallRiskScore < 0.3) {
            complianceStatus.put("BASIC_SECURITY", "GOOD");
        } else if (overallRiskScore < 0.6) {
            complianceStatus.put("BASIC_SECURITY", "MODERATE");
        } else {
            complianceStatus.put("BASIC_SECURITY", "POOR");
        }
    }
    
    // Getters and setters
    public double getOverallRiskScore() { return overallRiskScore; }
    public void setOverallRiskScore(double overallRiskScore) { this.overallRiskScore = overallRiskScore; }
    
    public int getVulnerabilityCount() { return vulnerabilityCount; }
    public void setVulnerabilityCount(int vulnerabilityCount) { this.vulnerabilityCount = vulnerabilityCount; }
    
    public String getSecurityPosture() { return securityPosture; }
    public void setSecurityPosture(String securityPosture) { this.securityPosture = securityPosture; }
    
    public List<String> getSecurityRecommendations() { return securityRecommendations; }
    public void setSecurityRecommendations(List<String> securityRecommendations) { this.securityRecommendations = securityRecommendations; }
    
    public Map<String, String> getComplianceStatus() { return complianceStatus; }
    public void setComplianceStatus(Map<String, String> complianceStatus) { this.complianceStatus = complianceStatus; }
    
    public String getThreatLevel() { return threatLevel; }
    public void setThreatLevel(String threatLevel) { this.threatLevel = threatLevel; }
}

// Performance metrics tracking
class PerformanceMetrics {
    private final AtomicLong totalRequestsProcessed = new AtomicLong(0);
    private final AtomicLong totalVulnerabilitiesDetected = new AtomicLong(0);
    private final AtomicLong totalProcessingTimeMs = new AtomicLong(0);
    private final Map<String, AtomicLong> vulnerabilityTypesCounts = new ConcurrentHashMap<>();
    private final List<Double> recentProcessingTimes = Collections.synchronizedList(new ArrayList<>());
    
    public void recordProcessingStats(long requestsProcessed, long vulnerabilitiesDetected, 
                                    int pendingAnalyses, int queueSize) {
        totalRequestsProcessed.set(requestsProcessed);
        totalVulnerabilitiesDetected.set(vulnerabilitiesDetected);
    }
    
    public void recordProcessingTime(long timeMs) {
        totalProcessingTimeMs.addAndGet(timeMs);
        recentProcessingTimes.add((double) timeMs);
        
        // Keep only recent processing times
        if (recentProcessingTimes.size() > 1000) {
            recentProcessingTimes.subList(0, recentProcessingTimes.size() - 1000).clear();
        }
    }
    
    public void recordVulnerabilityDetection(String vulnerabilityType) {
        vulnerabilityTypesCounts.computeIfAbsent(vulnerabilityType, k -> new AtomicLong(0)).incrementAndGet();
    }
    
    public Map<String, Object> getCurrentMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("total_requests_processed", totalRequestsProcessed.get());
        metrics.put("total_vulnerabilities_detected", totalVulnerabilitiesDetected.get());
        metrics.put("average_processing_time_ms", getAverageProcessingTime());
        metrics.put("vulnerability_detection_rate", getVulnerabilityDetectionRate());
        metrics.put("vulnerability_types_distribution", getVulnerabilityTypesDistribution());
        return metrics;
    }
    
    public double getAverageProcessingTime() {
        if (recentProcessingTimes.isEmpty()) return 0.0;
        return recentProcessingTimes.stream().mapToDouble(d -> d).average().orElse(0.0);
    }
    
    public double getVulnerabilityDetectionRate() {
        long total = totalRequestsProcessed.get();
        long detected = totalVulnerabilitiesDetected.get();
        return total > 0 ? (double) detected / total : 0.0;
    }
    
    public Map<String, Long> getVulnerabilityTypesDistribution() {
        return vulnerabilityTypesCounts.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
    }
    
    public void updateMetrics() {
        // Periodic metrics update - clear old data, recalculate averages, etc.
        if (recentProcessingTimes.size() > 1000) {
            recentProcessingTimes.subList(0, 500).clear(); // Keep more recent half
        }
    }
}

// Configuration for real-time analysis
class RealTimeAnalysisConfig {
    private int analysisThreads = 6;
    private int payloadGenerationThreads = 4;
    private int queueCapacity = 10000;
    private long queueTimeoutMs = 5000;
    private long analysisTimeoutMs = 30000;
    private double vulnerabilityThreshold = 0.6;
    private double correlationThreshold = 0.5;
    private int sessionTimeoutHours = 2;
    private boolean enableMLPrediction = true;
    private boolean enablePayloadGeneration = true;
    private boolean enableContextBuilding = true;
    
    // Getters and setters
    public int getAnalysisThreads() { return analysisThreads; }
    public void setAnalysisThreads(int analysisThreads) { this.analysisThreads = analysisThreads; }
    
    public int getPayloadGenerationThreads() { return payloadGenerationThreads; }
    public void setPayloadGenerationThreads(int payloadGenerationThreads) { this.payloadGenerationThreads = payloadGenerationThreads; }
    
    public int getQueueCapacity() { return queueCapacity; }
    public void setQueueCapacity(int queueCapacity) { this.queueCapacity = queueCapacity; }
    
    public long getQueueTimeoutMs() { return queueTimeoutMs; }
    public void setQueueTimeoutMs(long queueTimeoutMs) { this.queueTimeoutMs = queueTimeoutMs; }
    
    public long getAnalysisTimeoutMs() { return analysisTimeoutMs; }
    public void setAnalysisTimeoutMs(long analysisTimeoutMs) { this.analysisTimeoutMs = analysisTimeoutMs; }
    
    public double getVulnerabilityThreshold() { return vulnerabilityThreshold; }
    public void setVulnerabilityThreshold(double vulnerabilityThreshold) { this.vulnerabilityThreshold = vulnerabilityThreshold; }
    
    public double getCorrelationThreshold() { return correlationThreshold; }
    public void setCorrelationThreshold(double correlationThreshold) { this.correlationThreshold = correlationThreshold; }
    
    public int getSessionTimeoutHours() { return sessionTimeoutHours; }
    public void setSessionTimeoutHours(int sessionTimeoutHours) { this.sessionTimeoutHours = sessionTimeoutHours; }
    
    public boolean isEnableMLPrediction() { return enableMLPrediction; }
    public void setEnableMLPrediction(boolean enableMLPrediction) { this.enableMLPrediction = enableMLPrediction; }
    
    public boolean isEnablePayloadGeneration() { return enablePayloadGeneration; }
    public void setEnablePayloadGeneration(boolean enablePayloadGeneration) { this.enablePayloadGeneration = enablePayloadGeneration; }
    
    public boolean isEnableContextBuilding() { return enableContextBuilding; }
    public void setEnableContextBuilding(boolean enableContextBuilding) { this.enableContextBuilding = enableContextBuilding; }
}