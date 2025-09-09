package com.secure.ai.burp.ml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

// Main request class for traffic analysis
@JsonIgnoreProperties(ignoreUnknown = true)
public class TrafficAnalysisRequest {
    @JsonProperty("session_id")
    private String sessionId;
    
    @JsonProperty("request_id")
    private String requestId;
    
    @JsonProperty("payload")
    private String payload;
    
    @JsonProperty("context")
    private Map<String, Object> context;
    
    @JsonProperty("timestamp")
    private LocalDateTime timestamp;
    
    @JsonProperty("http_method")
    private String httpMethod;
    
    @JsonProperty("url")
    private String url;
    
    @JsonProperty("headers")
    private Map<String, String> headers;
    
    public TrafficAnalysisRequest() {
        this.context = new HashMap<>();
        this.headers = new HashMap<>();
        this.timestamp = LocalDateTime.now();
    }
    
    public TrafficAnalysisRequest(String sessionId, String requestId, String payload, Map<String, Object> context) {
        this();
        this.sessionId = sessionId;
        this.requestId = requestId;
        this.payload = payload;
        this.context = context != null ? new HashMap<>(context) : new HashMap<>();
    }
    
    // Getters and setters
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    
    public Map<String, Object> getContext() { return context; }
    public void setContext(Map<String, Object> context) { this.context = context; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }
    
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    
    public Map<String, String> getHeaders() { return headers; }
    public void setHeaders(Map<String, String> headers) { this.headers = headers; }
}

// Multi-layer anomaly detection result
@JsonIgnoreProperties(ignoreUnknown = true)
public class MultiLayerAnomalyResult {
    @JsonProperty("session_id")
    private String sessionId;
    
    @JsonProperty("request_id")
    private String requestId;
    
    @JsonProperty("aggregated_score")
    private double aggregatedScore;
    
    @JsonProperty("classification")
    private AnomalyClassification classification;
    
    @JsonProperty("layer_results")
    private List<LayerDetectionResult> layerResults;
    
    @JsonProperty("layer_details")
    private Map<String, Object> layerDetails;
    
    @JsonProperty("indicators")
    private List<AnomalyIndicator> indicators;
    
    @JsonProperty("risk_assessment")
    private RiskAssessment riskAssessment;
    
    @JsonProperty("recommendations")
    private List<String> recommendations;
    
    @JsonProperty("detection_timestamp")
    private LocalDateTime detectionTimestamp;
    
    public MultiLayerAnomalyResult() {}
    
    public MultiLayerAnomalyResult(String sessionId, String requestId, double aggregatedScore, 
                                  AnomalyClassification classification, List<LayerDetectionResult> layerResults,
                                  Map<String, Object> layerDetails, List<AnomalyIndicator> indicators,
                                  RiskAssessment riskAssessment, List<String> recommendations,
                                  LocalDateTime detectionTimestamp) {
        this.sessionId = sessionId;
        this.requestId = requestId;
        this.aggregatedScore = aggregatedScore;
        this.classification = classification;
        this.layerResults = layerResults != null ? new ArrayList<>(layerResults) : new ArrayList<>();
        this.layerDetails = layerDetails != null ? new HashMap<>(layerDetails) : new HashMap<>();
        this.indicators = indicators != null ? new ArrayList<>(indicators) : new ArrayList<>();
        this.riskAssessment = riskAssessment;
        this.recommendations = recommendations != null ? new ArrayList<>(recommendations) : new ArrayList<>();
        this.detectionTimestamp = detectionTimestamp;
    }
    
    // Getters and setters
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    
    public double getAggregatedScore() { return aggregatedScore; }
    public void setAggregatedScore(double aggregatedScore) { this.aggregatedScore = aggregatedScore; }
    
    public AnomalyClassification getClassification() { return classification; }
    public void setClassification(AnomalyClassification classification) { this.classification = classification; }
    
    public List<LayerDetectionResult> getLayerResults() { return layerResults; }
    public void setLayerResults(List<LayerDetectionResult> layerResults) { this.layerResults = layerResults; }
    
    public Map<String, Object> getLayerDetails() { return layerDetails; }
    public void setLayerDetails(Map<String, Object> layerDetails) { this.layerDetails = layerDetails; }
    
    public List<AnomalyIndicator> getIndicators() { return indicators; }
    public void setIndicators(List<AnomalyIndicator> indicators) { this.indicators = indicators; }
    
    public RiskAssessment getRiskAssessment() { return riskAssessment; }
    public void setRiskAssessment(RiskAssessment riskAssessment) { this.riskAssessment = riskAssessment; }
    
    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
    
    public LocalDateTime getDetectionTimestamp() { return detectionTimestamp; }
    public void setDetectionTimestamp(LocalDateTime detectionTimestamp) { this.detectionTimestamp = detectionTimestamp; }
}

// Individual layer detection result
@JsonIgnoreProperties(ignoreUnknown = true)
public class LayerDetectionResult {
    @JsonProperty("layer_name")
    private String layerName;
    
    @JsonProperty("anomaly_score")
    private double anomalyScore;
    
    @JsonProperty("indicators")
    private List<AnomalyIndicator> indicators;
    
    @JsonProperty("details")
    private Map<String, Object> details;
    
    @JsonProperty("recommendations")
    private List<String> recommendations;
    
    @JsonProperty("mitigation_strategies")
    private List<String> mitigationStrategies;
    
    public LayerDetectionResult() {}
    
    public LayerDetectionResult(String layerName, double anomalyScore, List<AnomalyIndicator> indicators,
                               Map<String, Object> details, List<String> recommendations, 
                               List<String> mitigationStrategies) {
        this.layerName = layerName;
        this.anomalyScore = anomalyScore;
        this.indicators = indicators != null ? new ArrayList<>(indicators) : new ArrayList<>();
        this.details = details != null ? new HashMap<>(details) : new HashMap<>();
        this.recommendations = recommendations != null ? new ArrayList<>(recommendations) : new ArrayList<>();
        this.mitigationStrategies = mitigationStrategies != null ? new ArrayList<>(mitigationStrategies) : new ArrayList<>();
    }
    
    // Getters and setters
    public String getLayerName() { return layerName; }
    public void setLayerName(String layerName) { this.layerName = layerName; }
    
    public double getAnomalyScore() { return anomalyScore; }
    public void setAnomalyScore(double anomalyScore) { this.anomalyScore = anomalyScore; }
    
    public List<AnomalyIndicator> getIndicators() { return indicators; }
    public void setIndicators(List<AnomalyIndicator> indicators) { this.indicators = indicators; }
    
    public Map<String, Object> getDetails() { return details; }
    public void setDetails(Map<String, Object> details) { this.details = details; }
    
    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
    
    public List<String> getMitigationStrategies() { return mitigationStrategies; }
    public void setMitigationStrategies(List<String> mitigationStrategies) { this.mitigationStrategies = mitigationStrategies; }
}

// Anomaly indicator
@JsonIgnoreProperties(ignoreUnknown = true)
public class AnomalyIndicator {
    @JsonProperty("type")
    private String type;
    
    @JsonProperty("reason")
    private String reason;
    
    @JsonProperty("severity")
    private String severity;
    
    @JsonProperty("confidence")
    private double confidence;
    
    @JsonProperty("recommendation")
    private String recommendation;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    public AnomalyIndicator() {
        this.metadata = new HashMap<>();
    }
    
    public AnomalyIndicator(String type, String reason, String severity, double confidence, String recommendation) {
        this();
        this.type = type;
        this.reason = reason;
        this.severity = severity;
        this.confidence = confidence;
        this.recommendation = recommendation;
    }
    
    // Getters and setters
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}

// Anomaly classification
@JsonIgnoreProperties(ignoreUnknown = true)
public class AnomalyClassification {
    @JsonProperty("severity")
    private String severity;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("confidence")
    private double confidence;
    
    @JsonProperty("reasons")
    private List<String> reasons;
    
    public AnomalyClassification() {}
    
    public AnomalyClassification(String severity, String description, double confidence, List<String> reasons) {
        this.severity = severity;
        this.description = description;
        this.confidence = confidence;
        this.reasons = reasons != null ? new ArrayList<>(reasons) : new ArrayList<>();
    }
    
    // Getters and setters
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public List<String> getReasons() { return reasons; }
    public void setReasons(List<String> reasons) { this.reasons = reasons; }
}

// Risk assessment
@JsonIgnoreProperties(ignoreUnknown = true)
public class RiskAssessment {
    @JsonProperty("risk_score")
    private double riskScore;
    
    @JsonProperty("risk_category")
    private String riskCategory;
    
    @JsonProperty("risk_factors")
    private Map<String, Object> riskFactors;
    
    @JsonProperty("mitigation_strategies")
    private List<String> mitigationStrategies;
    
    public RiskAssessment() {}
    
    public RiskAssessment(double riskScore, String riskCategory, Map<String, Object> riskFactors, 
                         List<String> mitigationStrategies) {
        this.riskScore = riskScore;
        this.riskCategory = riskCategory;
        this.riskFactors = riskFactors != null ? new HashMap<>(riskFactors) : new HashMap<>();
        this.mitigationStrategies = mitigationStrategies != null ? new ArrayList<>(mitigationStrategies) : new ArrayList<>();
    }
    
    // Getters and setters
    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }
    
    public String getRiskCategory() { return riskCategory; }
    public void setRiskCategory(String riskCategory) { this.riskCategory = riskCategory; }
    
    public Map<String, Object> getRiskFactors() { return riskFactors; }
    public void setRiskFactors(Map<String, Object> riskFactors) { this.riskFactors = riskFactors; }
    
    public List<String> getMitigationStrategies() { return mitigationStrategies; }
    public void setMitigationStrategies(List<String> mitigationStrategies) { this.mitigationStrategies = mitigationStrategies; }
}

// Configuration for anomaly detection
public class AnomalyDetectionConfig {
    private double anomalyThreshold = 0.5;
    private double lowThreshold = 0.3;
    private double mediumThreshold = 0.5;
    private double highThreshold = 0.7;
    private double criticalThreshold = 0.9;
    private int maxCacheSize = 10000;
    private long cacheExpirationMinutes = 60;
    private int detectionThreads = 8;
    private boolean enableLearning = true;
    
    // Getters and setters
    public double getAnomalyThreshold() { return anomalyThreshold; }
    public void setAnomalyThreshold(double anomalyThreshold) { this.anomalyThreshold = anomalyThreshold; }
    
    public double getLowThreshold() { return lowThreshold; }
    public void setLowThreshold(double lowThreshold) { this.lowThreshold = lowThreshold; }
    
    public double getMediumThreshold() { return mediumThreshold; }
    public void setMediumThreshold(double mediumThreshold) { this.mediumThreshold = mediumThreshold; }
    
    public double getHighThreshold() { return highThreshold; }
    public void setHighThreshold(double highThreshold) { this.highThreshold = highThreshold; }
    
    public double getCriticalThreshold() { return criticalThreshold; }
    public void setCriticalThreshold(double criticalThreshold) { this.criticalThreshold = criticalThreshold; }
    
    public int getMaxCacheSize() { return maxCacheSize; }
    public void setMaxCacheSize(int maxCacheSize) { this.maxCacheSize = maxCacheSize; }
    
    public long getCacheExpirationMinutes() { return cacheExpirationMinutes; }
    public void setCacheExpirationMinutes(long cacheExpirationMinutes) { this.cacheExpirationMinutes = cacheExpirationMinutes; }
    
    public int getDetectionThreads() { return detectionThreads; }
    public void setDetectionThreads(int detectionThreads) { this.detectionThreads = detectionThreads; }
    
    public boolean isEnableLearning() { return enableLearning; }
    public void setEnableLearning(boolean enableLearning) { this.enableLearning = enableLearning; }
}

// Session baseline tracking
public class SessionBaseline {
    private final String sessionId;
    private final LocalDateTime startTime;
    private final AtomicLong requestCount;
    private final Map<String, Double> baselineMetrics;
    private final List<Double> requestSizes;
    private final List<Long> requestIntervals;
    private LocalDateTime lastRequestTime;
    
    public SessionBaseline(String sessionId, LocalDateTime startTime) {
        this.sessionId = sessionId;
        this.startTime = startTime;
        this.requestCount = new AtomicLong(0);
        this.baselineMetrics = new ConcurrentHashMap<>();
        this.requestSizes = Collections.synchronizedList(new ArrayList<>());
        this.requestIntervals = Collections.synchronizedList(new ArrayList<>());
        this.lastRequestTime = startTime;
    }
    
    public void updateWithRequest(TrafficAnalysisRequest request, MultiLayerAnomalyResult result) {
        requestCount.incrementAndGet();
        
        // Update request sizes
        requestSizes.add((double) request.getPayload().length());
        
        // Update request intervals
        if (lastRequestTime != null) {
            long interval = java.time.Duration.between(lastRequestTime, request.getTimestamp()).toMillis();
            requestIntervals.add(interval);
        }
        lastRequestTime = request.getTimestamp();
        
        // Update baseline metrics
        baselineMetrics.put("avg_payload_size", requestSizes.stream().mapToDouble(d -> d).average().orElse(0.0));
        baselineMetrics.put("avg_anomaly_score", result.getAggregatedScore());
        
        if (!requestIntervals.isEmpty()) {
            baselineMetrics.put("avg_request_interval", requestIntervals.stream().mapToLong(l -> l).average().orElse(0.0));
        }
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public LocalDateTime getStartTime() { return startTime; }
    public long getRequestCount() { return requestCount.get(); }
    public Map<String, Double> getBaselineMetrics() { return new HashMap<>(baselineMetrics); }
    public LocalDateTime getLastRequestTime() { return lastRequestTime; }
}

// User behavior profiling
public class UserBehaviorProfile {
    private final String userContext;
    private final AtomicLong totalRequests;
    private final Map<String, Integer> payloadPatterns;
    private final List<Long> requestTimings;
    private final Map<String, Double> behaviorMetrics;
    private LocalDateTime lastActivity;
    
    public UserBehaviorProfile(String userContext) {
        this.userContext = userContext;
        this.totalRequests = new AtomicLong(0);
        this.payloadPatterns = new ConcurrentHashMap<>();
        this.requestTimings = Collections.synchronizedList(new ArrayList<>());
        this.behaviorMetrics = new ConcurrentHashMap<>();
        this.lastActivity = LocalDateTime.now();
    }
    
    public double analyzeBehavior(TrafficAnalysisRequest request) {
        totalRequests.incrementAndGet();
        
        // Update timing patterns
        if (lastActivity != null) {
            long interval = java.time.Duration.between(lastActivity, request.getTimestamp()).toMillis();
            requestTimings.add(interval);
        }
        lastActivity = request.getTimestamp();
        
        // Analyze payload patterns
        String payloadPattern = categorizePayload(request.getPayload());
        payloadPatterns.merge(payloadPattern, 1, Integer::sum);
        
        // Calculate behavior anomaly score
        return calculateBehaviorAnomalyScore();
    }
    
    public void updateBehavior(TrafficAnalysisRequest request, MultiLayerAnomalyResult result) {
        // Update behavior based on anomaly detection results
        behaviorMetrics.put("avg_anomaly_score", result.getAggregatedScore());
        behaviorMetrics.put("total_requests", (double) totalRequests.get());
    }
    
    private String categorizePayload(String payload) {
        if (payload.length() < 50) return "SHORT";
        if (payload.length() > 500) return "LONG";
        if (payload.contains("script")) return "SCRIPT";
        if (payload.contains("select") || payload.contains("union")) return "SQL";
        return "NORMAL";
    }
    
    private double calculateBehaviorAnomalyScore() {
        double score = 0.0;
        
        // Check for consistent timing (bot-like behavior)
        if (hasConsistentTiming()) {
            score += 0.3;
        }
        
        // Check for unusual payload patterns
        if (hasUnusualPatterns()) {
            score += 0.4;
        }
        
        return Math.min(score, 1.0);
    }
    
    public boolean hasConsistentTiming() {
        if (requestTimings.size() < 5) return false;
        
        double variance = calculateVariance(requestTimings);
        double mean = requestTimings.stream().mapToLong(l -> l).average().orElse(0.0);
        
        return variance < mean * 0.1; // Very low variance relative to mean
    }
    
    public double getAverageRequestInterval() {
        return requestTimings.stream().mapToLong(l -> l).average().orElse(0.0);
    }
    
    private boolean hasUnusualPatterns() {
        long maliciousPatterns = payloadPatterns.entrySet().stream()
            .filter(entry -> entry.getKey().equals("SCRIPT") || entry.getKey().equals("SQL"))
            .mapToLong(Map.Entry::getValue)
            .sum();
        
        return maliciousPatterns > totalRequests.get() * 0.2; // More than 20% malicious patterns
    }
    
    private double calculateVariance(List<Long> values) {
        if (values.isEmpty()) return 0.0;
        
        double mean = values.stream().mapToLong(l -> l).average().orElse(0.0);
        return values.stream()
            .mapToDouble(v -> Math.pow(v - mean, 2))
            .average()
            .orElse(0.0);
    }
    
    // Getters
    public String getUserContext() { return userContext; }
    public long getRequestCount() { return totalRequests.get(); }
    public Map<String, Double> getBehaviorMetrics() { return new HashMap<>(behaviorMetrics); }
}

// Request frequency tracking
public class RequestFrequencyTracker {
    private final String identifier;
    private final List<LocalDateTime> requestTimes;
    private final AtomicLong totalRequests;
    private final Map<String, Double> frequencyMetrics;
    
    public RequestFrequencyTracker(String identifier) {
        this.identifier = identifier;
        this.requestTimes = Collections.synchronizedList(new ArrayList<>());
        this.totalRequests = new AtomicLong(0);
        this.frequencyMetrics = new ConcurrentHashMap<>();
    }
    
    public double analyzeFrequency(TrafficAnalysisRequest request) {
        LocalDateTime now = request.getTimestamp();
        requestTimes.add(now);
        totalRequests.incrementAndGet();
        
        // Clean old requests (keep only last hour)
        LocalDateTime oneHourAgo = now.minusHours(1);
        requestTimes.removeIf(time -> time.isBefore(oneHourAgo));
        
        // Calculate requests per minute
        double rpm = calculateRequestsPerMinute();
        frequencyMetrics.put("requests_per_minute", rpm);
        
        // Calculate frequency anomaly score
        return calculateFrequencyScore(rpm);
    }
    
    public double calculateRequestsPerMinute() {
        if (requestTimes.isEmpty()) return 0.0;
        
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime oneMinuteAgo = now.minusMinutes(1);
        
        long recentRequests = requestTimes.stream()
            .mapToLong(time -> time.isAfter(oneMinuteAgo) ? 1 : 0)
            .sum();
        
        return recentRequests;
    }
    
    public double getAverageInterval() {
        if (requestTimes.size() < 2) return 0.0;
        
        List<Long> intervals = new ArrayList<>();
        for (int i = 1; i < requestTimes.size(); i++) {
            long interval = java.time.Duration.between(requestTimes.get(i-1), requestTimes.get(i)).toMillis();
            intervals.add(interval);
        }
        
        return intervals.stream().mapToLong(l -> l).average().orElse(0.0);
    }
    
    public boolean hasConsistentTiming() {
        if (requestTimes.size() < 5) return false;
        
        List<Long> intervals = new ArrayList<>();
        for (int i = 1; i < requestTimes.size(); i++) {
            long interval = java.time.Duration.between(requestTimes.get(i-1), requestTimes.get(i)).toMillis();
            intervals.add(interval);
        }
        
        double variance = calculateVariance(intervals);
        double mean = intervals.stream().mapToLong(l -> l).average().orElse(0.0);
        
        return variance < mean * 0.1;
    }
    
    public double getTimingVariance() {
        if (requestTimes.size() < 2) return 0.0;
        
        List<Long> intervals = new ArrayList<>();
        for (int i = 1; i < requestTimes.size(); i++) {
            long interval = java.time.Duration.between(requestTimes.get(i-1), requestTimes.get(i)).toMillis();
            intervals.add(interval);
        }
        
        return calculateVariance(intervals);
    }
    
    public boolean hasBurstPattern() {
        if (requestTimes.size() < 10) return false;
        
        // Check for sudden spikes in request frequency
        double currentRpm = calculateRequestsPerMinute();
        double avgRpm = frequencyMetrics.getOrDefault("historical_avg_rpm", currentRpm);
        
        return currentRpm > avgRpm * 3; // Current rate is 3x historical average
    }
    
    private double calculateFrequencyScore(double rpm) {
        // Scoring based on requests per minute
        if (rpm > 100) return 1.0;      // Very high frequency
        if (rpm > 50) return 0.8;       // High frequency
        if (rpm > 20) return 0.6;       // Moderate frequency
        if (rpm > 10) return 0.4;       // Slightly elevated
        return 0.0;                     // Normal frequency
    }
    
    private double calculateVariance(List<Long> values) {
        if (values.isEmpty()) return 0.0;
        
        double mean = values.stream().mapToLong(l -> l).average().orElse(0.0);
        return values.stream()
            .mapToDouble(v -> Math.pow(v - mean, 2))
            .average()
            .orElse(0.0);
    }
    
    public double getRequestsPerMinute() {
        return frequencyMetrics.getOrDefault("requests_per_minute", 0.0);
    }
}

// Threat Intelligence Database
public class ThreatIntelligenceDatabase {
    private final Map<String, ThreatIntelEntry> ipDatabase;
    private final Set<String> maliciousUserAgents;
    private final List<String> threatSignatures;
    private final Map<String, String> geoData;
    
    public ThreatIntelligenceDatabase() {
        this.ipDatabase = new ConcurrentHashMap<>();
        this.maliciousUserAgents = ConcurrentHashMap.newKeySet();
        this.threatSignatures = Collections.synchronizedList(new ArrayList<>());
        this.geoData = new ConcurrentHashMap<>();
        initializeDatabase();
    }
    
    public void initialize() {
        // Load threat intelligence data
        loadThreatIntelligence();
    }
    
    public double checkIPReputation(String ip) {
        ThreatIntelEntry entry = ipDatabase.get(ip);
        if (entry == null) return 0.0;
        
        return entry.getThreatScore();
    }
    
    public double analyzeUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) return 0.3;
        
        String lowerUA = userAgent.toLowerCase();
        
        // Check against known malicious user agents
        if (maliciousUserAgents.stream().anyMatch(lowerUA::contains)) {
            return 0.9;
        }
        
        // Check for suspicious patterns
        if (lowerUA.length() < 20 || lowerUA.contains("bot") || lowerUA.contains("crawler")) {
            return 0.6;
        }
        
        return 0.0;
    }
    
    public double matchPayloadSignatures(String payload) {
        String lowerPayload = payload.toLowerCase();
        
        long matchCount = threatSignatures.stream()
            .mapToLong(signature -> lowerPayload.contains(signature.toLowerCase()) ? 1 : 0)
            .sum();
        
        return Math.min(matchCount * 0.3, 1.0);
    }
    
    public double analyzeGeolocation(String ip) {
        String country = geoData.get(ip);
        if (country == null) return 0.0;
        
        // Simple geo-based scoring (in practice, would use more sophisticated analysis)
        Set<String> highRiskCountries = Set.of("XX", "YY", "ZZ"); // Placeholder
        return highRiskCountries.contains(country) ? 0.6 : 0.0;
    }
    
    public boolean hasReputationData(String ip) {
        return ipDatabase.containsKey(ip);
    }
    
    public Set<String> getThreatCategories(String ip) {
        ThreatIntelEntry entry = ipDatabase.get(ip);
        return entry != null ? entry.getCategories() : Collections.emptySet();
    }
    
    private void initializeDatabase() {
        // Initialize with sample threat intelligence data
        // In practice, this would load from external threat feeds
        
        // Sample malicious IPs
        ipDatabase.put("192.168.1.100", new ThreatIntelEntry(0.9, Set.of("malware", "botnet")));
        ipDatabase.put("10.0.0.50", new ThreatIntelEntry(0.7, Set.of("scanning", "reconnaissance")));
        
        // Sample malicious user agents
        maliciousUserAgents.add("badbot");
        maliciousUserAgents.add("scanner");
        maliciousUserAgents.add("exploit");
        
        // Sample threat signatures
        threatSignatures.add("eval(");
        threatSignatures.add("system(");
        threatSignatures.add("exec(");
        threatSignatures.add("passthru(");
        threatSignatures.add("shell_exec(");
    }
    
    private void loadThreatIntelligence() {
        // Load additional threat intelligence from external sources
        // This is where integration with threat intelligence feeds would occur
    }
    
    // Inner class for threat intelligence entries
    public static class ThreatIntelEntry {
        private final double threatScore;
        private final Set<String> categories;
        private final LocalDateTime lastUpdated;
        
        public ThreatIntelEntry(double threatScore, Set<String> categories) {
            this.threatScore = threatScore;
            this.categories = new HashSet<>(categories);
            this.lastUpdated = LocalDateTime.now();
        }
        
        public double getThreatScore() { return threatScore; }
        public Set<String> getCategories() { return new HashSet<>(categories); }
        public LocalDateTime getLastUpdated() { return lastUpdated; }
    }
}

// Metrics tracking for anomaly detection
public class AnomalyMetrics {
    private final AtomicLong totalDetections;
    private final AtomicLong anomaliesDetected;
    private final AtomicLong criticalAnomalies;
    private final Map<String, AtomicLong> layerDetections;
    private final List<Double> processingTimes;
    private final Map<String, AtomicLong> severityCounts;
    
    public AnomalyMetrics() {
        this.totalDetections = new AtomicLong(0);
        this.anomaliesDetected = new AtomicLong(0);
        this.criticalAnomalies = new AtomicLong(0);
        this.layerDetections = new ConcurrentHashMap<>();
        this.processingTimes = Collections.synchronizedList(new ArrayList<>());
        this.severityCounts = new ConcurrentHashMap<>();
        
        // Initialize severity counters
        severityCounts.put("LOW", new AtomicLong(0));
        severityCounts.put("MEDIUM", new AtomicLong(0));
        severityCounts.put("HIGH", new AtomicLong(0));
        severityCounts.put("CRITICAL", new AtomicLong(0));
    }
    
    public void recordDetection(MultiLayerAnomalyResult result, long processingTimeMs) {
        totalDetections.incrementAndGet();
        processingTimes.add((double) processingTimeMs);
        
        if (result.getAggregatedScore() > 0.5) {
            anomaliesDetected.incrementAndGet();
        }
        
        String severity = result.getClassification().getSeverity();
        severityCounts.get(severity).incrementAndGet();
        
        if ("CRITICAL".equals(severity)) {
            criticalAnomalies.incrementAndGet();
        }
        
        // Record layer-specific detections
        for (LayerDetectionResult layerResult : result.getLayerResults()) {
            layerDetections.computeIfAbsent(layerResult.getLayerName(), k -> new AtomicLong(0))
                          .incrementAndGet();
        }
    }
    
    // Getters for metrics
    public long getTotalDetections() { return totalDetections.get(); }
    public long getAnomaliesDetected() { return anomaliesDetected.get(); }
    public long getCriticalAnomalies() { return criticalAnomalies.get(); }
    public double getAnomalyRate() { 
        return totalDetections.get() > 0 ? (double) anomaliesDetected.get() / totalDetections.get() : 0.0; 
    }
    public double getAverageProcessingTime() { 
        return processingTimes.stream().mapToDouble(d -> d).average().orElse(0.0); 
    }
    public Map<String, Long> getLayerDetectionCounts() {
        return layerDetections.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
    }
    public Map<String, Long> getSeverityCounts() {
        return severityCounts.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
    }
}