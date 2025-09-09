package com.secure.ai.burp.models.ml;

import com.secure.ai.burp.utils.SecurityTestingUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

class MultiLayerAnomalyDetection {
    private static final Logger logger = LoggerFactory.getLogger(MultiLayerAnomalyDetection.class);
    
    private final StatisticalAnalyzer statisticalAnalyzer;
    private final ClusteringEngine clusteringEngine;
    private final PatternLearner patternLearner;
    private final FeatureExtractor featureExtractor;
    
    // Detection Layer Components
    private final StatisticalAnomalyLayer statisticalLayer;
    private final BehavioralAnomalyLayer behavioralLayer;
    private final PatternAnomalyLayer patternLayer;
    private final FrequencyAnomalyLayer frequencyLayer;
    private final ThreatIntelligenceLayer threatIntelLayer;
    
    // Configuration and State
    private final AnomalyDetectionConfig config;
    private final Map<String, SessionBaseline> sessionBaselines;
    private final Map<String, UserBehaviorProfile> userProfiles;
    private final ThreatIntelligenceDatabase threatIntelDB;
    private final ExecutorService detectionExecutor;
    
    // Metrics and Monitoring
    private final AnomalyMetrics metrics;
    private volatile boolean isActive = false;
    
    public MultiLayerAnomalyDetection(StatisticalAnalyzer statisticalAnalyzer,
                                    ClusteringEngine clusteringEngine,
                                    PatternLearner patternLearner,
                                    FeatureExtractor featureExtractor) {
        this.statisticalAnalyzer = statisticalAnalyzer;
        this.clusteringEngine = clusteringEngine;
        this.patternLearner = patternLearner;
        this.featureExtractor = featureExtractor;
        
        // Initialize detection layers
        this.statisticalLayer = new StatisticalAnomalyLayer(statisticalAnalyzer);
        this.behavioralLayer = new BehavioralAnomalyLayer();
        this.patternLayer = new PatternAnomalyLayer(patternLearner, clusteringEngine);
        this.frequencyLayer = new FrequencyAnomalyLayer();
        this.threatIntelLayer = new ThreatIntelligenceLayer();
        
        // Initialize state management
        this.config = new AnomalyDetectionConfig();
        this.sessionBaselines = new ConcurrentHashMap<>();
        this.userProfiles = new ConcurrentHashMap<>();
        this.threatIntelDB = new ThreatIntelligenceDatabase();
        this.detectionExecutor = Executors.newFixedThreadPool(8);
        this.metrics = new AnomalyMetrics();
        
        logger.info("Multi-layer anomaly detection system initialized");
    }
    
    public CompletableFuture<MultiLayerAnomalyResult> detectAnomalies(TrafficAnalysisRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                long startTime = System.currentTimeMillis();
                
                // Extract features for all layers
                float[] features = featureExtractor.extractFeatures(request.getPayload(), request.getContext());
                
                // Parallel execution of all detection layers
                List<CompletableFuture<LayerDetectionResult>> layerFutures = Arrays.asList(
                    CompletableFuture.supplyAsync(() -> statisticalLayer.detectAnomalies(request, features), detectionExecutor),
                    CompletableFuture.supplyAsync(() -> behavioralLayer.detectAnomalies(request, features), detectionExecutor),
                    CompletableFuture.supplyAsync(() -> patternLayer.detectAnomalies(request, features), detectionExecutor),
                    CompletableFuture.supplyAsync(() -> frequencyLayer.detectAnomalies(request, features), detectionExecutor),
                    CompletableFuture.supplyAsync(() -> threatIntelLayer.detectAnomalies(request, features), detectionExecutor)
                );
                
                // Collect all layer results
                List<LayerDetectionResult> layerResults = layerFutures.stream()
                    .map(CompletableFuture::join)
                    .collect(Collectors.toList());
                
                // Aggregate results using advanced fusion techniques
                MultiLayerAnomalyResult result = aggregateLayerResults(request, layerResults, features);
                
                // Update baselines and learning systems
                updateBaselines(request, result);
                updateLearning(request, result);
                
                // Update metrics
                long processingTime = System.currentTimeMillis() - startTime;
                metrics.recordDetection(result, processingTime);
                
                return result;
                
            } catch (Exception e) {
                logger.error("Multi-layer anomaly detection failed for request: {}", request, e);
                return createErrorResult(request, e);
            }
        }, detectionExecutor);
    }
    
    private MultiLayerAnomalyResult aggregateLayerResults(TrafficAnalysisRequest request,
                                                         List<LayerDetectionResult> layerResults,
                                                         float[] features) {
        
        // Advanced weighted scoring system
        double[] layerWeights = calculateDynamicWeights(request, layerResults);
        double aggregatedScore = 0.0;
        
        Map<String, Object> layerDetails = new HashMap<>();
        List<AnomalyIndicator> allIndicators = new ArrayList<>();
        
        for (int i = 0; i < layerResults.size(); i++) {
            LayerDetectionResult layerResult = layerResults.get(i);
            double weight = layerWeights[i];
            
            aggregatedScore += layerResult.getAnomalyScore() * weight;
            layerDetails.put(layerResult.getLayerName(), layerResult.getDetails());
            allIndicators.addAll(layerResult.getIndicators());
        }
        
        // Apply confidence adjustment based on layer consensus
        double consensusAdjustment = calculateConsensusAdjustment(layerResults);
        aggregatedScore *= consensusAdjustment;
        
        // Determine final classification
        AnomalyClassification classification = determineAnomalyClassification(aggregatedScore, allIndicators);
        
        // Generate risk assessment
        RiskAssessment riskAssessment = generateRiskAssessment(request, aggregatedScore, layerResults);
        
        // Create recommendations
        List<String> recommendations = generateRecommendations(request, layerResults, classification);
        
        return new MultiLayerAnomalyResult(
            request.getSessionId(),
            request.getRequestId(),
            aggregatedScore,
            classification,
            layerResults,
            layerDetails,
            allIndicators,
            riskAssessment,
            recommendations,
            LocalDateTime.now()
        );
    }
    
    private double[] calculateDynamicWeights(TrafficAnalysisRequest request, List<LayerDetectionResult> layerResults) {
        double[] baseWeights = {0.25, 0.20, 0.25, 0.15, 0.15}; // Statistical, Behavioral, Pattern, Frequency, ThreatIntel
        double[] dynamicWeights = Arrays.copyOf(baseWeights, baseWeights.length);
        
        // Adjust weights based on context
        Map<String, Object> context = request.getContext();
        
        // Increase statistical layer weight for numerical anomalies
        if (hasNumericalContent(request.getPayload())) {
            dynamicWeights[0] *= 1.3;
        }
        
        // Increase behavioral layer weight for session-based analysis
        if (context.containsKey("session_data") && hasSessionHistory(request.getSessionId())) {
            dynamicWeights[1] *= 1.2;
        }
        
        // Increase pattern layer weight for complex payloads
        if (request.getPayload().length() > 100) {
            dynamicWeights[2] *= 1.1;
        }
        
        // Increase threat intelligence weight for known malicious indicators
        if (threatIntelDB.hasReputationData(extractIPAddress(request))) {
            dynamicWeights[4] *= 1.4;
        }
        
        // Normalize weights
        double sum = Arrays.stream(dynamicWeights).sum();
        for (int i = 0; i < dynamicWeights.length; i++) {
            dynamicWeights[i] /= sum;
        }
        
        return dynamicWeights;
    }
    
    private double calculateConsensusAdjustment(List<LayerDetectionResult> layerResults) {
        // Calculate how many layers agree on anomaly detection
        long anomalousLayers = layerResults.stream()
            .mapToLong(layer -> layer.getAnomalyScore() > config.getAnomalyThreshold() ? 1 : 0)
            .sum();
        
        double consensusRatio = (double) anomalousLayers / layerResults.size();
        
        // Strong consensus increases confidence, weak consensus decreases it
        if (consensusRatio >= 0.6) {
            return 1.0 + (consensusRatio - 0.6) * 0.5; // Up to 20% boost
        } else if (consensusRatio <= 0.3) {
            return 0.7 + consensusRatio; // Down to 30% reduction
        }
        
        return 1.0; // Neutral adjustment
    }
    
    private AnomalyClassification determineAnomalyClassification(double aggregatedScore, List<AnomalyIndicator> indicators) {
        if (aggregatedScore >= config.getCriticalThreshold()) {
            return new AnomalyClassification("CRITICAL", "High-confidence security threat detected", 
                                           aggregatedScore, getSeverityReasons(indicators, "CRITICAL"));
        } else if (aggregatedScore >= config.getHighThreshold()) {
            return new AnomalyClassification("HIGH", "Significant anomaly requiring attention", 
                                           aggregatedScore, getSeverityReasons(indicators, "HIGH"));
        } else if (aggregatedScore >= config.getMediumThreshold()) {
            return new AnomalyClassification("MEDIUM", "Moderate anomaly detected", 
                                           aggregatedScore, getSeverityReasons(indicators, "MEDIUM"));
        } else if (aggregatedScore >= config.getLowThreshold()) {
            return new AnomalyClassification("LOW", "Minor anomaly observed", 
                                           aggregatedScore, getSeverityReasons(indicators, "LOW"));
        } else {
            return new AnomalyClassification("NORMAL", "No significant anomaly detected", 
                                           aggregatedScore, Collections.emptyList());
        }
    }
    
    private RiskAssessment generateRiskAssessment(TrafficAnalysisRequest request, double aggregatedScore, 
                                                List<LayerDetectionResult> layerResults) {
        
        // Calculate risk factors
        double probabilityOfAttack = calculateAttackProbability(aggregatedScore, layerResults);
        double potentialImpact = calculatePotentialImpact(request, layerResults);
        double exploitability = calculateExploitability(request, layerResults);
        
        // Overall risk score
        double riskScore = (probabilityOfAttack * 0.4 + potentialImpact * 0.3 + exploitability * 0.3);
        
        // Risk category
        String riskCategory = determineRiskCategory(riskScore);
        
        // Additional risk factors
        Map<String, Object> riskFactors = new HashMap<>();
        riskFactors.put("attack_probability", probabilityOfAttack);
        riskFactors.put("potential_impact", potentialImpact);
        riskFactors.put("exploitability", exploitability);
        riskFactors.put("data_sensitivity", assessDataSensitivity(request));
        riskFactors.put("attack_surface", assessAttackSurface(request));
        
        return new RiskAssessment(riskScore, riskCategory, riskFactors, generateMitigationStrategies(layerResults));
    }
    
    private List<String> generateRecommendations(TrafficAnalysisRequest request, 
                                              List<LayerDetectionResult> layerResults,
                                              AnomalyClassification classification) {
        List<String> recommendations = new ArrayList<>();
        
        // Layer-specific recommendations
        for (LayerDetectionResult layerResult : layerResults) {
            if (layerResult.getAnomalyScore() > config.getAnomalyThreshold()) {
                recommendations.addAll(layerResult.getRecommendations());
            }
        }
        
        // Overall recommendations based on classification
        switch (classification.getSeverity()) {
            case "CRITICAL":
                recommendations.add("IMMEDIATE ACTION: Block source IP and investigate security breach");
                recommendations.add("Activate incident response procedures");
                recommendations.add("Perform forensic analysis of attack vector");
                break;
            case "HIGH":
                recommendations.add("Investigate traffic source and intent");
                recommendations.add("Increase monitoring sensitivity for this session");
                recommendations.add("Consider temporary rate limiting");
                break;
            case "MEDIUM":
                recommendations.add("Monitor continued behavior patterns");
                recommendations.add("Log for security audit purposes");
                break;
            case "LOW":
                recommendations.add("Continue normal monitoring");
                break;
        }
        
        return recommendations.stream().distinct().collect(Collectors.toList());
    }
    
    private void updateBaselines(TrafficAnalysisRequest request, MultiLayerAnomalyResult result) {
        String sessionId = request.getSessionId();
        
        // Update session baseline
        SessionBaseline baseline = sessionBaselines.computeIfAbsent(sessionId, 
            k -> new SessionBaseline(sessionId, LocalDateTime.now()));
        baseline.updateWithRequest(request, result);
        
        // Update user behavior profile
        String userContext = extractUserContext(request);
        if (userContext != null) {
            UserBehaviorProfile profile = userProfiles.computeIfAbsent(userContext, 
                k -> new UserBehaviorProfile(userContext));
            profile.updateBehavior(request, result);
        }
    }
    
    private void updateLearning(TrafficAnalysisRequest request, MultiLayerAnomalyResult result) {
        // Update pattern learning based on detected anomalies
        if (result.getClassification().getSeverity().equals("HIGH") || 
            result.getClassification().getSeverity().equals("CRITICAL")) {
            
            patternLearner.learnPattern(
                request.getPayload(),
                result.getClassification().getSeverity(),
                result.getAggregatedScore()
            );
        }
        
        // Update statistical models with new data points
        statisticalAnalyzer.updateBaseline(request.getSessionId(), request.getPayload(), result.getAggregatedScore());
    }
    
    // Utility methods
    private boolean hasNumericalContent(String payload) {
        return payload.matches(".*\\d+.*");
    }
    
    private boolean hasSessionHistory(String sessionId) {
        return sessionBaselines.containsKey(sessionId) && 
               sessionBaselines.get(sessionId).getRequestCount() > 5;
    }
    
    private String extractIPAddress(TrafficAnalysisRequest request) {
        return (String) request.getContext().getOrDefault("source_ip", "unknown");
    }
    
    private String extractUserContext(TrafficAnalysisRequest request) {
        return (String) request.getContext().get("user_agent");
    }
    
    private List<String> getSeverityReasons(List<AnomalyIndicator> indicators, String severity) {
        return indicators.stream()
            .filter(indicator -> indicator.getSeverity().equals(severity))
            .map(AnomalyIndicator::getReason)
            .distinct()
            .collect(Collectors.toList());
    }
    
    private double calculateAttackProbability(double aggregatedScore, List<LayerDetectionResult> layerResults) {
        // Sophisticated probability calculation based on multiple factors
        double baseProbability = Math.min(aggregatedScore / config.getCriticalThreshold(), 1.0);
        
        // Adjust based on threat intelligence matches
        boolean hasThreatIntelMatch = layerResults.stream()
            .anyMatch(layer -> layer.getLayerName().equals("ThreatIntelligence") && 
                      layer.getAnomalyScore() > config.getHighThreshold());
        
        if (hasThreatIntelMatch) {
            baseProbability *= 1.5;
        }
        
        return Math.min(baseProbability, 1.0);
    }
    
    private double calculatePotentialImpact(TrafficAnalysisRequest request, List<LayerDetectionResult> layerResults) {
        // Assess potential impact based on target and payload characteristics
        double impact = 0.5; // Base impact
        
        String payload = request.getPayload().toLowerCase();
        
        // High impact indicators
        if (payload.contains("admin") || payload.contains("root") || payload.contains("system")) {
            impact += 0.3;
        }
        
        if (payload.contains("delete") || payload.contains("drop") || payload.contains("truncate")) {
            impact += 0.4;
        }
        
        if (payload.contains("union") || payload.contains("script") || payload.contains("eval")) {
            impact += 0.3;
        }
        
        return Math.min(impact, 1.0);
    }
    
    private double calculateExploitability(TrafficAnalysisRequest request, List<LayerDetectionResult> layerResults) {
        // Assess how easily the detected anomaly could be exploited
        double exploitability = 0.3; // Base exploitability
        
        // Check for common exploitation patterns
        boolean hasInjectionPattern = layerResults.stream()
            .anyMatch(layer -> layer.getDetails().toString().contains("injection"));
        
        boolean hasScriptingPattern = layerResults.stream()
            .anyMatch(layer -> layer.getDetails().toString().contains("script"));
        
        if (hasInjectionPattern) exploitability += 0.4;
        if (hasScriptingPattern) exploitability += 0.3;
        
        return Math.min(exploitability, 1.0);
    }
    
    private String assessDataSensitivity(TrafficAnalysisRequest request) {
        String payload = request.getPayload().toLowerCase();
        
        if (payload.contains("password") || payload.contains("ssn") || payload.contains("credit")) {
            return "HIGH";
        } else if (payload.contains("email") || payload.contains("phone") || payload.contains("address")) {
            return "MEDIUM";
        }
        
        return "LOW";
    }
    
    private String assessAttackSurface(TrafficAnalysisRequest request) {
        Map<String, Object> context = request.getContext();
        
        // Assess based on endpoint exposure and technology stack
        if (context.containsKey("public_endpoint") && (Boolean) context.get("public_endpoint")) {
            return "HIGH";
        }
        
        return "MEDIUM";
    }
    
    private String determineRiskCategory(double riskScore) {
        if (riskScore >= 0.8) return "CRITICAL";
        if (riskScore >= 0.6) return "HIGH";
        if (riskScore >= 0.4) return "MEDIUM";
        if (riskScore >= 0.2) return "LOW";
        return "MINIMAL";
    }
    
    private List<String> generateMitigationStrategies(List<LayerDetectionResult> layerResults) {
        Set<String> strategies = new HashSet<>();
        
        for (LayerDetectionResult result : layerResults) {
            if (result.getAnomalyScore() > config.getAnomalyThreshold()) {
                strategies.addAll(result.getMitigationStrategies());
            }
        }
        
        return new ArrayList<>(strategies);
    }
    
    private MultiLayerAnomalyResult createErrorResult(TrafficAnalysisRequest request, Exception e) {
        return new MultiLayerAnomalyResult(
            request.getSessionId(),
            request.getRequestId(),
            0.0,
            new AnomalyClassification("ERROR", "Detection failed: " + e.getMessage(), 0.0, Collections.emptyList()),
            Collections.emptyList(),
            Map.of("error", e.getMessage()),
            Collections.emptyList(),
            new RiskAssessment(0.0, "UNKNOWN", Collections.emptyMap(), Collections.emptyList()),
            Arrays.asList("Review system logs", "Check detection system health"),
            LocalDateTime.now()
        );
    }
    
    // Lifecycle methods
    public void start() {
        isActive = true;
        threatIntelDB.initialize();
        logger.info("Multi-layer anomaly detection system started");
    }
    
    public void stop() {
        isActive = false;
        detectionExecutor.shutdown();
        try {
            if (!detectionExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                detectionExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            detectionExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logger.info("Multi-layer anomaly detection system stopped");
    }
    
    public AnomalyMetrics getMetrics() {
        return metrics;
    }
    
    public boolean isActive() {
        return isActive;
    }
}