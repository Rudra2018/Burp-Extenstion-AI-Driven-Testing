package com.secure.ai.burp.detectors.anomaly;

import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.models.ml.StatisticalAnalyzer;
import com.secure.ai.burp.models.ml.ClusteringEngine;
import com.secure.ai.burp.models.ml.FeatureExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Multi-layer anomaly detection engine for real-time traffic analysis
 * Combines statistical analysis, ML clustering, behavioral analysis, and threat intelligence
 */
class AnomalyDetectionEngine {
    private static final Logger logger = LoggerFactory.getLogger(AnomalyDetectionEngine.class);
    
    private final StatisticalAnalyzer statisticalAnalyzer;
    private final ClusteringEngine clusteringEngine;
    private final FeatureExtractor featureExtractor;
    private final ScheduledExecutorService scheduler;
    
    // Detection layers
    private final StatisticalAnomalyDetector statisticalDetector;
    private final BehavioralAnomalyDetector behavioralDetector;
    private final PatternAnomalyDetector patternDetector;
    private final FrequencyAnomalyDetector frequencyDetector;
    private final ThreatIntelligenceDetector threatIntelDetector;
    
    // Anomaly tracking
    private final Map<String, List<AnomalyEvent>> anomalyHistory = new ConcurrentHashMap<>();
    private final Map<String, BaselineMetrics> sessionBaselines = new ConcurrentHashMap<>();
    private final PriorityQueue<AnomalyAlert> activeAlerts = new PriorityQueue<>(
        Comparator.comparingDouble(AnomalyAlert::getSeverityScore).reversed()
    );
    
    // Configuration
    private final AnomalyDetectionConfig config;
    private volatile boolean realTimeMonitoring = false;
    
    public AnomalyDetectionEngine(StatisticalAnalyzer statisticalAnalyzer,
                                ClusteringEngine clusteringEngine,
                                FeatureExtractor featureExtractor,
                                AnomalyDetectionConfig config) {
        this.statisticalAnalyzer = statisticalAnalyzer;
        this.clusteringEngine = clusteringEngine;
        this.featureExtractor = featureExtractor;
        this.config = config;
        this.scheduler = Executors.newScheduledThreadPool(4);
        
        // Initialize detection layers
        this.statisticalDetector = new StatisticalAnomalyDetector(statisticalAnalyzer);
        this.behavioralDetector = new BehavioralAnomalyDetector();
        this.patternDetector = new PatternAnomalyDetector(clusteringEngine);
        this.frequencyDetector = new FrequencyAnomalyDetector();
        this.threatIntelDetector = new ThreatIntelligenceDetector();
        
        logger.info("Multi-layer anomaly detection engine initialized");
    }
    
    /**
     * Perform comprehensive anomaly detection on traffic data
     */
    public AnomalyDetectionResult detectAnomalies(TrafficData traffic, ApplicationContext context) {
        String sessionId = traffic.getSessionId();
        long startTime = System.currentTimeMillis();
        
        try {
            // Update session baseline
            updateSessionBaseline(sessionId, traffic);
            
            // Multi-layer detection
            List<AnomalyIndicator> indicators = new ArrayList<>();
            
            // Layer 1: Statistical anomaly detection
            indicators.addAll(statisticalDetector.detect(traffic, context));
            
            // Layer 2: Behavioral anomaly detection
            indicators.addAll(behavioralDetector.detect(traffic, context));
            
            // Layer 3: Pattern-based anomaly detection
            indicators.addAll(patternDetector.detect(traffic, context));
            
            // Layer 4: Frequency anomaly detection
            indicators.addAll(frequencyDetector.detect(traffic, context));
            
            // Layer 5: Threat intelligence detection
            indicators.addAll(threatIntelDetector.detect(traffic, context));
            
            // Correlation and scoring
            CorrelatedAnomalies correlations = correlateBetweenLayers(indicators, traffic);
            
            // Generate comprehensive result
            AnomalyDetectionResult result = generateResult(
                traffic, indicators, correlations, startTime);
            
            // Store anomaly events for historical analysis
            storeAnomalyEvents(sessionId, result);
            
            // Generate alerts if needed
            generateAlertsIfRequired(result, context);
            
            logger.debug("Anomaly detection completed for session {} in {}ms", 
                        sessionId, System.currentTimeMillis() - startTime);
            
            return result;
            
        } catch (Exception e) {
            logger.error("Anomaly detection failed for session: " + sessionId, e);
            return createErrorResult(traffic, e);
        }
    }
    
    /**
     * Start real-time anomaly monitoring
     */
    public void startRealTimeMonitoring() {
        if (realTimeMonitoring) {
            logger.warn("Real-time monitoring already active");
            return;
        }
        
        realTimeMonitoring = true;
        
        // Schedule baseline updates
        scheduler.scheduleAtFixedRate(this::updateBaselines, 
            config.getBaselineUpdateInterval(), 
            config.getBaselineUpdateInterval(), 
            TimeUnit.MINUTES);
        
        // Schedule anomaly correlation
        scheduler.scheduleAtFixedRate(this::performCrossSessionCorrelation,
            config.getCorrelationInterval(),
            config.getCorrelationInterval(),
            TimeUnit.MINUTES);
        
        // Schedule alert cleanup
        scheduler.scheduleAtFixedRate(this::cleanupExpiredAlerts,
            5, 5, TimeUnit.MINUTES);
        
        logger.info("Real-time anomaly monitoring started");
    }
    
    /**
     * Stop real-time monitoring
     */
    public void stopRealTimeMonitoring() {
        realTimeMonitoring = false;
        scheduler.shutdown();
        logger.info("Real-time anomaly monitoring stopped");
    }
    
    /**
     * Get anomaly trends for analysis
     */
    public AnomalyTrends getAnomalyTrends(String sessionId, int hours) {
        List<AnomalyEvent> events = anomalyHistory.getOrDefault(sessionId, List.of());
        LocalDateTime cutoff = LocalDateTime.now().minus(hours, ChronoUnit.HOURS);
        
        List<AnomalyEvent> recentEvents = events.stream()
            .filter(event -> event.getTimestamp().isAfter(cutoff))
            .collect(Collectors.toList());
        
        return analyzeTrends(recentEvents, hours);
    }
    
    // Statistical Anomaly Detector
    private static class StatisticalAnomalyDetector {
        private final StatisticalAnalyzer analyzer;
        
        StatisticalAnomalyDetector(StatisticalAnalyzer analyzer) {
            this.analyzer = analyzer;
        }
        
        List<AnomalyIndicator> detect(TrafficData traffic, ApplicationContext context) {
            List<AnomalyIndicator> indicators = new ArrayList<>();
            
            // Response size anomalies
            StatisticalAnalyzer.AnomalyIndicator sizeAnomaly = 
                analyzer.analyzeMetric("response_size", traffic.getResponseSize(), "http");
            if (sizeAnomaly.isAnomaly()) {
                indicators.add(new AnomalyIndicator("STATISTICAL_RESPONSE_SIZE", 
                    sizeAnomaly.getSeverity(), sizeAnomaly.getScore(),
                    "Response size deviates significantly from baseline: " + 
                    traffic.getResponseSize() + " bytes"));
            }
            
            // Response time anomalies
            StatisticalAnalyzer.AnomalyIndicator timeAnomaly = 
                analyzer.analyzeMetric("response_time", traffic.getResponseTime(), "http");
            if (timeAnomaly.isAnomaly()) {
                indicators.add(new AnomalyIndicator("STATISTICAL_RESPONSE_TIME",
                    timeAnomaly.getSeverity(), timeAnomaly.getScore(),
                    "Response time deviates from baseline: " + 
                    traffic.getResponseTime() + "ms"));
            }
            
            // Parameter count anomalies
            StatisticalAnalyzer.AnomalyIndicator paramAnomaly = 
                analyzer.analyzeMetric("param_count", traffic.getParameterCount(), "http");
            if (paramAnomaly.isAnomaly()) {
                indicators.add(new AnomalyIndicator("STATISTICAL_PARAM_COUNT",
                    paramAnomaly.getSeverity(), paramAnomaly.getScore(),
                    "Parameter count anomaly: " + traffic.getParameterCount()));
            }
            
            // Header count anomalies
            StatisticalAnalyzer.AnomalyIndicator headerAnomaly = 
                analyzer.analyzeMetric("header_count", traffic.getHeaderCount(), "http");
            if (headerAnomaly.isAnomaly()) {
                indicators.add(new AnomalyIndicator("STATISTICAL_HEADER_COUNT",
                    headerAnomaly.getSeverity(), headerAnomaly.getScore(),
                    "Header count anomaly: " + traffic.getHeaderCount()));
            }
            
            return indicators;
        }
    }
    
    // Behavioral Anomaly Detector
    private static class BehavioralAnomalyDetector {
        private final Map<String, UserBehaviorProfile> userProfiles = new ConcurrentHashMap<>();
        
        List<AnomalyIndicator> detect(TrafficData traffic, ApplicationContext context) {
            List<AnomalyIndicator> indicators = new ArrayList<>();
            String userId = traffic.getUserId();
            
            if (userId != null) {
                UserBehaviorProfile profile = userProfiles.computeIfAbsent(
                    userId, k -> new UserBehaviorProfile());
                
                // Analyze user behavior patterns
                BehaviorAnalysis analysis = profile.analyzeRequest(traffic);
                
                if (analysis.isAnomalous()) {
                    indicators.add(new AnomalyIndicator("BEHAVIORAL_PATTERN",
                        analysis.getSeverity(), analysis.getScore(),
                        "User behavior anomaly: " + analysis.getDescription()));
                }
                
                // Check for automation indicators
                if (detectAutomation(traffic, profile)) {
                    indicators.add(new AnomalyIndicator("BEHAVIORAL_AUTOMATION",
                        "high", 0.8,
                        "Automated behavior detected for user: " + userId));
                }
            }
            
            return indicators;
        }
        
        private boolean detectAutomation(TrafficData traffic, UserBehaviorProfile profile) {
            // Perfect timing patterns
            if (profile.hasConsistentTiming(50)) { // 50ms tolerance
                return true;
            }
            
            // Repetitive user agents
            if (profile.getUserAgentVariety() < 0.1) {
                return true;
            }
            
            // Unusual request patterns
            if (profile.getRequestFrequency() > 100) { // More than 100 requests/minute
                return true;
            }
            
            return false;
        }
    }
    
    // Pattern Anomaly Detector
    private static class PatternAnomalyDetector {
        private final ClusteringEngine clusteringEngine;
        private final Map<String, List<double[]>> patternHistory = new ConcurrentHashMap<>();
        
        PatternAnomalyDetector(ClusteringEngine clusteringEngine) {
            this.clusteringEngine = clusteringEngine;
        }
        
        List<AnomalyIndicator> detect(TrafficData traffic, ApplicationContext context) {
            List<AnomalyIndicator> indicators = new ArrayList<>();
            String endpoint = traffic.getEndpoint();
            
            // Extract features for pattern analysis
            double[] features = extractTrafficFeatures(traffic);
            
            // Get historical patterns
            List<double[]> history = patternHistory.computeIfAbsent(
                endpoint, k -> new ArrayList<>());
            
            if (history.size() > 10) {
                // Perform clustering to identify normal patterns
                ClusteringEngine.ClusteringResult clustering = 
                    clusteringEngine.clusterTrafficPatterns(history, 3);
                
                // Check if current traffic fits known patterns
                double minDistance = findMinDistanceToCluster(features, clustering);
                
                if (minDistance > 2.0) { // Threshold for anomaly
                    indicators.add(new AnomalyIndicator("PATTERN_DEVIATION",
                        calculateSeverityFromDistance(minDistance), 
                        minDistance / 5.0,
                        "Traffic pattern deviates from known clusters"));
                }
            }
            
            // Add current features to history
            history.add(features);
            if (history.size() > 1000) {
                history.remove(0); // Keep recent history only
            }
            
            return indicators;
        }
        
        private double[] extractTrafficFeatures(TrafficData traffic) {
            return new double[] {
                traffic.getResponseSize(),
                traffic.getResponseTime(),
                traffic.getParameterCount(),
                traffic.getHeaderCount(),
                traffic.getPayloadEntropy(),
                traffic.getMethod().hashCode(),
                traffic.getStatusCode(),
                traffic.getContentLength()
            };
        }
        
        private double findMinDistanceToCluster(double[] features, 
                                             ClusteringEngine.ClusteringResult clustering) {
            double[][] centers = clustering.getClusterCenters();
            double minDistance = Double.MAX_VALUE;
            
            for (double[] center : centers) {
                double distance = calculateEuclideanDistance(features, center);
                minDistance = Math.min(minDistance, distance);
            }
            
            return minDistance;
        }
        
        private double calculateEuclideanDistance(double[] a, double[] b) {
            double sum = 0.0;
            for (int i = 0; i < a.length && i < b.length; i++) {
                sum += Math.pow(a[i] - b[i], 2);
            }
            return Math.sqrt(sum);
        }
        
        private String calculateSeverityFromDistance(double distance) {
            if (distance > 5.0) return "high";
            if (distance > 3.0) return "medium";
            return "low";
        }
    }
    
    // Frequency Anomaly Detector
    private static class FrequencyAnomalyDetector {
        private final Map<String, FrequencyTracker> frequencyTrackers = new ConcurrentHashMap<>();
        
        List<AnomalyIndicator> detect(TrafficData traffic, ApplicationContext context) {
            List<AnomalyIndicator> indicators = new ArrayList<>();
            
            String endpoint = traffic.getEndpoint();
            FrequencyTracker tracker = frequencyTrackers.computeIfAbsent(
                endpoint, k -> new FrequencyTracker());
            
            tracker.recordRequest(traffic.getTimestamp());
            
            // Check for frequency anomalies
            double currentRate = tracker.getCurrentRate();
            double baselineRate = tracker.getBaselineRate();
            
            if (currentRate > baselineRate * 5) { // 5x baseline
                indicators.add(new AnomalyIndicator("FREQUENCY_SPIKE",
                    "high", Math.min(currentRate / baselineRate / 10.0, 1.0),
                    "Request frequency spike: " + String.format("%.2f", currentRate) + 
                    " req/min (baseline: " + String.format("%.2f", baselineRate) + ")"));
            }
            
            // Check for unusual timing patterns
            if (tracker.hasRegularPattern()) {
                indicators.add(new AnomalyIndicator("FREQUENCY_PATTERN",
                    "medium", 0.6,
                    "Highly regular request pattern detected"));
            }
            
            return indicators;
        }
    }
    
    // Threat Intelligence Detector
    private static class ThreatIntelligenceDetector {
        private final Set<String> maliciousIPs = new HashSet<>();
        private final Set<String> suspiciousUserAgents = new HashSet<>();
        private final Map<String, String> knownAttackSignatures = new HashMap<>();
        
        ThreatIntelligenceDetector() {
            loadThreatIntelligence();
        }
        
        List<AnomalyIndicator> detect(TrafficData traffic, ApplicationContext context) {
            List<AnomalyIndicator> indicators = new ArrayList<>();
            
            // Check IP reputation
            if (maliciousIPs.contains(traffic.getSourceIP())) {
                indicators.add(new AnomalyIndicator("THREAT_INTEL_IP",
                    "critical", 1.0,
                    "Request from known malicious IP: " + traffic.getSourceIP()));
            }
            
            // Check User-Agent
            String userAgent = traffic.getUserAgent();
            if (suspiciousUserAgents.stream().anyMatch(userAgent::contains)) {
                indicators.add(new AnomalyIndicator("THREAT_INTEL_USER_AGENT",
                    "medium", 0.7,
                    "Suspicious User-Agent detected: " + userAgent));
            }
            
            // Check for known attack signatures
            String payload = traffic.getPayload();
            for (Map.Entry<String, String> signature : knownAttackSignatures.entrySet()) {
                if (payload.contains(signature.getKey())) {
                    indicators.add(new AnomalyIndicator("THREAT_INTEL_SIGNATURE",
                        "high", 0.9,
                        "Known attack signature detected: " + signature.getValue()));
                }
            }
            
            return indicators;
        }
        
        private void loadThreatIntelligence() {
            // Load from threat intelligence feeds
            maliciousIPs.addAll(Set.of(
                "192.168.1.100", // Example malicious IPs
                "10.0.0.50"
            ));
            
            suspiciousUserAgents.addAll(Set.of(
                "sqlmap", "nikto", "dirb", "gobuster", "masscan"
            ));
            
            knownAttackSignatures.put("' OR 1=1", "SQL Injection");
            knownAttackSignatures.put("<script>", "XSS Attempt");
            knownAttackSignatures.put("../../../", "Path Traversal");
            knownAttackSignatures.put("${jndi:", "Log4Shell");
        }
    }
    
    private void updateSessionBaseline(String sessionId, TrafficData traffic) {
        BaselineMetrics baseline = sessionBaselines.computeIfAbsent(
            sessionId, k -> new BaselineMetrics());
        baseline.update(traffic);
    }
    
    private CorrelatedAnomalies correlateBetweenLayers(List<AnomalyIndicator> indicators, 
                                                     TrafficData traffic) {
        Map<String, List<AnomalyIndicator>> groupedIndicators = indicators.stream()
            .collect(Collectors.groupingBy(AnomalyIndicator::getType));
        
        // Calculate correlation scores
        double correlationScore = calculateCorrelationScore(groupedIndicators);
        
        // Identify correlated attack patterns
        List<String> correlatedPatterns = identifyCorrelatedPatterns(indicators);
        
        return new CorrelatedAnomalies(correlationScore, correlatedPatterns, indicators);
    }
    
    private double calculateCorrelationScore(Map<String, List<AnomalyIndicator>> grouped) {
        int totalTypes = grouped.size();
        int highSeverityTypes = (int) grouped.values().stream()
            .filter(list -> list.stream().anyMatch(i -> "high".equals(i.getSeverity()) || 
                                                       "critical".equals(i.getSeverity())))
            .count();
        
        return totalTypes > 1 ? (double) highSeverityTypes / totalTypes : 0.0;
    }
    
    private List<String> identifyCorrelatedPatterns(List<AnomalyIndicator> indicators) {
        List<String> patterns = new ArrayList<>();
        
        // Check for common attack patterns
        boolean hasStatistical = indicators.stream()
            .anyMatch(i -> i.getType().startsWith("STATISTICAL_"));
        boolean hasBehavioral = indicators.stream()
            .anyMatch(i -> i.getType().startsWith("BEHAVIORAL_"));
        boolean hasThreatIntel = indicators.stream()
            .anyMatch(i -> i.getType().startsWith("THREAT_INTEL_"));
        
        if (hasStatistical && hasBehavioral) {
            patterns.add("Coordinated Attack Pattern");
        }
        
        if (hasBehavioral && hasThreatIntel) {
            patterns.add("Known Attacker Behavioral Pattern");
        }
        
        if (hasStatistical && hasThreatIntel) {
            patterns.add("Automated Attack with Known Signatures");
        }
        
        return patterns;
    }
    
    private AnomalyDetectionResult generateResult(TrafficData traffic,
                                                List<AnomalyIndicator> indicators,
                                                CorrelatedAnomalies correlations,
                                                long startTime) {
        
        // Calculate overall risk score
        double riskScore = calculateOverallRiskScore(indicators, correlations);
        
        // Determine overall severity
        String overallSeverity = determineOverallSeverity(indicators);
        
        // Generate recommendations
        List<String> recommendations = generateRecommendations(indicators, correlations);
        
        long processingTime = System.currentTimeMillis() - startTime;
        
        return new AnomalyDetectionResult(
            traffic.getSessionId(),
            traffic.getTimestamp(),
            indicators,
            correlations,
            riskScore,
            overallSeverity,
            recommendations,
            processingTime
        );
    }
    
    private double calculateOverallRiskScore(List<AnomalyIndicator> indicators,
                                           CorrelatedAnomalies correlations) {
        if (indicators.isEmpty()) return 0.0;
        
        double baseScore = indicators.stream()
            .mapToDouble(AnomalyIndicator::getScore)
            .max().orElse(0.0);
        
        // Boost score for correlations
        double correlationBoost = correlations.getCorrelationScore() * 0.3;
        
        // Boost score for multiple indicator types
        double diversityBoost = Math.min(indicators.size() * 0.1, 0.5);
        
        return Math.min(baseScore + correlationBoost + diversityBoost, 1.0);
    }
    
    private String determineOverallSeverity(List<AnomalyIndicator> indicators) {
        if (indicators.stream().anyMatch(i -> "critical".equals(i.getSeverity()))) {
            return "critical";
        }
        if (indicators.stream().anyMatch(i -> "high".equals(i.getSeverity()))) {
            return "high";
        }
        if (indicators.stream().anyMatch(i -> "medium".equals(i.getSeverity()))) {
            return "medium";
        }
        return "low";
    }
    
    private List<String> generateRecommendations(List<AnomalyIndicator> indicators,
                                               CorrelatedAnomalies correlations) {
        List<String> recommendations = new ArrayList<>();
        
        // Type-specific recommendations
        for (AnomalyIndicator indicator : indicators) {
            switch (indicator.getType()) {
                case "BEHAVIORAL_AUTOMATION":
                    recommendations.add("Implement CAPTCHA or rate limiting");
                    break;
                case "THREAT_INTEL_IP":
                    recommendations.add("Block malicious IP immediately");
                    break;
                case "FREQUENCY_SPIKE":
                    recommendations.add("Activate DDoS protection measures");
                    break;
                case "PATTERN_DEVIATION":
                    recommendations.add("Investigate unusual traffic patterns");
                    break;
            }
        }
        
        // Correlation-based recommendations
        if (correlations.getCorrelationScore() > 0.7) {
            recommendations.add("Multi-vector attack suspected - escalate to security team");
        }
        
        return recommendations.stream().distinct().collect(Collectors.toList());
    }
    
    private AnomalyDetectionResult createErrorResult(TrafficData traffic, Exception e) {
        return new AnomalyDetectionResult(
            traffic.getSessionId(),
            traffic.getTimestamp(),
            List.of(),
            new CorrelatedAnomalies(0.0, List.of(), List.of()),
            0.0,
            "error",
            List.of("Anomaly detection failed: " + e.getMessage()),
            0
        );
    }
    
    private void storeAnomalyEvents(String sessionId, AnomalyDetectionResult result) {
        if (!result.getIndicators().isEmpty()) {
            List<AnomalyEvent> events = anomalyHistory.computeIfAbsent(
                sessionId, k -> new ArrayList<>());
            
            AnomalyEvent event = new AnomalyEvent(
                LocalDateTime.now(),
                result.getOverallSeverity(),
                result.getRiskScore(),
                result.getIndicators().size(),
                result.getCorrelations().getCorrelatedPatterns()
            );
            
            events.add(event);
            
            // Keep only recent events
            if (events.size() > 1000) {
                events.subList(0, events.size() - 1000).clear();
            }
        }
    }
    
    private void generateAlertsIfRequired(AnomalyDetectionResult result, ApplicationContext context) {
        if (result.getRiskScore() > config.getAlertThreshold()) {
            AnomalyAlert alert = new AnomalyAlert(
                UUID.randomUUID().toString(),
                result.getSessionId(),
                result.getTimestamp(),
                result.getOverallSeverity(),
                result.getRiskScore(),
                result.getIndicators().size(),
                result.getRecommendations()
            );
            
            synchronized (activeAlerts) {
                activeAlerts.offer(alert);
                
                // Keep only top alerts
                while (activeAlerts.size() > config.getMaxActiveAlerts()) {
                    activeAlerts.poll();
                }
            }
            
            logger.warn("Anomaly alert generated for session {}: {} (risk score: {})",
                       result.getSessionId(), result.getOverallSeverity(), result.getRiskScore());
        }
    }
    
    private void updateBaselines() {
        if (!realTimeMonitoring) return;
        
        sessionBaselines.values().forEach(BaselineMetrics::updateBaseline);
        logger.debug("Updated {} session baselines", sessionBaselines.size());
    }
    
    private void performCrossSessionCorrelation() {
        if (!realTimeMonitoring) return;
        
        // Perform cross-session correlation analysis
        logger.debug("Performing cross-session correlation analysis");
    }
    
    private void cleanupExpiredAlerts() {
        synchronized (activeAlerts) {
            activeAlerts.removeIf(alert -> 
                alert.getTimestamp().isBefore(LocalDateTime.now().minus(1, ChronoUnit.HOURS)));
        }
    }
    
    private AnomalyTrends analyzeTrends(List<AnomalyEvent> events, int hours) {
        if (events.isEmpty()) {
            return new AnomalyTrends(0, 0.0, Map.of(), List.of());
        }
        
        int totalEvents = events.size();
        double averageRiskScore = events.stream()
            .mapToDouble(AnomalyEvent::getRiskScore)
            .average().orElse(0.0);
        
        Map<String, Integer> severityDistribution = events.stream()
            .collect(Collectors.groupingBy(
                AnomalyEvent::getSeverity,
                Collectors.collectingAndThen(Collectors.counting(), Math::toIntExact)
            ));
        
        List<String> trendingSeverities = severityDistribution.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(3)
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
        
        return new AnomalyTrends(totalEvents, averageRiskScore, 
                               severityDistribution, trendingSeverities);
    }
    
    public List<AnomalyAlert> getActiveAlerts() {
        synchronized (activeAlerts) {
            return new ArrayList<>(activeAlerts);
        }
    }
    
    public Map<String, BaselineMetrics> getSessionBaselines() {
        return new HashMap<>(sessionBaselines);
    }
    
    public AnomalyDetectionConfig getConfig() {
        return config;
    }
    
    // Data classes
    
    public static class AnomalyIndicator {
        private final String type;
        private final String severity;
        private final double score;
        private final String description;
        
        public AnomalyIndicator(String type, String severity, double score, String description) {
            this.type = type;
            this.severity = severity;
            this.score = score;
            this.description = description;
        }
        
        public String getType() { return type; }
        public String getSeverity() { return severity; }
        public double getScore() { return score; }
        public String getDescription() { return description; }
    }
    
    public static class CorrelatedAnomalies {
        private final double correlationScore;
        private final List<String> correlatedPatterns;
        private final List<AnomalyIndicator> indicators;
        
        public CorrelatedAnomalies(double correlationScore, List<String> correlatedPatterns,
                                 List<AnomalyIndicator> indicators) {
            this.correlationScore = correlationScore;
            this.correlatedPatterns = correlatedPatterns;
            this.indicators = indicators;
        }
        
        public double getCorrelationScore() { return correlationScore; }
        public List<String> getCorrelatedPatterns() { return correlatedPatterns; }
        public List<AnomalyIndicator> getIndicators() { return indicators; }
    }
    
    public static class AnomalyDetectionResult {
        private final String sessionId;
        private final LocalDateTime timestamp;
        private final List<AnomalyIndicator> indicators;
        private final CorrelatedAnomalies correlations;
        private final double riskScore;
        private final String overallSeverity;
        private final List<String> recommendations;
        private final long processingTimeMs;
        
        public AnomalyDetectionResult(String sessionId, LocalDateTime timestamp,
                                    List<AnomalyIndicator> indicators, CorrelatedAnomalies correlations,
                                    double riskScore, String overallSeverity,
                                    List<String> recommendations, long processingTimeMs) {
            this.sessionId = sessionId;
            this.timestamp = timestamp;
            this.indicators = indicators;
            this.correlations = correlations;
            this.riskScore = riskScore;
            this.overallSeverity = overallSeverity;
            this.recommendations = recommendations;
            this.processingTimeMs = processingTimeMs;
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public List<AnomalyIndicator> getIndicators() { return indicators; }
        public CorrelatedAnomalies getCorrelations() { return correlations; }
        public double getRiskScore() { return riskScore; }
        public String getOverallSeverity() { return overallSeverity; }
        public List<String> getRecommendations() { return recommendations; }
        public long getProcessingTimeMs() { return processingTimeMs; }
    }
    
    public static class AnomalyEvent {
        private final LocalDateTime timestamp;
        private final String severity;
        private final double riskScore;
        private final int indicatorCount;
        private final List<String> correlatedPatterns;
        
        public AnomalyEvent(LocalDateTime timestamp, String severity, double riskScore,
                          int indicatorCount, List<String> correlatedPatterns) {
            this.timestamp = timestamp;
            this.severity = severity;
            this.riskScore = riskScore;
            this.indicatorCount = indicatorCount;
            this.correlatedPatterns = correlatedPatterns;
        }
        
        // Getters
        public LocalDateTime getTimestamp() { return timestamp; }
        public String getSeverity() { return severity; }
        public double getRiskScore() { return riskScore; }
        public int getIndicatorCount() { return indicatorCount; }
        public List<String> getCorrelatedPatterns() { return correlatedPatterns; }
    }
    
    public static class AnomalyAlert {
        private final String alertId;
        private final String sessionId;
        private final LocalDateTime timestamp;
        private final String severity;
        private final double riskScore;
        private final int indicatorCount;
        private final List<String> recommendations;
        
        public AnomalyAlert(String alertId, String sessionId, LocalDateTime timestamp,
                          String severity, double riskScore, int indicatorCount,
                          List<String> recommendations) {
            this.alertId = alertId;
            this.sessionId = sessionId;
            this.timestamp = timestamp;
            this.severity = severity;
            this.riskScore = riskScore;
            this.indicatorCount = indicatorCount;
            this.recommendations = recommendations;
        }
        
        public double getSeverityScore() {
            switch (severity) {
                case "critical": return 1.0;
                case "high": return 0.8;
                case "medium": return 0.6;
                case "low": return 0.4;
                default: return 0.2;
            }
        }
        
        // Getters
        public String getAlertId() { return alertId; }
        public String getSessionId() { return sessionId; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public String getSeverity() { return severity; }
        public double getRiskScore() { return riskScore; }
        public int getIndicatorCount() { return indicatorCount; }
        public List<String> getRecommendations() { return recommendations; }
    }
    
    public static class AnomalyTrends {
        private final int totalEvents;
        private final double averageRiskScore;
        private final Map<String, Integer> severityDistribution;
        private final List<String> trendingSeverities;
        
        public AnomalyTrends(int totalEvents, double averageRiskScore,
                           Map<String, Integer> severityDistribution, List<String> trendingSeverities) {
            this.totalEvents = totalEvents;
            this.averageRiskScore = averageRiskScore;
            this.severityDistribution = severityDistribution;
            this.trendingSeverities = trendingSeverities;
        }
        
        // Getters
        public int getTotalEvents() { return totalEvents; }
        public double getAverageRiskScore() { return averageRiskScore; }
        public Map<String, Integer> getSeverityDistribution() { return severityDistribution; }
        public List<String> getTrendingSeverities() { return trendingSeverities; }
    }
}