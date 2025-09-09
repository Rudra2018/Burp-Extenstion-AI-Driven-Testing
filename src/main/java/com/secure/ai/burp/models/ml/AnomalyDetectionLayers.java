package com.secure.ai.burp.models.ml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

// Statistical Anomaly Detection Layer
class StatisticalAnomalyLayer {
    private static final Logger logger = LoggerFactory.getLogger(StatisticalAnomalyLayer.class);
    private final StatisticalAnalyzer statisticalAnalyzer;
    
    public StatisticalAnomalyLayer(StatisticalAnalyzer statisticalAnalyzer) {
        this.statisticalAnalyzer = statisticalAnalyzer;
    }
    
    public LayerDetectionResult detectAnomalies(TrafficAnalysisRequest request, float[] features) {
        Map<String, Object> details = new HashMap<>();
        List<AnomalyIndicator> indicators = new ArrayList<>();
        double layerScore = 0.0;
        
        try {
            // Analyze various statistical aspects
            String payload = request.getPayload();
            
            // Length anomaly detection
            double lengthScore = statisticalAnalyzer.analyzeLength(payload, request.getSessionId());
            if (lengthScore > 0.7) {
                indicators.add(new AnomalyIndicator("LENGTH_ANOMALY", "Payload length significantly deviates from baseline", 
                                                  "HIGH", lengthScore, "Monitor for potential buffer overflow attempts"));
            }
            
            // Character distribution anomaly
            double charDistScore = statisticalAnalyzer.analyzeCharacterDistribution(payload);
            if (charDistScore > 0.6) {
                indicators.add(new AnomalyIndicator("CHAR_DISTRIBUTION", "Unusual character distribution detected", 
                                                  "MEDIUM", charDistScore, "Check for encoding anomalies"));
            }
            
            // Entropy analysis
            double entropy = calculateEntropy(payload);
            double entropyScore = statisticalAnalyzer.analyzeEntropy(entropy, payload.length());
            if (entropyScore > 0.8) {
                indicators.add(new AnomalyIndicator("HIGH_ENTROPY", "Payload has unusually high entropy", 
                                                  "HIGH", entropyScore, "Possible obfuscation or encryption attempt"));
            }
            
            // Feature-based statistical analysis
            double featureScore = analyzeFeatureStatistics(features);
            if (featureScore > 0.5) {
                indicators.add(new AnomalyIndicator("FEATURE_ANOMALY", "Statistical anomaly in extracted features", 
                                                  "MEDIUM", featureScore, "Investigate feature patterns"));
            }
            
            // Aggregate layer score
            layerScore = Math.max(Math.max(lengthScore, charDistScore), Math.max(entropyScore, featureScore));
            
            details.put("length_score", lengthScore);
            details.put("char_distribution_score", charDistScore);
            details.put("entropy_score", entropyScore);
            details.put("feature_score", featureScore);
            details.put("payload_entropy", entropy);
            details.put("payload_length", payload.length());
            
        } catch (Exception e) {
            logger.error("Statistical layer analysis failed", e);
            details.put("error", e.getMessage());
        }
        
        return new LayerDetectionResult("Statistical", layerScore, indicators, details, 
                                       generateStatisticalRecommendations(indicators),
                                       generateStatisticalMitigations(indicators));
    }
    
    private double calculateEntropy(String data) {
        Map<Character, Integer> frequency = new HashMap<>();
        for (char c : data.toCharArray()) {
            frequency.put(c, frequency.getOrDefault(c, 0) + 1);
        }
        
        double entropy = 0.0;
        int length = data.length();
        for (int count : frequency.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
    
    private double analyzeFeatureStatistics(float[] features) {
        // Statistical analysis of extracted features
        if (features.length == 0) return 0.0;
        
        double mean = Arrays.stream(features).mapToDouble(f -> f).average().orElse(0.0);
        double variance = Arrays.stream(features).mapToDouble(f -> Math.pow(f - mean, 2)).average().orElse(0.0);
        double stdDev = Math.sqrt(variance);
        
        // Check for extreme values
        long extremeValues = Arrays.stream(features)
            .mapToLong(f -> Math.abs(f - mean) > 3 * stdDev ? 1 : 0)
            .sum();
        
        return Math.min((double) extremeValues / features.length * 2.0, 1.0);
    }
    
    private List<String> generateStatisticalRecommendations(List<AnomalyIndicator> indicators) {
        return indicators.stream()
            .map(indicator -> "Statistical: " + indicator.getReason())
            .collect(Collectors.toList());
    }
    
    private List<String> generateStatisticalMitigations(List<AnomalyIndicator> indicators) {
        Set<String> mitigations = new HashSet<>();
        for (AnomalyIndicator indicator : indicators) {
            switch (indicator.getType()) {
                case "LENGTH_ANOMALY":
                    mitigations.add("Implement payload length limits");
                    mitigations.add("Enable buffer overflow protection");
                    break;
                case "HIGH_ENTROPY":
                    mitigations.add("Implement content inspection for obfuscated payloads");
                    mitigations.add("Block high-entropy suspicious content");
                    break;
            }
        }
        return new ArrayList<>(mitigations);
    }
}

// Behavioral Anomaly Detection Layer
class BehavioralAnomalyLayer {
    private static final Logger logger = LoggerFactory.getLogger(BehavioralAnomalyLayer.class);
    private final Map<String, UserBehaviorProfile> behaviorProfiles = new ConcurrentHashMap<>();
    private final Map<String, RequestPatternAnalyzer> patternAnalyzers = new ConcurrentHashMap<>();
    
    public LayerDetectionResult detectAnomalies(TrafficAnalysisRequest request, float[] features) {
        Map<String, Object> details = new HashMap<>();
        List<AnomalyIndicator> indicators = new ArrayList<>();
        double layerScore = 0.0;
        
        try {
            String sessionId = request.getSessionId();
            String userAgent = (String) request.getContext().getOrDefault("user_agent", "unknown");
            
            // User behavior analysis
            UserBehaviorProfile profile = behaviorProfiles.computeIfAbsent(userAgent, 
                k -> new UserBehaviorProfile(userAgent));
            
            double behaviorScore = profile.analyzeBehavior(request);
            if (behaviorScore > 0.7) {
                indicators.add(new AnomalyIndicator("BEHAVIOR_ANOMALY", "Unusual user behavior pattern detected", 
                                                  "HIGH", behaviorScore, "Investigate user session for automation"));
            }
            
            // Request pattern analysis
            RequestPatternAnalyzer patternAnalyzer = patternAnalyzers.computeIfAbsent(sessionId,
                k -> new RequestPatternAnalyzer(sessionId));
            
            double patternScore = patternAnalyzer.analyzeRequestPattern(request);
            if (patternScore > 0.6) {
                indicators.add(new AnomalyIndicator("PATTERN_ANOMALY", "Abnormal request pattern detected", 
                                                  "MEDIUM", patternScore, "Check for automated scanning"));
            }
            
            // Bot detection
            double botScore = detectBotBehavior(request, profile);
            if (botScore > 0.8) {
                indicators.add(new AnomalyIndicator("BOT_DETECTION", "Automated bot behavior detected", 
                                                  "HIGH", botScore, "Implement CAPTCHA or rate limiting"));
            }
            
            // Session anomaly detection
            double sessionScore = detectSessionAnomalies(request, sessionId);
            if (sessionScore > 0.5) {
                indicators.add(new AnomalyIndicator("SESSION_ANOMALY", "Session behavior anomaly detected", 
                                                  "MEDIUM", sessionScore, "Monitor session for hijacking"));
            }
            
            layerScore = Math.max(Math.max(behaviorScore, patternScore), Math.max(botScore, sessionScore));
            
            details.put("behavior_score", behaviorScore);
            details.put("pattern_score", patternScore);
            details.put("bot_score", botScore);
            details.put("session_score", sessionScore);
            details.put("request_count", profile.getRequestCount());
            details.put("session_duration", calculateSessionDuration(sessionId));
            
        } catch (Exception e) {
            logger.error("Behavioral layer analysis failed", e);
            details.put("error", e.getMessage());
        }
        
        return new LayerDetectionResult("Behavioral", layerScore, indicators, details,
                                       generateBehavioralRecommendations(indicators),
                                       generateBehavioralMitigations(indicators));
    }
    
    private double detectBotBehavior(TrafficAnalysisRequest request, UserBehaviorProfile profile) {
        double botScore = 0.0;
        
        // Check request timing patterns
        if (profile.hasConsistentTiming() && profile.getAverageRequestInterval() < 1000) {
            botScore += 0.4;
        }
        
        // Check user agent patterns
        String userAgent = (String) request.getContext().get("user_agent");
        if (userAgent != null && (userAgent.contains("bot") || userAgent.contains("crawler") || 
                                  userAgent.contains("spider") || userAgent.length() < 20)) {
            botScore += 0.5;
        }
        
        // Check payload patterns
        if (hasAutomatedPayloadPattern(request.getPayload())) {
            botScore += 0.3;
        }
        
        return Math.min(botScore, 1.0);
    }
    
    private double detectSessionAnomalies(TrafficAnalysisRequest request, String sessionId) {
        // Check for session-based anomalies like rapid session creation, unusual session duration, etc.
        double sessionScore = 0.0;
        
        // Rapid session switching
        if (hasRapidSessionSwitching(sessionId)) {
            sessionScore += 0.4;
        }
        
        // Unusual session duration
        long duration = calculateSessionDuration(sessionId);
        if (duration > 0 && (duration < 30000 || duration > 3600000)) { // Less than 30s or more than 1hr
            sessionScore += 0.3;
        }
        
        return sessionScore;
    }
    
    private boolean hasAutomatedPayloadPattern(String payload) {
        // Check for common automated testing patterns
        String[] automatedPatterns = {
            "test", "scan", "probe", "check", "validate", "automated", "script", 
            "<%", "${", "{{", "[[", "((", "))", "]]", "}}", "%>", 
            "1'", "1\"", "1=1", "0=0", "true", "false"
        };
        
        String lowerPayload = payload.toLowerCase();
        for (String pattern : automatedPatterns) {
            if (lowerPayload.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean hasRapidSessionSwitching(String sessionId) {
        // Implementation would check session creation patterns
        return false; // Simplified for demo
    }
    
    private long calculateSessionDuration(String sessionId) {
        // Implementation would calculate actual session duration
        return System.currentTimeMillis(); // Simplified for demo
    }
    
    private List<String> generateBehavioralRecommendations(List<AnomalyIndicator> indicators) {
        return indicators.stream()
            .map(indicator -> "Behavioral: " + indicator.getReason())
            .collect(Collectors.toList());
    }
    
    private List<String> generateBehavioralMitigations(List<AnomalyIndicator> indicators) {
        Set<String> mitigations = new HashSet<>();
        for (AnomalyIndicator indicator : indicators) {
            switch (indicator.getType()) {
                case "BOT_DETECTION":
                    mitigations.add("Implement CAPTCHA verification");
                    mitigations.add("Apply rate limiting for automated requests");
                    break;
                case "BEHAVIOR_ANOMALY":
                    mitigations.add("Require additional authentication");
                    mitigations.add("Monitor user session closely");
                    break;
            }
        }
        return new ArrayList<>(mitigations);
    }
}

// Pattern Anomaly Detection Layer
class PatternAnomalyLayer {
    private static final Logger logger = LoggerFactory.getLogger(PatternAnomalyLayer.class);
    private final PatternLearner patternLearner;
    private final ClusteringEngine clusteringEngine;
    private final List<Pattern> maliciousPatterns;
    
    public PatternAnomalyLayer(PatternLearner patternLearner, ClusteringEngine clusteringEngine) {
        this.patternLearner = patternLearner;
        this.clusteringEngine = clusteringEngine;
        this.maliciousPatterns = initializeMaliciousPatterns();
    }
    
    public LayerDetectionResult detectAnomalies(TrafficAnalysisRequest request, float[] features) {
        Map<String, Object> details = new HashMap<>();
        List<AnomalyIndicator> indicators = new ArrayList<>();
        double layerScore = 0.0;
        
        try {
            String payload = request.getPayload();
            
            // Pattern matching against known attack patterns
            double patternMatchScore = matchMaliciousPatterns(payload);
            if (patternMatchScore > 0.6) {
                indicators.add(new AnomalyIndicator("MALICIOUS_PATTERN", "Known attack pattern detected", 
                                                  "HIGH", patternMatchScore, "Block or investigate malicious pattern"));
            }
            
            // Learned pattern analysis
            double learnedPatternScore = patternLearner.analyzePattern(payload);
            if (learnedPatternScore > 0.5) {
                indicators.add(new AnomalyIndicator("LEARNED_PATTERN", "Similar to previously observed attack pattern", 
                                                  "MEDIUM", learnedPatternScore, "Apply learned countermeasures"));
            }
            
            // Clustering-based anomaly detection
            double clusterScore = analyzeWithClustering(features);
            if (clusterScore > 0.7) {
                indicators.add(new AnomalyIndicator("CLUSTER_ANOMALY", "Request clusters with anomalous patterns", 
                                                  "HIGH", clusterScore, "Investigate clustered attack patterns"));
            }
            
            // Structural pattern analysis
            double structuralScore = analyzeStructuralPatterns(payload);
            if (structuralScore > 0.6) {
                indicators.add(new AnomalyIndicator("STRUCTURAL_ANOMALY", "Unusual structural patterns detected", 
                                                  "MEDIUM", structuralScore, "Check for injection attempts"));
            }
            
            layerScore = Math.max(Math.max(patternMatchScore, learnedPatternScore), 
                                 Math.max(clusterScore, structuralScore));
            
            details.put("pattern_match_score", patternMatchScore);
            details.put("learned_pattern_score", learnedPatternScore);
            details.put("cluster_score", clusterScore);
            details.put("structural_score", structuralScore);
            details.put("matched_patterns", getMatchedPatterns(payload));
            
        } catch (Exception e) {
            logger.error("Pattern layer analysis failed", e);
            details.put("error", e.getMessage());
        }
        
        return new LayerDetectionResult("Pattern", layerScore, indicators, details,
                                       generatePatternRecommendations(indicators),
                                       generatePatternMitigations(indicators));
    }
    
    private List<Pattern> initializeMaliciousPatterns() {
        List<Pattern> patterns = new ArrayList<>();
        
        // SQL Injection patterns
        patterns.add(Pattern.compile("(?i).*\\b(union|select|insert|update|delete|drop|alter|create)\\b.*"));
        patterns.add(Pattern.compile("(?i).*\\b(or|and)\\s+\\d+\\s*=\\s*\\d+.*"));
        patterns.add(Pattern.compile("(?i).*'\\s*(or|and)\\s*'.*"));
        
        // XSS patterns
        patterns.add(Pattern.compile("(?i).*<\\s*script[^>]*>.*"));
        patterns.add(Pattern.compile("(?i).*javascript\\s*:.*"));
        patterns.add(Pattern.compile("(?i).*on\\w+\\s*=.*"));
        
        // Command injection patterns
        patterns.add(Pattern.compile("(?i).*(;|\\||&|\\$\\(|`).*"));
        patterns.add(Pattern.compile("(?i).*\\b(cat|ls|ps|whoami|id|pwd|curl|wget)\\b.*"));
        
        // Path traversal patterns
        patterns.add(Pattern.compile(".*\\.\\./.*"));
        patterns.add(Pattern.compile(".*%2e%2e%2f.*"));
        
        // LDAP injection patterns
        patterns.add(Pattern.compile("(?i).*(\\*|\\(|\\)|\\\\|\\/).*"));
        
        return patterns;
    }
    
    private double matchMaliciousPatterns(String payload) {
        int matchCount = 0;
        for (Pattern pattern : maliciousPatterns) {
            if (pattern.matcher(payload).matches()) {
                matchCount++;
            }
        }
        return Math.min((double) matchCount / 3.0, 1.0); // Normalize to 0-1 range
    }
    
    private double analyzeWithClustering(float[] features) {
        try {
            // Use clustering to detect if this request is an outlier
            List<double[]> featureList = Arrays.asList(convertFloatsToDoubles(features));
            if (clusteringEngine.isOutlier(featureList.get(0))) {
                return 0.8; // High score for outliers
            }
        } catch (Exception e) {
            logger.warn("Clustering analysis failed", e);
        }
        return 0.0;
    }
    
    private double analyzeStructuralPatterns(String payload) {
        double structuralScore = 0.0;
        
        // Check for nested structures
        int nestedStructures = countNestedStructures(payload);
        if (nestedStructures > 3) {
            structuralScore += 0.3;
        }
        
        // Check for unusual character sequences
        if (hasUnusualCharacterSequences(payload)) {
            structuralScore += 0.4;
        }
        
        // Check for encoding anomalies
        if (hasEncodingAnomalies(payload)) {
            structuralScore += 0.3;
        }
        
        return Math.min(structuralScore, 1.0);
    }
    
    private int countNestedStructures(String payload) {
        int count = 0;
        String[] structures = {"()", "{}", "[]", "<>", "''", "\"\""};
        
        for (String structure : structures) {
            char open = structure.charAt(0);
            char close = structure.charAt(1);
            
            int depth = 0;
            int maxDepth = 0;
            
            for (char c : payload.toCharArray()) {
                if (c == open) {
                    depth++;
                    maxDepth = Math.max(maxDepth, depth);
                } else if (c == close) {
                    depth--;
                }
            }
            count += maxDepth;
        }
        
        return count;
    }
    
    private boolean hasUnusualCharacterSequences(String payload) {
        // Check for repeated special characters
        return payload.matches(".*[!@#$%^&*()\\-+=\\[\\]{}|;:'\",.<>?/~`]{3,}.*") ||
               payload.matches(".*\\d{10,}.*") || // Long number sequences
               payload.matches(".*[a-zA-Z]\\1{5,}.*"); // Repeated characters
    }
    
    private boolean hasEncodingAnomalies(String payload) {
        // Check for multiple encoding layers
        long encodedChars = payload.chars()
            .filter(c -> c == '%' || c == '&' || c == '+')
            .count();
        
        return encodedChars > payload.length() * 0.3; // More than 30% encoded characters
    }
    
    private double[] convertFloatsToDoubles(float[] features) {
        double[] doubles = new double[features.length];
        for (int i = 0; i < features.length; i++) {
            doubles[i] = features[i];
        }
        return doubles;
    }
    
    private List<String> getMatchedPatterns(String payload) {
        List<String> matched = new ArrayList<>();
        for (int i = 0; i < maliciousPatterns.size(); i++) {
            if (maliciousPatterns.get(i).matcher(payload).matches()) {
                matched.add("Pattern_" + i);
            }
        }
        return matched;
    }
    
    private List<String> generatePatternRecommendations(List<AnomalyIndicator> indicators) {
        return indicators.stream()
            .map(indicator -> "Pattern: " + indicator.getReason())
            .collect(Collectors.toList());
    }
    
    private List<String> generatePatternMitigations(List<AnomalyIndicator> indicators) {
        Set<String> mitigations = new HashSet<>();
        for (AnomalyIndicator indicator : indicators) {
            switch (indicator.getType()) {
                case "MALICIOUS_PATTERN":
                    mitigations.add("Block known malicious patterns");
                    mitigations.add("Update pattern database");
                    break;
                case "STRUCTURAL_ANOMALY":
                    mitigations.add("Implement input validation");
                    mitigations.add("Sanitize unusual structures");
                    break;
            }
        }
        return new ArrayList<>(mitigations);
    }
}

// Frequency Anomaly Detection Layer  
class FrequencyAnomalyLayer {
    private static final Logger logger = LoggerFactory.getLogger(FrequencyAnomalyLayer.class);
    private final Map<String, RequestFrequencyTracker> frequencyTrackers = new ConcurrentHashMap<>();
    
    public LayerDetectionResult detectAnomalies(TrafficAnalysisRequest request, float[] features) {
        Map<String, Object> details = new HashMap<>();
        List<AnomalyIndicator> indicators = new ArrayList<>();
        double layerScore = 0.0;
        
        try {
            String sessionId = request.getSessionId();
            String sourceIP = (String) request.getContext().getOrDefault("source_ip", "unknown");
            
            // Request frequency analysis
            RequestFrequencyTracker tracker = frequencyTrackers.computeIfAbsent(sourceIP,
                k -> new RequestFrequencyTracker(sourceIP));
            
            double frequencyScore = tracker.analyzeFrequency(request);
            if (frequencyScore > 0.8) {
                indicators.add(new AnomalyIndicator("HIGH_FREQUENCY", "Unusually high request frequency detected", 
                                                  "HIGH", frequencyScore, "Apply rate limiting"));
            }
            
            // Request timing analysis
            double timingScore = analyzeRequestTiming(request, tracker);
            if (timingScore > 0.7) {
                indicators.add(new AnomalyIndicator("TIMING_ANOMALY", "Abnormal request timing pattern", 
                                                  "MEDIUM", timingScore, "Monitor for automated attacks"));
            }
            
            // Burst detection
            double burstScore = detectRequestBursts(tracker);
            if (burstScore > 0.6) {
                indicators.add(new AnomalyIndicator("REQUEST_BURST", "Request burst pattern detected", 
                                                  "MEDIUM", burstScore, "Implement burst protection"));
            }
            
            // Session-based frequency analysis
            double sessionFreqScore = analyzeSessionFrequency(sessionId);
            if (sessionFreqScore > 0.5) {
                indicators.add(new AnomalyIndicator("SESSION_FREQUENCY", "Unusual session request frequency", 
                                                  "LOW", sessionFreqScore, "Monitor session activity"));
            }
            
            layerScore = Math.max(Math.max(frequencyScore, timingScore), 
                                 Math.max(burstScore, sessionFreqScore));
            
            details.put("frequency_score", frequencyScore);
            details.put("timing_score", timingScore);
            details.put("burst_score", burstScore);
            details.put("session_freq_score", sessionFreqScore);
            details.put("requests_per_minute", tracker.getRequestsPerMinute());
            details.put("average_interval", tracker.getAverageInterval());
            
        } catch (Exception e) {
            logger.error("Frequency layer analysis failed", e);
            details.put("error", e.getMessage());
        }
        
        return new LayerDetectionResult("Frequency", layerScore, indicators, details,
                                       generateFrequencyRecommendations(indicators),
                                       generateFrequencyMitigations(indicators));
    }
    
    private double analyzeRequestTiming(TrafficAnalysisRequest request, RequestFrequencyTracker tracker) {
        double timingScore = 0.0;
        
        // Check for overly consistent timing (bot-like behavior)
        if (tracker.hasConsistentTiming() && tracker.getTimingVariance() < 100) {
            timingScore += 0.5;
        }
        
        // Check for extremely rapid requests
        if (tracker.getAverageInterval() < 100) { // Less than 100ms between requests
            timingScore += 0.4;
        }
        
        return Math.min(timingScore, 1.0);
    }
    
    private double detectRequestBursts(RequestFrequencyTracker tracker) {
        // Detect sudden spikes in request frequency
        return tracker.hasBurstPattern() ? 0.7 : 0.0;
    }
    
    private double analyzeSessionFrequency(String sessionId) {
        // Analyze frequency patterns within a session
        // Simplified implementation
        return 0.0;
    }
    
    private List<String> generateFrequencyRecommendations(List<AnomalyIndicator> indicators) {
        return indicators.stream()
            .map(indicator -> "Frequency: " + indicator.getReason())
            .collect(Collectors.toList());
    }
    
    private List<String> generateFrequencyMitigations(List<AnomalyIndicator> indicators) {
        Set<String> mitigations = new HashSet<>();
        for (AnomalyIndicator indicator : indicators) {
            switch (indicator.getType()) {
                case "HIGH_FREQUENCY":
                    mitigations.add("Implement request rate limiting");
                    mitigations.add("Block source IP temporarily");
                    break;
                case "REQUEST_BURST":
                    mitigations.add("Apply burst protection algorithms");
                    mitigations.add("Queue excessive requests");
                    break;
            }
        }
        return new ArrayList<>(mitigations);
    }
}

// Threat Intelligence Layer
class ThreatIntelligenceLayer {
    private static final Logger logger = LoggerFactory.getLogger(ThreatIntelligenceLayer.class);
    private final ThreatIntelligenceDatabase threatIntelDB = new ThreatIntelligenceDatabase();
    
    public LayerDetectionResult detectAnomalies(TrafficAnalysisRequest request, float[] features) {
        Map<String, Object> details = new HashMap<>();
        List<AnomalyIndicator> indicators = new ArrayList<>();
        double layerScore = 0.0;
        
        try {
            String sourceIP = (String) request.getContext().getOrDefault("source_ip", "unknown");
            String userAgent = (String) request.getContext().getOrDefault("user_agent", "");
            String payload = request.getPayload();
            
            // IP reputation check
            double ipReputationScore = threatIntelDB.checkIPReputation(sourceIP);
            if (ipReputationScore > 0.7) {
                indicators.add(new AnomalyIndicator("MALICIOUS_IP", "Source IP has bad reputation", 
                                                  "HIGH", ipReputationScore, "Block or closely monitor malicious IP"));
            }
            
            // User Agent analysis
            double uaScore = threatIntelDB.analyzeUserAgent(userAgent);
            if (uaScore > 0.6) {
                indicators.add(new AnomalyIndicator("SUSPICIOUS_UA", "Suspicious user agent detected", 
                                                  "MEDIUM", uaScore, "Monitor suspicious user agent"));
            }
            
            // Payload signature matching
            double signatureScore = threatIntelDB.matchPayloadSignatures(payload);
            if (signatureScore > 0.8) {
                indicators.add(new AnomalyIndicator("THREAT_SIGNATURE", "Known threat signature detected", 
                                                  "CRITICAL", signatureScore, "Block known threat signature"));
            }
            
            // Geolocation analysis
            double geoScore = threatIntelDB.analyzeGeolocation(sourceIP);
            if (geoScore > 0.5) {
                indicators.add(new AnomalyIndicator("GEO_ANOMALY", "Request from suspicious geolocation", 
                                                  "LOW", geoScore, "Apply geo-based restrictions"));
            }
            
            layerScore = Math.max(Math.max(ipReputationScore, uaScore), 
                                 Math.max(signatureScore, geoScore));
            
            details.put("ip_reputation_score", ipReputationScore);
            details.put("user_agent_score", uaScore);
            details.put("signature_score", signatureScore);
            details.put("geo_score", geoScore);
            details.put("source_ip", sourceIP);
            details.put("threat_categories", threatIntelDB.getThreatCategories(sourceIP));
            
        } catch (Exception e) {
            logger.error("Threat intelligence layer analysis failed", e);
            details.put("error", e.getMessage());
        }
        
        return new LayerDetectionResult("ThreatIntelligence", layerScore, indicators, details,
                                       generateThreatIntelRecommendations(indicators),
                                       generateThreatIntelMitigations(indicators));
    }
    
    private List<String> generateThreatIntelRecommendations(List<AnomalyIndicator> indicators) {
        return indicators.stream()
            .map(indicator -> "ThreatIntel: " + indicator.getReason())
            .collect(Collectors.toList());
    }
    
    private List<String> generateThreatIntelMitigations(List<AnomalyIndicator> indicators) {
        Set<String> mitigations = new HashSet<>();
        for (AnomalyIndicator indicator : indicators) {
            switch (indicator.getType()) {
                case "MALICIOUS_IP":
                    mitigations.add("Block malicious IP addresses");
                    mitigations.add("Update IP blacklist");
                    break;
                case "THREAT_SIGNATURE":
                    mitigations.add("Block known threat signatures");
                    mitigations.add("Update signature database");
                    break;
            }
        }
        return new ArrayList<>(mitigations);
    }
}