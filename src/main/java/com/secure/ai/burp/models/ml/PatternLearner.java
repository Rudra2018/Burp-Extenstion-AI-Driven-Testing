package com.secure.ai.burp.models.ml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Advanced pattern learning system for attack recognition and adaptation
 */
class PatternLearner {
    private static final Logger logger = LoggerFactory.getLogger(PatternLearner.class);
    
    // Pattern storage and learning
    private final Map<String, AttackPattern> learnedPatterns;
    private final Map<String, List<PatternObservation>> observationHistory;
    private final Map<String, Double> patternEffectiveness;
    
    // Learning parameters
    private static final double LEARNING_RATE = 0.1;
    private static final double DECAY_FACTOR = 0.95;
    private static final int MAX_OBSERVATIONS = 1000;
    private static final double MIN_CONFIDENCE_THRESHOLD = 0.6;
    
    // Pattern evolution tracking
    private final AtomicLong totalObservations;
    private final Map<String, Long> patternObservationCounts;
    
    public PatternLearner() {
        this.learnedPatterns = new ConcurrentHashMap<>();
        this.observationHistory = new ConcurrentHashMap<>();
        this.patternEffectiveness = new ConcurrentHashMap<>();
        this.totalObservations = new AtomicLong(0);
        this.patternObservationCounts = new ConcurrentHashMap<>();
        
        logger.info("PatternLearner initialized");
    }
    
    /**
     * Learn from a new attack pattern observation
     */
    public void learnPattern(String pattern, String classification, double effectiveness) {
        try {
            totalObservations.incrementAndGet();
            
            // Extract features from the pattern
            PatternFeatures features = extractPatternFeatures(pattern);
            
            // Create or update attack pattern
            AttackPattern attackPattern = learnedPatterns.computeIfAbsent(
                generatePatternId(features), 
                k -> new AttackPattern(k, features, classification)
            );
            
            // Update pattern with new observation
            updatePattern(attackPattern, effectiveness);
            
            // Record observation
            recordObservation(pattern, classification, effectiveness, features);
            
            // Update effectiveness tracking
            updateEffectiveness(classification, effectiveness);
            
            // Trigger pattern evolution if needed
            if (shouldEvolvePatterns()) {
                evolvePatterns();
            }
            
            logger.debug("Learned pattern: {} with effectiveness: {}", classification, effectiveness);
            
        } catch (Exception e) {
            logger.error("Failed to learn pattern", e);
        }
    }
    
    /**
     * Recognize patterns in new input
     */
    public PatternRecognitionResult recognizePattern(String input) {
        try {
            PatternFeatures inputFeatures = extractPatternFeatures(input);
            
            List<PatternMatch> matches = new ArrayList<>();
            
            // Compare against all learned patterns
            for (AttackPattern pattern : learnedPatterns.values()) {
                double similarity = calculateSimilarity(inputFeatures, pattern.getFeatures());
                
                if (similarity > MIN_CONFIDENCE_THRESHOLD) {
                    double confidence = calculateConfidence(pattern, similarity);
                    matches.add(new PatternMatch(pattern, similarity, confidence));
                }
            }
            
            // Sort by confidence
            matches.sort((a, b) -> Double.compare(b.getConfidence(), a.getConfidence()));
            
            // Return best match or unknown
            if (!matches.isEmpty()) {
                PatternMatch bestMatch = matches.get(0);
                return new PatternRecognitionResult(
                    true,
                    bestMatch.getPattern().getClassification(),
                    bestMatch.getConfidence(),
                    matches,
                    "Pattern recognized with " + matches.size() + " potential matches"
                );
            } else {
                return new PatternRecognitionResult(
                    false,
                    "unknown",
                    0.0,
                    matches,
                    "No matching patterns found"
                );
            }
            
        } catch (Exception e) {
            logger.error("Pattern recognition failed", e);
            return new PatternRecognitionResult(false, "error", 0.0, List.of(), e.getMessage());
        }
    }
    
    /**
     * Get effectiveness statistics for attack types
     */
    public Map<String, EffectivenessStats> getEffectivenessStats() {
        Map<String, EffectivenessStats> stats = new HashMap<>();
        
        for (Map.Entry<String, Double> entry : patternEffectiveness.entrySet()) {
            String classification = entry.getKey();
            Double effectiveness = entry.getValue();
            
            long observations = patternObservationCounts.getOrDefault(classification, 0L);
            
            stats.put(classification, new EffectivenessStats(
                classification,
                effectiveness,
                observations,
                calculateSuccessRate(classification),
                calculateTrendScore(classification)
            ));
        }
        
        return stats;
    }
    
    /**
     * Get top performing attack patterns
     */
    public List<AttackPattern> getTopPatterns(int count) {
        return learnedPatterns.values().stream()
            .sorted((a, b) -> Double.compare(b.getEffectiveness(), a.getEffectiveness()))
            .limit(count)
            .collect(Collectors.toList());
    }
    
    /**
     * Adapt patterns based on new threat intelligence
     */
    public void adaptToThreatIntelligence(List<ThreatIndicator> indicators) {
        logger.info("Adapting to {} threat indicators", indicators.size());
        
        for (ThreatIndicator indicator : indicators) {
            try {
                // Create synthetic pattern from threat indicator
                String syntheticPattern = generateSyntheticPattern(indicator);
                
                // Learn from threat intelligence
                learnPattern(syntheticPattern, indicator.getType(), indicator.getSeverity());
                
                logger.debug("Adapted to threat indicator: {}", indicator.getType());
                
            } catch (Exception e) {
                logger.warn("Failed to adapt to threat indicator: {}", indicator, e);
            }
        }
    }
    
    private PatternFeatures extractPatternFeatures(String pattern) {
        PatternFeatures features = new PatternFeatures();
        
        if (pattern == null || pattern.isEmpty()) {
            return features;
        }
        
        String lowerPattern = pattern.toLowerCase();
        
        // Basic features
        features.length = pattern.length();
        features.wordCount = pattern.split("\\s+").length;
        features.specialCharCount = (int) pattern.chars().filter(c -> !Character.isLetterOrDigit(c) && !Character.isWhitespace(c)).count();
        
        // Content features
        features.hasScript = lowerPattern.contains("script");
        features.hasSQL = lowerPattern.contains("select") || lowerPattern.contains("union") || lowerPattern.contains("drop");
        features.hasJavaScript = lowerPattern.contains("javascript:") || lowerPattern.contains("eval(");
        features.hasHTML = lowerPattern.contains("<") && lowerPattern.contains(">");
        features.hasEncoding = lowerPattern.contains("%") || lowerPattern.contains("&#");
        
        // Structural features
        features.quotesCount = (int) pattern.chars().filter(c -> c == '\'' || c == '"').count();
        features.parenthesesCount = (int) pattern.chars().filter(c -> c == '(' || c == ')').count();
        features.bracketsCount = (int) pattern.chars().filter(c -> c == '[' || c == ']').count();
        features.braceCount = (int) pattern.chars().filter(c -> c == '{' || c == '}').count();
        
        // Entropy and complexity
        features.entropy = calculateEntropy(pattern);
        features.complexity = calculateComplexityScore(pattern);
        
        // N-gram features (simplified)
        features.commonBigrams = extractCommonBigrams(lowerPattern);
        features.commonTrigrams = extractCommonTrigrams(lowerPattern);
        
        return features;
    }
    
    private String generatePatternId(PatternFeatures features) {
        // Generate a unique ID based on pattern features
        StringBuilder id = new StringBuilder();
        
        id.append(features.hasScript ? "S" : "s");
        id.append(features.hasSQL ? "Q" : "q");
        id.append(features.hasJavaScript ? "J" : "j");
        id.append(features.hasHTML ? "H" : "h");
        id.append(features.hasEncoding ? "E" : "e");
        
        id.append("_").append(Integer.toHexString(features.hashCode()));
        
        return id.toString();
    }
    
    private void updatePattern(AttackPattern pattern, double effectiveness) {
        // Update pattern effectiveness using exponential moving average
        double currentEffectiveness = pattern.getEffectiveness();
        double newEffectiveness = currentEffectiveness == 0.0 ? 
            effectiveness : 
            (1 - LEARNING_RATE) * currentEffectiveness + LEARNING_RATE * effectiveness;
            
        pattern.setEffectiveness(newEffectiveness);
        pattern.incrementObservations();
        pattern.setLastSeen(System.currentTimeMillis());
        
        // Apply decay to older patterns
        applyDecayToPattern(pattern);
    }
    
    private void recordObservation(String pattern, String classification, double effectiveness, PatternFeatures features) {
        PatternObservation observation = new PatternObservation(
            pattern,
            classification,
            effectiveness,
            features,
            System.currentTimeMillis()
        );
        
        observationHistory.computeIfAbsent(classification, k -> new ArrayList<>()).add(observation);
        
        // Limit history size
        List<PatternObservation> history = observationHistory.get(classification);
        if (history.size() > MAX_OBSERVATIONS) {
            history.remove(0); // Remove oldest
        }
        
        // Update observation counts
        patternObservationCounts.merge(classification, 1L, Long::sum);
    }
    
    private void updateEffectiveness(String classification, double effectiveness) {
        patternEffectiveness.merge(classification, effectiveness, (oldValue, newValue) -> 
            (1 - LEARNING_RATE) * oldValue + LEARNING_RATE * newValue);
    }
    
    private boolean shouldEvolvePatterns() {
        return totalObservations.get() % 100 == 0; // Evolve every 100 observations
    }
    
    private void evolvePatterns() {
        logger.info("Evolving patterns based on observations");
        
        // Remove ineffective patterns
        learnedPatterns.entrySet().removeIf(entry -> {
            AttackPattern pattern = entry.getValue();
            return pattern.getEffectiveness() < 0.3 && pattern.getObservationCount() > 10;
        });
        
        // Merge similar patterns
        mergeSimilarPatterns();
        
        // Create new patterns from clusters
        createPatternsFromClusters();
        
        logger.info("Pattern evolution complete. {} patterns active", learnedPatterns.size());
    }
    
    private void mergeSimilarPatterns() {
        List<AttackPattern> patterns = new ArrayList<>(learnedPatterns.values());
        
        for (int i = 0; i < patterns.size(); i++) {
            for (int j = i + 1; j < patterns.size(); j++) {
                AttackPattern p1 = patterns.get(i);
                AttackPattern p2 = patterns.get(j);
                
                if (p1.getClassification().equals(p2.getClassification()) &&
                    calculateSimilarity(p1.getFeatures(), p2.getFeatures()) > 0.85) {
                    
                    // Merge patterns
                    AttackPattern merged = mergePatterns(p1, p2);
                    learnedPatterns.remove(p1.getId());
                    learnedPatterns.remove(p2.getId());
                    learnedPatterns.put(merged.getId(), merged);
                    
                    logger.debug("Merged similar patterns: {} and {}", p1.getId(), p2.getId());
                    break;
                }
            }
        }
    }
    
    private void createPatternsFromClusters() {
        // This would use clustering to identify new pattern groups
        // Simplified implementation for now
        logger.debug("Creating patterns from observation clusters");
    }
    
    private double calculateSimilarity(PatternFeatures f1, PatternFeatures f2) {
        double similarity = 0.0;
        int features = 0;
        
        // Binary features
        similarity += (f1.hasScript == f2.hasScript) ? 1 : 0; features++;
        similarity += (f1.hasSQL == f2.hasSQL) ? 1 : 0; features++;
        similarity += (f1.hasJavaScript == f2.hasJavaScript) ? 1 : 0; features++;
        similarity += (f1.hasHTML == f2.hasHTML) ? 1 : 0; features++;
        similarity += (f1.hasEncoding == f2.hasEncoding) ? 1 : 0; features++;
        
        // Numeric features (normalized)
        similarity += 1.0 - Math.abs(f1.entropy - f2.entropy) / Math.max(f1.entropy, f2.entropy);
        features++;
        
        similarity += 1.0 - Math.abs(f1.complexity - f2.complexity) / Math.max(f1.complexity, f2.complexity);
        features++;
        
        // Length similarity
        double lengthSimilarity = 1.0 - Math.abs(f1.length - f2.length) / (double) Math.max(f1.length, f2.length);
        similarity += lengthSimilarity;
        features++;
        
        return similarity / features;
    }
    
    private double calculateConfidence(AttackPattern pattern, double similarity) {
        double baseConfidence = similarity;
        double experienceBoost = Math.min(pattern.getObservationCount() / 100.0, 0.2);
        double effectivenessBoost = pattern.getEffectiveness() * 0.3;
        double recencyBoost = calculateRecencyBoost(pattern);
        
        return Math.min(baseConfidence + experienceBoost + effectivenessBoost + recencyBoost, 1.0);
    }
    
    private double calculateRecencyBoost(AttackPattern pattern) {
        long age = System.currentTimeMillis() - pattern.getLastSeen();
        long maxAge = 24 * 60 * 60 * 1000; // 24 hours
        
        return Math.max(0, 0.1 * (1.0 - (double) age / maxAge));
    }
    
    private void applyDecayToPattern(AttackPattern pattern) {
        long age = System.currentTimeMillis() - pattern.getLastSeen();
        long decayTime = 60 * 60 * 1000; // 1 hour
        
        if (age > decayTime) {
            double decayFactor = Math.pow(DECAY_FACTOR, age / decayTime);
            pattern.setEffectiveness(pattern.getEffectiveness() * decayFactor);
        }
    }
    
    private double calculateSuccessRate(String classification) {
        List<PatternObservation> observations = observationHistory.getOrDefault(classification, List.of());
        
        if (observations.isEmpty()) return 0.0;
        
        long successfulObservations = observations.stream()
            .mapToLong(obs -> obs.getEffectiveness() > 0.5 ? 1 : 0)
            .sum();
            
        return (double) successfulObservations / observations.size();
    }
    
    private double calculateTrendScore(String classification) {
        List<PatternObservation> observations = observationHistory.getOrDefault(classification, List.of());
        
        if (observations.size() < 5) return 0.0;
        
        // Calculate trend using linear regression on recent observations
        List<PatternObservation> recentObservations = observations.stream()
            .skip(Math.max(0, observations.size() - 20))
            .collect(Collectors.toList());
            
        return calculateLinearTrend(recentObservations);
    }
    
    private double calculateLinearTrend(List<PatternObservation> observations) {
        if (observations.size() < 2) return 0.0;
        
        double sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
        int n = observations.size();
        
        for (int i = 0; i < n; i++) {
            double x = i;
            double y = observations.get(i).getEffectiveness();
            
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumXX += x * x;
        }
        
        double slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
        return Math.max(-1.0, Math.min(1.0, slope)); // Normalize to [-1, 1]
    }
    
    private AttackPattern mergePatterns(AttackPattern p1, AttackPattern p2) {
        // Create merged pattern with combined statistics
        PatternFeatures mergedFeatures = mergeFeatures(p1.getFeatures(), p2.getFeatures());
        
        AttackPattern merged = new AttackPattern(
            generatePatternId(mergedFeatures),
            mergedFeatures,
            p1.getClassification()
        );
        
        // Combine statistics
        double combinedEffectiveness = (p1.getEffectiveness() * p1.getObservationCount() + 
                                      p2.getEffectiveness() * p2.getObservationCount()) / 
                                      (p1.getObservationCount() + p2.getObservationCount());
                                      
        merged.setEffectiveness(combinedEffectiveness);
        merged.setObservationCount(p1.getObservationCount() + p2.getObservationCount());
        merged.setLastSeen(Math.max(p1.getLastSeen(), p2.getLastSeen()));
        
        return merged;
    }
    
    private PatternFeatures mergeFeatures(PatternFeatures f1, PatternFeatures f2) {
        PatternFeatures merged = new PatternFeatures();
        
        // Take average/max of numeric features
        merged.length = (f1.length + f2.length) / 2;
        merged.wordCount = (f1.wordCount + f2.wordCount) / 2;
        merged.specialCharCount = (f1.specialCharCount + f2.specialCharCount) / 2;
        merged.quotesCount = (f1.quotesCount + f2.quotesCount) / 2;
        merged.parenthesesCount = (f1.parenthesesCount + f2.parenthesesCount) / 2;
        merged.bracketsCount = (f1.bracketsCount + f2.bracketsCount) / 2;
        merged.braceCount = (f1.braceCount + f2.braceCount) / 2;
        merged.entropy = (f1.entropy + f2.entropy) / 2;
        merged.complexity = (f1.complexity + f2.complexity) / 2;
        
        // Use OR for boolean features
        merged.hasScript = f1.hasScript || f2.hasScript;
        merged.hasSQL = f1.hasSQL || f2.hasSQL;
        merged.hasJavaScript = f1.hasJavaScript || f2.hasJavaScript;
        merged.hasHTML = f1.hasHTML || f2.hasHTML;
        merged.hasEncoding = f1.hasEncoding || f2.hasEncoding;
        
        // Merge n-gram features
        merged.commonBigrams = new HashSet<>(f1.commonBigrams);
        merged.commonBigrams.addAll(f2.commonBigrams);
        
        merged.commonTrigrams = new HashSet<>(f1.commonTrigrams);
        merged.commonTrigrams.addAll(f2.commonTrigrams);
        
        return merged;
    }
    
    private String generateSyntheticPattern(ThreatIndicator indicator) {
        // Generate synthetic patterns based on threat indicator
        StringBuilder pattern = new StringBuilder();
        
        switch (indicator.getType().toLowerCase()) {
            case "xss":
                pattern.append("<script>alert('").append(indicator.getIoc()).append("')</script>");
                break;
            case "sqli":
                pattern.append("' OR '1'='1' --").append(indicator.getIoc());
                break;
            case "cmdi":
                pattern.append(";").append(indicator.getIoc()).append(" | whoami");
                break;
            default:
                pattern.append(indicator.getIoc());
        }
        
        return pattern.toString();
    }
    
    // Helper methods for feature extraction
    private double calculateEntropy(String input) {
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : input.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }
        
        double entropy = 0.0;
        for (int count : freq.values()) {
            double probability = (double) count / input.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
    
    private double calculateComplexityScore(String input) {
        double entropy = calculateEntropy(input);
        double uniqueRatio = input.chars().distinct().count() / (double) input.length();
        double specialCharRatio = input.chars().filter(c -> !Character.isLetterOrDigit(c)).count() / (double) input.length();
        
        return (entropy / 8.0 + uniqueRatio + specialCharRatio) / 3.0; // Normalize
    }
    
    private Set<String> extractCommonBigrams(String input) {
        Set<String> bigrams = new HashSet<>();
        
        for (int i = 0; i < input.length() - 1; i++) {
            bigrams.add(input.substring(i, i + 2));
        }
        
        return bigrams.stream()
            .collect(Collectors.groupingBy(s -> s, Collectors.counting()))
            .entrySet().stream()
            .filter(e -> e.getValue() > 1)
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());
    }
    
    private Set<String> extractCommonTrigrams(String input) {
        Set<String> trigrams = new HashSet<>();
        
        for (int i = 0; i < input.length() - 2; i++) {
            trigrams.add(input.substring(i, i + 3));
        }
        
        return trigrams.stream()
            .collect(Collectors.groupingBy(s -> s, Collectors.counting()))
            .entrySet().stream()
            .filter(e -> e.getValue() > 1)
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet());
    }
    
    // Supporting classes and data structures
    public static class AttackPattern {
        private final String id;
        private final PatternFeatures features;
        private final String classification;
        private double effectiveness;
        private long observationCount;
        private long lastSeen;
        
        public AttackPattern(String id, PatternFeatures features, String classification) {
            this.id = id;
            this.features = features;
            this.classification = classification;
            this.effectiveness = 0.0;
            this.observationCount = 0;
            this.lastSeen = System.currentTimeMillis();
        }
        
        // Getters and setters
        public String getId() { return id; }
        public PatternFeatures getFeatures() { return features; }
        public String getClassification() { return classification; }
        public double getEffectiveness() { return effectiveness; }
        public void setEffectiveness(double effectiveness) { this.effectiveness = effectiveness; }
        public long getObservationCount() { return observationCount; }
        public void setObservationCount(long observationCount) { this.observationCount = observationCount; }
        public void incrementObservations() { this.observationCount++; }
        public long getLastSeen() { return lastSeen; }
        public void setLastSeen(long lastSeen) { this.lastSeen = lastSeen; }
    }
    
    public static class PatternFeatures {
        // Basic features
        public int length;
        public int wordCount;
        public int specialCharCount;
        
        // Content features
        public boolean hasScript;
        public boolean hasSQL;
        public boolean hasJavaScript;
        public boolean hasHTML;
        public boolean hasEncoding;
        
        // Structural features
        public int quotesCount;
        public int parenthesesCount;
        public int bracketsCount;
        public int braceCount;
        
        // Complexity features
        public double entropy;
        public double complexity;
        
        // N-gram features
        public Set<String> commonBigrams = new HashSet<>();
        public Set<String> commonTrigrams = new HashSet<>();
        
        @Override
        public int hashCode() {
            return Objects.hash(length, wordCount, hasScript, hasSQL, hasJavaScript, 
                              hasHTML, hasEncoding, entropy, complexity);
        }
    }
    
    public static class PatternObservation {
        private final String pattern;
        private final String classification;
        private final double effectiveness;
        private final PatternFeatures features;
        private final long timestamp;
        
        public PatternObservation(String pattern, String classification, double effectiveness, 
                                PatternFeatures features, long timestamp) {
            this.pattern = pattern;
            this.classification = classification;
            this.effectiveness = effectiveness;
            this.features = features;
            this.timestamp = timestamp;
        }
        
        public String getPattern() { return pattern; }
        public String getClassification() { return classification; }
        public double getEffectiveness() { return effectiveness; }
        public PatternFeatures getFeatures() { return features; }
        public long getTimestamp() { return timestamp; }
    }
    
    public static class PatternRecognitionResult {
        private final boolean recognized;
        private final String classification;
        private final double confidence;
        private final List<PatternMatch> matches;
        private final String description;
        
        public PatternRecognitionResult(boolean recognized, String classification, double confidence, 
                                      List<PatternMatch> matches, String description) {
            this.recognized = recognized;
            this.classification = classification;
            this.confidence = confidence;
            this.matches = matches;
            this.description = description;
        }
        
        public boolean isRecognized() { return recognized; }
        public String getClassification() { return classification; }
        public double getConfidence() { return confidence; }
        public List<PatternMatch> getMatches() { return matches; }
        public String getDescription() { return description; }
    }
    
    public static class PatternMatch {
        private final AttackPattern pattern;
        private final double similarity;
        private final double confidence;
        
        public PatternMatch(AttackPattern pattern, double similarity, double confidence) {
            this.pattern = pattern;
            this.similarity = similarity;
            this.confidence = confidence;
        }
        
        public AttackPattern getPattern() { return pattern; }
        public double getSimilarity() { return similarity; }
        public double getConfidence() { return confidence; }
    }
    
    public static class EffectivenessStats {
        private final String classification;
        private final double averageEffectiveness;
        private final long totalObservations;
        private final double successRate;
        private final double trendScore;
        
        public EffectivenessStats(String classification, double averageEffectiveness, 
                                long totalObservations, double successRate, double trendScore) {
            this.classification = classification;
            this.averageEffectiveness = averageEffectiveness;
            this.totalObservations = totalObservations;
            this.successRate = successRate;
            this.trendScore = trendScore;
        }
        
        public String getClassification() { return classification; }
        public double getAverageEffectiveness() { return averageEffectiveness; }
        public long getTotalObservations() { return totalObservations; }
        public double getSuccessRate() { return successRate; }
        public double getTrendScore() { return trendScore; }
    }
    
    public static class ThreatIndicator {
        private final String type;
        private final String ioc;
        private final double severity;
        private final long timestamp;
        
        public ThreatIndicator(String type, String ioc, double severity, long timestamp) {
            this.type = type;
            this.ioc = ioc;
            this.severity = severity;
            this.timestamp = timestamp;
        }
        
        public String getType() { return type; }
        public String getIoc() { return ioc; }
        public double getSeverity() { return severity; }
        public long getTimestamp() { return timestamp; }
    }
}