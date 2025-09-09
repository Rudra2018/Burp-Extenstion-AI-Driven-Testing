package com.secure.ai.burp.detection;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * User behavior profile for behavioral anomaly detection
 */
public class UserBehaviorProfile {
    private final Queue<RequestTiming> requestTimings = new ConcurrentLinkedQueue<>();
    private final Set<String> userAgents = new HashSet<>();
    private final Map<String, Integer> endpointFrequency = new HashMap<>();
    private final Map<String, Integer> methodFrequency = new HashMap<>();
    
    private volatile LocalDateTime firstSeen;
    private volatile LocalDateTime lastSeen;
    private volatile int totalRequests = 0;
    
    public BehaviorAnalysis analyzeRequest(TrafficData traffic) {
        updateProfile(traffic);
        
        double anomalyScore = 0.0;
        List<String> anomalousPatterns = new ArrayList<>();
        
        // Analyze request timing
        if (hasUnusualTiming()) {
            anomalyScore += 0.3;
            anomalousPatterns.add("Unusual request timing pattern");
        }
        
        // Analyze endpoint access patterns
        if (hasUnusualEndpointAccess(traffic.getEndpoint())) {
            anomalyScore += 0.2;
            anomalousPatterns.add("Unusual endpoint access pattern");
        }
        
        // Analyze user agent consistency
        if (hasInconsistentUserAgent(traffic.getUserAgent())) {
            anomalyScore += 0.15;
            anomalousPatterns.add("Inconsistent user agent");
        }
        
        // Analyze request method patterns
        if (hasUnusualMethodPattern(traffic.getMethod())) {
            anomalyScore += 0.1;
            anomalousPatterns.add("Unusual HTTP method pattern");
        }
        
        // Analyze session duration
        if (hasUnusualSessionDuration()) {
            anomalyScore += 0.1;
            anomalousPatterns.add("Unusual session duration");
        }
        
        String severity = calculateSeverity(anomalyScore);
        String description = String.join("; ", anomalousPatterns);
        
        return new BehaviorAnalysis(anomalyScore > 0.3, severity, anomalyScore, description);
    }
    
    private void updateProfile(TrafficData traffic) {
        if (firstSeen == null) {
            firstSeen = traffic.getTimestamp();
        }
        lastSeen = traffic.getTimestamp();
        totalRequests++;
        
        // Update timing history
        requestTimings.offer(new RequestTiming(traffic.getTimestamp()));
        while (requestTimings.size() > 100) { // Keep last 100 requests
            requestTimings.poll();
        }
        
        // Update user agents
        userAgents.add(traffic.getUserAgent());
        
        // Update endpoint frequency
        endpointFrequency.merge(traffic.getEndpoint(), 1, Integer::sum);
        
        // Update method frequency
        methodFrequency.merge(traffic.getMethod(), 1, Integer::sum);
    }
    
    public boolean hasConsistentTiming(long toleranceMs) {
        if (requestTimings.size() < 3) return false;
        
        List<Long> intervals = new ArrayList<>();
        RequestTiming prev = null;
        
        for (RequestTiming timing : requestTimings) {
            if (prev != null) {
                long interval = ChronoUnit.MILLIS.between(prev.timestamp, timing.timestamp);
                intervals.add(interval);
            }
            prev = timing;
        }
        
        if (intervals.size() < 2) return false;
        
        // Calculate standard deviation
        double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0.0);
        double variance = intervals.stream()
            .mapToDouble(interval -> Math.pow(interval - mean, 2))
            .average().orElse(0.0);
        double stdDev = Math.sqrt(variance);
        
        return stdDev <= toleranceMs;
    }
    
    public double getUserAgentVariety() {
        return userAgents.size() / (double) Math.max(totalRequests, 1);
    }
    
    public double getRequestFrequency() {
        if (firstSeen == null || lastSeen == null) return 0.0;
        
        long durationMinutes = ChronoUnit.MINUTES.between(firstSeen, lastSeen);
        if (durationMinutes == 0) durationMinutes = 1;
        
        return totalRequests / (double) durationMinutes;
    }
    
    private boolean hasUnusualTiming() {
        if (requestTimings.size() < 5) return false;
        
        // Check for perfect intervals (bot-like behavior)
        if (hasConsistentTiming(100)) return true;
        
        // Check for bursts followed by long pauses
        List<Long> intervals = calculateIntervals();
        if (intervals.isEmpty()) return false;
        
        double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0.0);
        long maxInterval = intervals.stream().mapToLong(Long::longValue).max().orElse(0);
        
        // If max interval is more than 10x the mean, it's suspicious
        return maxInterval > mean * 10;
    }
    
    private boolean hasUnusualEndpointAccess(String currentEndpoint) {
        if (endpointFrequency.size() < 3) return false;
        
        // Check if suddenly accessing a new endpoint type
        int currentCount = endpointFrequency.getOrDefault(currentEndpoint, 0);
        double averageAccess = endpointFrequency.values().stream()
            .mapToInt(Integer::intValue)
            .average().orElse(0.0);
        
        // If this endpoint has never been accessed and user has established patterns
        return currentCount == 0 && totalRequests > 10 && averageAccess > 2.0;
    }
    
    private boolean hasInconsistentUserAgent(String currentUserAgent) {
        if (userAgents.size() <= 2) return false;
        
        // More than 3 different user agents is suspicious
        return userAgents.size() > 3;
    }
    
    private boolean hasUnusualMethodPattern(String currentMethod) {
        if (methodFrequency.size() < 2) return false;
        
        // Check if suddenly using unusual methods
        Set<String> commonMethods = Set.of("GET", "POST");
        if (!commonMethods.contains(currentMethod) && totalRequests > 5) {
            return methodFrequency.getOrDefault(currentMethod, 0) < 2;
        }
        
        return false;
    }
    
    private boolean hasUnusualSessionDuration() {
        if (firstSeen == null || lastSeen == null) return false;
        
        long sessionMinutes = ChronoUnit.MINUTES.between(firstSeen, lastSeen);
        
        // Sessions longer than 12 hours or very short intensive sessions
        return sessionMinutes > 720 || (sessionMinutes < 5 && totalRequests > 50);
    }
    
    private List<Long> calculateIntervals() {
        List<Long> intervals = new ArrayList<>();
        RequestTiming prev = null;
        
        for (RequestTiming timing : requestTimings) {
            if (prev != null) {
                long interval = ChronoUnit.MILLIS.between(prev.timestamp, timing.timestamp);
                intervals.add(interval);
            }
            prev = timing;
        }
        
        return intervals;
    }
    
    private String calculateSeverity(double score) {
        if (score >= 0.8) return "high";
        if (score >= 0.5) return "medium";
        if (score >= 0.3) return "low";
        return "info";
    }
    
    // Getters
    public int getTotalRequests() { return totalRequests; }
    public LocalDateTime getFirstSeen() { return firstSeen; }
    public LocalDateTime getLastSeen() { return lastSeen; }
    public Set<String> getUserAgents() { return new HashSet<>(userAgents); }
    public Map<String, Integer> getEndpointFrequency() { return new HashMap<>(endpointFrequency); }
    
    // Inner classes
    private static class RequestTiming {
        final LocalDateTime timestamp;
        
        RequestTiming(LocalDateTime timestamp) {
            this.timestamp = timestamp;
        }
    }
    
    public static class BehaviorAnalysis {
        private final boolean anomalous;
        private final String severity;
        private final double score;
        private final String description;
        
        public BehaviorAnalysis(boolean anomalous, String severity, double score, String description) {
            this.anomalous = anomalous;
            this.severity = severity;
            this.score = score;
            this.description = description;
        }
        
        public boolean isAnomalous() { return anomalous; }
        public String getSeverity() { return severity; }
        public double getScore() { return score; }
        public String getDescription() { return description; }
    }
}