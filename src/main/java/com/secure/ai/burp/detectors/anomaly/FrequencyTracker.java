package com.secure.ai.burp.detectors.anomaly;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Frequency tracker for request rate analysis
 */
class FrequencyTracker {
    private final ConcurrentLinkedQueue<LocalDateTime> requestTimes = new ConcurrentLinkedQueue<>();
    private volatile double baselineRate = 1.0; // requests per minute
    private volatile LocalDateTime lastRateCalculation = LocalDateTime.now();
    
    private static final int WINDOW_SIZE_MINUTES = 5;
    private static final int BASELINE_WINDOW_MINUTES = 60;
    
    public void recordRequest(LocalDateTime timestamp) {
        requestTimes.offer(timestamp);
        
        // Clean old entries
        cleanOldEntries(timestamp);
        
        // Update baseline periodically
        if (ChronoUnit.MINUTES.between(lastRateCalculation, timestamp) >= 10) {
            updateBaselineRate(timestamp);
            lastRateCalculation = timestamp;
        }
    }
    
    public double getCurrentRate() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime windowStart = now.minus(WINDOW_SIZE_MINUTES, ChronoUnit.MINUTES);
        
        long recentRequests = requestTimes.stream()
            .filter(time -> time.isAfter(windowStart))
            .count();
        
        return recentRequests / (double) WINDOW_SIZE_MINUTES;
    }
    
    public double getBaselineRate() {
        return baselineRate;
    }
    
    public boolean hasRegularPattern() {
        if (requestTimes.size() < 10) return false;
        
        // Calculate intervals between requests
        LocalDateTime[] times = requestTimes.toArray(new LocalDateTime[0]);
        double[] intervals = new double[times.length - 1];
        
        for (int i = 1; i < times.length; i++) {
            intervals[i - 1] = ChronoUnit.MILLIS.between(times[i - 1], times[i]);
        }
        
        if (intervals.length < 5) return false;
        
        // Calculate coefficient of variation
        double mean = 0.0;
        for (double interval : intervals) {
            mean += interval;
        }
        mean /= intervals.length;
        
        double variance = 0.0;
        for (double interval : intervals) {
            variance += Math.pow(interval - mean, 2);
        }
        variance /= intervals.length;
        
        double stdDev = Math.sqrt(variance);
        double coefficientOfVariation = stdDev / mean;
        
        // Low coefficient of variation indicates regular pattern
        return coefficientOfVariation < 0.1;
    }
    
    private void cleanOldEntries(LocalDateTime currentTime) {
        LocalDateTime cutoff = currentTime.minus(BASELINE_WINDOW_MINUTES, ChronoUnit.MINUTES);
        requestTimes.removeIf(time -> time.isBefore(cutoff));
    }
    
    private void updateBaselineRate(LocalDateTime currentTime) {
        LocalDateTime baselineStart = currentTime.minus(BASELINE_WINDOW_MINUTES, ChronoUnit.MINUTES);
        
        long baselineRequests = requestTimes.stream()
            .filter(time -> time.isAfter(baselineStart))
            .count();
        
        if (baselineRequests > 0) {
            baselineRate = baselineRequests / (double) BASELINE_WINDOW_MINUTES;
        }
    }
    
    public int getRequestCount() {
        return requestTimes.size();
    }
    
    public LocalDateTime getEarliestRequest() {
        return requestTimes.peek();
    }
    
    public LocalDateTime getLatestRequest() {
        return requestTimes.stream()
            .max(LocalDateTime::compareTo)
            .orElse(null);
    }
}