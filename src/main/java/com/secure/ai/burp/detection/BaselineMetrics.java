package com.secure.ai.burp.detection;

import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Baseline metrics for session behavior tracking
 */
public class BaselineMetrics {
    private final AtomicLong requestCount = new AtomicLong(0);
    private final RunningStatistics responseSizeStats = new RunningStatistics();
    private final RunningStatistics responseTimeStats = new RunningStatistics();
    private final RunningStatistics parameterCountStats = new RunningStatistics();
    private final RunningStatistics headerCountStats = new RunningStatistics();
    
    private volatile LocalDateTime firstRequest;
    private volatile LocalDateTime lastRequest;
    private volatile LocalDateTime lastBaselineUpdate;
    
    public void update(TrafficData traffic) {
        requestCount.incrementAndGet();
        
        if (firstRequest == null) {
            firstRequest = traffic.getTimestamp();
        }
        lastRequest = traffic.getTimestamp();
        
        responseSizeStats.update(traffic.getResponseSize());
        responseTimeStats.update(traffic.getResponseTime());
        parameterCountStats.update(traffic.getParameterCount());
        headerCountStats.update(traffic.getHeaderCount());
    }
    
    public void updateBaseline() {
        lastBaselineUpdate = LocalDateTime.now();
    }
    
    public long getRequestCount() { return requestCount.get(); }
    public RunningStatistics getResponseSizeStats() { return responseSizeStats; }
    public RunningStatistics getResponseTimeStats() { return responseTimeStats; }
    public RunningStatistics getParameterCountStats() { return parameterCountStats; }
    public RunningStatistics getHeaderCountStats() { return headerCountStats; }
    
    public LocalDateTime getFirstRequest() { return firstRequest; }
    public LocalDateTime getLastRequest() { return lastRequest; }
    public LocalDateTime getLastBaselineUpdate() { return lastBaselineUpdate; }
    
    public static class RunningStatistics {
        private volatile double mean = 0.0;
        private volatile double variance = 0.0;
        private volatile long count = 0;
        private volatile double min = Double.MAX_VALUE;
        private volatile double max = Double.MIN_VALUE;
        
        public synchronized void update(double value) {
            count++;
            
            if (count == 1) {
                mean = value;
                variance = 0.0;
                min = value;
                max = value;
            } else {
                double delta = value - mean;
                mean += delta / count;
                double delta2 = value - mean;
                variance += delta * delta2;
                
                if (value < min) min = value;
                if (value > max) max = value;
            }
        }
        
        public double getMean() { return mean; }
        public double getVariance() { return count > 1 ? variance / (count - 1) : 0.0; }
        public double getStandardDeviation() { return Math.sqrt(getVariance()); }
        public long getCount() { return count; }
        public double getMin() { return count > 0 ? min : 0.0; }
        public double getMax() { return count > 0 ? max : 0.0; }
    }
}