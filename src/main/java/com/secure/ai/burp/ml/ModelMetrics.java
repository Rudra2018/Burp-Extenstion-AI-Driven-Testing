package com.secure.ai.burp.ml;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.DoubleAdder;

/**
 * Comprehensive metrics tracking for ML models
 */
public class ModelMetrics {
    private final String modelName;
    private final boolean isFallbackModel;
    private final long creationTime;
    
    // Performance metrics
    private final AtomicLong totalPredictions = new AtomicLong(0);
    private final AtomicLong successfulPredictions = new AtomicLong(0);
    private final AtomicLong failedPredictions = new AtomicLong(0);
    
    // Accuracy metrics
    private final AtomicLong truePositives = new AtomicLong(0);
    private final AtomicLong falsePositives = new AtomicLong(0);
    private final AtomicLong trueNegatives = new AtomicLong(0);
    private final AtomicLong falseNegatives = new AtomicLong(0);
    
    // Performance timing
    private final DoubleAdder totalInferenceTime = new DoubleAdder();
    private final List<Double> recentInferenceTimes = Collections.synchronizedList(new LinkedList<>());
    private final int MAX_RECENT_TIMES = 100;
    
    // Confidence metrics
    private final DoubleAdder totalConfidence = new DoubleAdder();
    private final List<Double> recentConfidences = Collections.synchronizedList(new LinkedList<>());
    
    // Error tracking
    private final Map<String, AtomicLong> errorCounts = new HashMap<>();
    private final List<String> recentErrors = Collections.synchronizedList(new LinkedList<>());
    
    public ModelMetrics(String modelName) {
        this(modelName, false);
    }
    
    public ModelMetrics(String modelName, boolean isFallbackModel) {
        this.modelName = modelName;
        this.isFallbackModel = isFallbackModel;
        this.creationTime = System.currentTimeMillis();
    }
    
    public void recordPrediction(double inferenceTime, double confidence, boolean successful) {
        totalPredictions.incrementAndGet();
        
        if (successful) {
            successfulPredictions.incrementAndGet();
            totalInferenceTime.add(inferenceTime);
            totalConfidence.add(confidence);
            
            // Track recent metrics
            synchronized (recentInferenceTimes) {
                recentInferenceTimes.add(inferenceTime);
                if (recentInferenceTimes.size() > MAX_RECENT_TIMES) {
                    recentInferenceTimes.remove(0);
                }
            }
            
            synchronized (recentConfidences) {
                recentConfidences.add(confidence);
                if (recentConfidences.size() > MAX_RECENT_TIMES) {
                    recentConfidences.remove(0);
                }
            }
        } else {
            failedPredictions.incrementAndGet();
        }
    }
    
    public void recordAccuracyResult(boolean actualPositive, boolean predictedPositive) {
        if (actualPositive && predictedPositive) {
            truePositives.incrementAndGet();
        } else if (!actualPositive && predictedPositive) {
            falsePositives.incrementAndGet();
        } else if (!actualPositive && !predictedPositive) {
            trueNegatives.incrementAndGet();
        } else {
            falseNegatives.incrementAndGet();
        }
    }
    
    public void recordError(String errorType, String errorMessage) {
        errorCounts.computeIfAbsent(errorType, k -> new AtomicLong(0)).incrementAndGet();
        
        synchronized (recentErrors) {
            recentErrors.add(errorType + ": " + errorMessage);
            if (recentErrors.size() > 50) {
                recentErrors.remove(0);
            }
        }
    }
    
    // Calculated metrics
    public double getSuccessRate() {
        long total = totalPredictions.get();
        return total > 0 ? (double) successfulPredictions.get() / total : 0.0;
    }
    
    public double getAverageInferenceTime() {
        long successful = successfulPredictions.get();
        return successful > 0 ? totalInferenceTime.sum() / successful : 0.0;
    }
    
    public double getRecentAverageInferenceTime() {
        synchronized (recentInferenceTimes) {
            if (recentInferenceTimes.isEmpty()) return 0.0;
            return recentInferenceTimes.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        }
    }
    
    public double getAverageConfidence() {
        long successful = successfulPredictions.get();
        return successful > 0 ? totalConfidence.sum() / successful : 0.0;
    }
    
    public double getRecentAverageConfidence() {
        synchronized (recentConfidences) {
            if (recentConfidences.isEmpty()) return 0.0;
            return recentConfidences.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        }
    }
    
    public double getPrecision() {
        long tp = truePositives.get();
        long fp = falsePositives.get();
        return (tp + fp) > 0 ? (double) tp / (tp + fp) : 0.0;
    }
    
    public double getRecall() {
        long tp = truePositives.get();
        long fn = falseNegatives.get();
        return (tp + fn) > 0 ? (double) tp / (tp + fn) : 0.0;
    }
    
    public double getF1Score() {
        double precision = getPrecision();
        double recall = getRecall();
        return (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;
    }
    
    public double getAccuracy() {
        long tp = truePositives.get();
        long tn = trueNegatives.get();
        long fp = falsePositives.get();
        long fn = falseNegatives.get();
        long total = tp + tn + fp + fn;
        
        return total > 0 ? (double) (tp + tn) / total : 0.0;
    }
    
    public double getSpecificity() {
        long tn = trueNegatives.get();
        long fp = falsePositives.get();
        return (tn + fp) > 0 ? (double) tn / (tn + fp) : 0.0;
    }
    
    public double getErrorRate() {
        long total = totalPredictions.get();
        return total > 0 ? (double) failedPredictions.get() / total : 0.0;
    }
    
    public long getUptime() {
        return System.currentTimeMillis() - creationTime;
    }
    
    public double getThroughput() {
        long uptime = getUptime();
        return uptime > 0 ? (double) totalPredictions.get() / (uptime / 1000.0) : 0.0; // predictions per second
    }
    
    // Getters for raw metrics
    public String getModelName() { return modelName; }
    public boolean isFallbackModel() { return isFallbackModel; }
    public long getCreationTime() { return creationTime; }
    public long getTotalPredictions() { return totalPredictions.get(); }
    public long getSuccessfulPredictions() { return successfulPredictions.get(); }
    public long getFailedPredictions() { return failedPredictions.get(); }
    public long getTruePositives() { return truePositives.get(); }
    public long getFalsePositives() { return falsePositives.get(); }
    public long getTrueNegatives() { return trueNegatives.get(); }
    public long getFalseNegatives() { return falseNegatives.get(); }
    
    public Map<String, Long> getErrorCounts() {
        Map<String, Long> result = new HashMap<>();
        errorCounts.forEach((k, v) -> result.put(k, v.get()));
        return result;
    }
    
    public List<String> getRecentErrors() {
        synchronized (recentErrors) {
            return new ArrayList<>(recentErrors);
        }
    }
    
    public ModelMetricsSummary getSummary() {
        return new ModelMetricsSummary(
            modelName,
            isFallbackModel,
            getTotalPredictions(),
            getSuccessRate(),
            getAverageInferenceTime(),
            getRecentAverageInferenceTime(),
            getAverageConfidence(),
            getRecentAverageConfidence(),
            getPrecision(),
            getRecall(),
            getF1Score(),
            getAccuracy(),
            getSpecificity(),
            getErrorRate(),
            getThroughput(),
            getUptime(),
            getErrorCounts(),
            getRecentErrors()
        );
    }
    
    public static class ModelMetricsSummary {
        private final String modelName;
        private final boolean isFallbackModel;
        private final long totalPredictions;
        private final double successRate;
        private final double averageInferenceTime;
        private final double recentAverageInferenceTime;
        private final double averageConfidence;
        private final double recentAverageConfidence;
        private final double precision;
        private final double recall;
        private final double f1Score;
        private final double accuracy;
        private final double specificity;
        private final double errorRate;
        private final double throughput;
        private final long uptime;
        private final Map<String, Long> errorCounts;
        private final List<String> recentErrors;
        
        public ModelMetricsSummary(String modelName, boolean isFallbackModel, long totalPredictions,
                                 double successRate, double averageInferenceTime, double recentAverageInferenceTime,
                                 double averageConfidence, double recentAverageConfidence, double precision,
                                 double recall, double f1Score, double accuracy, double specificity,
                                 double errorRate, double throughput, long uptime,
                                 Map<String, Long> errorCounts, List<String> recentErrors) {
            this.modelName = modelName;
            this.isFallbackModel = isFallbackModel;
            this.totalPredictions = totalPredictions;
            this.successRate = successRate;
            this.averageInferenceTime = averageInferenceTime;
            this.recentAverageInferenceTime = recentAverageInferenceTime;
            this.averageConfidence = averageConfidence;
            this.recentAverageConfidence = recentAverageConfidence;
            this.precision = precision;
            this.recall = recall;
            this.f1Score = f1Score;
            this.accuracy = accuracy;
            this.specificity = specificity;
            this.errorRate = errorRate;
            this.throughput = throughput;
            this.uptime = uptime;
            this.errorCounts = errorCounts;
            this.recentErrors = recentErrors;
        }
        
        // Getters
        public String getModelName() { return modelName; }
        public boolean isFallbackModel() { return isFallbackModel; }
        public long getTotalPredictions() { return totalPredictions; }
        public double getSuccessRate() { return successRate; }
        public double getAverageInferenceTime() { return averageInferenceTime; }
        public double getRecentAverageInferenceTime() { return recentAverageInferenceTime; }
        public double getAverageConfidence() { return averageConfidence; }
        public double getRecentAverageConfidence() { return recentAverageConfidence; }
        public double getPrecision() { return precision; }
        public double getRecall() { return recall; }
        public double getF1Score() { return f1Score; }
        public double getAccuracy() { return accuracy; }
        public double getSpecificity() { return specificity; }
        public double getErrorRate() { return errorRate; }
        public double getThroughput() { return throughput; }
        public long getUptime() { return uptime; }
        public Map<String, Long> getErrorCounts() { return errorCounts; }
        public List<String> getRecentErrors() { return recentErrors; }
        
        @Override
        public String toString() {
            return String.format(
                "ModelMetrics[%s] - Predictions: %d, Success Rate: %.2f%%, " +
                "Avg Inference: %.2fms, F1: %.3f, Accuracy: %.3f, Throughput: %.2f/s",
                modelName, totalPredictions, successRate * 100,
                averageInferenceTime, f1Score, accuracy, throughput
            );
        }
    }
}