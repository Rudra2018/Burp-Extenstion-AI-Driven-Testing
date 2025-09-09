package com.secure.ai.burp.models.ml;

import java.time.LocalDateTime;
import java.util.Arrays;

class MLPrediction {
    private final String modelName;
    private final float[] predictions;
    private final boolean usingMLModel;
    private final LocalDateTime timestamp;
    private final double confidence;
    private final String predictionClass;
    
    public MLPrediction(String modelName, float[] predictions, boolean usingMLModel) {
        this.modelName = modelName;
        this.predictions = predictions.clone();
        this.usingMLModel = usingMLModel;
        this.timestamp = LocalDateTime.now();
        
        // Calculate confidence and prediction class
        this.confidence = calculateConfidence();
        this.predictionClass = determinePredictionClass();
    }
    
    private double calculateConfidence() {
        if (predictions.length == 0) return 0.0;
        
        // For binary classification, confidence is the max prediction value
        if (predictions.length == 1) {
            return Math.abs(predictions[0] - 0.5) * 2; // Scale to 0-1 range
        }
        
        // For multi-class, confidence is the difference between top two predictions
        float[] sortedPredictions = predictions.clone();
        Arrays.sort(sortedPredictions);
        
        if (sortedPredictions.length >= 2) {
            return sortedPredictions[sortedPredictions.length - 1] - 
                   sortedPredictions[sortedPredictions.length - 2];
        }
        
        return sortedPredictions[sortedPredictions.length - 1];
    }
    
    private String determinePredictionClass() {
        if (predictions.length == 0) return "unknown";
        
        // For binary classification
        if (predictions.length == 1) {
            return predictions[0] > 0.5 ? "positive" : "negative";
        }
        
        // For multi-class, return index of highest prediction
        int maxIndex = 0;
        for (int i = 1; i < predictions.length; i++) {
            if (predictions[i] > predictions[maxIndex]) {
                maxIndex = i;
            }
        }
        
        return "class_" + maxIndex;
    }
    
    public boolean isPositive() {
        if (predictions.length == 0) return false;
        
        if (predictions.length == 1) {
            return predictions[0] > 0.5;
        }
        
        // For multi-class, check if any class has high confidence
        return Arrays.stream(predictions).anyMatch(p -> p > 0.7);
    }
    
    public boolean isHighConfidence() {
        return confidence > 0.7;
    }
    
    public boolean isMediumConfidence() {
        return confidence > 0.4 && confidence <= 0.7;
    }
    
    public boolean isLowConfidence() {
        return confidence <= 0.4;
    }
    
    public float getMaxPrediction() {
        if (predictions.length == 0) return 0.0f;
        
        float max = predictions[0];
        for (float prediction : predictions) {
            if (prediction > max) {
                max = prediction;
            }
        }
        return max;
    }
    
    public int getMaxPredictionIndex() {
        if (predictions.length == 0) return -1;
        
        int maxIndex = 0;
        for (int i = 1; i < predictions.length; i++) {
            if (predictions[i] > predictions[maxIndex]) {
                maxIndex = i;
            }
        }
        return maxIndex;
    }
    
    public VulnerabilityRisk getRiskLevel() {
        double maxPred = getMaxPrediction();
        
        if (maxPred >= 0.8) return VulnerabilityRisk.CRITICAL;
        if (maxPred >= 0.6) return VulnerabilityRisk.HIGH;
        if (maxPred >= 0.4) return VulnerabilityRisk.MEDIUM;
        if (maxPred >= 0.2) return VulnerabilityRisk.LOW;
        return VulnerabilityRisk.INFO;
    }
    
    // Getters
    public String getModelName() { return modelName; }
    public float[] getPredictions() { return predictions.clone(); }
    public boolean isUsingMLModel() { return usingMLModel; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public double getConfidence() { return confidence; }
    public String getPredictionClass() { return predictionClass; }
    
    @Override
    public String toString() {
        return String.format("MLPrediction{model='%s', predictions=%s, confidence=%.3f, class='%s', usingML=%s}", 
                           modelName, Arrays.toString(predictions), confidence, predictionClass, usingMLModel);
    }
    
    public enum VulnerabilityRisk {
        CRITICAL(9.0, 10.0),
        HIGH(7.0, 8.9),
        MEDIUM(4.0, 6.9),
        LOW(1.0, 3.9),
        INFO(0.0, 0.9);
        
        private final double minScore;
        private final double maxScore;
        
        VulnerabilityRisk(double minScore, double maxScore) {
            this.minScore = minScore;
            this.maxScore = maxScore;
        }
        
        public double getMinScore() { return minScore; }
        public double getMaxScore() { return maxScore; }
        public double getMidScore() { return (minScore + maxScore) / 2.0; }
    }
}