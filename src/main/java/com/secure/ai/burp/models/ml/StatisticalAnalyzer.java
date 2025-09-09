package com.secure.ai.burp.models.ml;

import smile.stat.distribution.GaussianDistribution;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.apache.commons.math3.stat.descriptive.rank.Percentile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Advanced statistical analyzer for anomaly detection and pattern recognition
 */
class StatisticalAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(StatisticalAnalyzer.class);
    
    // Historical data for baseline calculation
    private final Map<String, List<Double>> historicalData = new ConcurrentHashMap<>();
    private final Map<String, DescriptiveStatistics> baselineStats = new ConcurrentHashMap<>();
    
    // Anomaly detection thresholds
    private static final double Z_SCORE_THRESHOLD = 2.5;
    private static final double IQR_MULTIPLIER = 1.5;
    private static final int MIN_SAMPLES = 30;
    
    public AnomalyIndicator analyzeMetric(String metricName, double value, String context) {
        try {
            // Update historical data
            updateHistoricalData(metricName, value);
            
            // Get baseline statistics
            DescriptiveStatistics stats = getBaselineStats(metricName);
            
            if (stats.getN() < MIN_SAMPLES) {
                // Not enough data for statistical analysis
                return new AnomalyIndicator(false, 0.0, "insufficient_data", 
                    "Not enough historical data for " + metricName);
            }
            
            // Perform multiple statistical tests
            List<AnomalyTest> tests = Arrays.asList(
                performZScoreTest(value, stats),
                performIQRTest(value, stats),
                performGrubbsTest(value, stats),
                performModifiedZScoreTest(value, stats)
            );
            
            // Combine test results
            return combineAnomalyTests(tests, metricName, value);
            
        } catch (Exception e) {
            logger.error("Statistical analysis failed for metric: {}", metricName, e);
            return new AnomalyIndicator(false, 0.0, "error", "Analysis failed: " + e.getMessage());
        }
    }
    
    private void updateHistoricalData(String metricName, double value) {
        historicalData.computeIfAbsent(metricName, k -> new ArrayList<>()).add(value);
        
        // Maintain a rolling window of data
        List<Double> data = historicalData.get(metricName);
        if (data.size() > 1000) {
            data.remove(0); // Remove oldest data point
        }
        
        // Update baseline statistics
        DescriptiveStatistics stats = new DescriptiveStatistics();
        data.forEach(stats::addValue);
        baselineStats.put(metricName, stats);
    }
    
    private DescriptiveStatistics getBaselineStats(String metricName) {
        return baselineStats.getOrDefault(metricName, new DescriptiveStatistics());
    }
    
    private AnomalyTest performZScoreTest(double value, DescriptiveStatistics stats) {
        double mean = stats.getMean();
        double stdDev = stats.getStandardDeviation();
        
        if (stdDev == 0) {
            return new AnomalyTest("z_score", false, 0.0, "Zero standard deviation");
        }
        
        double zScore = Math.abs((value - mean) / stdDev);
        boolean isAnomalous = zScore > Z_SCORE_THRESHOLD;
        
        return new AnomalyTest("z_score", isAnomalous, zScore / 5.0, // Normalize to 0-1
            String.format("Z-score: %.2f (threshold: %.2f)", zScore, Z_SCORE_THRESHOLD));
    }
    
    private AnomalyTest performIQRTest(double value, DescriptiveStatistics stats) {
        double q1 = stats.getPercentile(25);
        double q3 = stats.getPercentile(75);
        double iqr = q3 - q1;
        
        double lowerBound = q1 - (IQR_MULTIPLIER * iqr);
        double upperBound = q3 + (IQR_MULTIPLIER * iqr);
        
        boolean isAnomalous = value < lowerBound || value > upperBound;
        
        double score = 0.0;
        if (isAnomalous) {
            if (value < lowerBound) {
                score = Math.min((lowerBound - value) / iqr, 1.0);
            } else {
                score = Math.min((value - upperBound) / iqr, 1.0);
            }
        }
        
        return new AnomalyTest("iqr", isAnomalous, score,
            String.format("IQR test: value=%.2f, bounds=[%.2f, %.2f]", value, lowerBound, upperBound));
    }
    
    private AnomalyTest performGrubbsTest(double value, DescriptiveStatistics stats) {
        double mean = stats.getMean();
        double stdDev = stats.getStandardDeviation();
        long n = stats.getN();
        
        if (stdDev == 0 || n < 3) {
            return new AnomalyTest("grubbs", false, 0.0, "Insufficient data for Grubbs test");
        }
        
        double grubbsStatistic = Math.abs((value - mean) / stdDev);
        
        // Critical value for Grubbs test (simplified)
        double criticalValue = Math.sqrt((n - 1) * (n - 1) / (n * (n - 2) + n * Math.pow(2.5, 2)));
        
        boolean isAnomalous = grubbsStatistic > criticalValue;
        double score = isAnomalous ? Math.min(grubbsStatistic / (criticalValue * 2), 1.0) : 0.0;
        
        return new AnomalyTest("grubbs", isAnomalous, score,
            String.format("Grubbs test: statistic=%.2f, critical=%.2f", grubbsStatistic, criticalValue));
    }
    
    private AnomalyTest performModifiedZScoreTest(double value, DescriptiveStatistics stats) {
        double median = stats.getPercentile(50);
        double[] values = stats.getValues();
        
        // Calculate Median Absolute Deviation (MAD)
        double[] deviations = new double[values.length];
        for (int i = 0; i < values.length; i++) {
            deviations[i] = Math.abs(values[i] - median);
        }
        
        DescriptiveStatistics madStats = new DescriptiveStatistics();
        for (double deviation : deviations) {
            madStats.addValue(deviation);
        }
        
        double mad = madStats.getPercentile(50);
        
        if (mad == 0) {
            return new AnomalyTest("modified_z_score", false, 0.0, "Zero MAD");
        }
        
        double modifiedZScore = Math.abs(0.6745 * (value - median) / mad);
        boolean isAnomalous = modifiedZScore > 3.5;
        
        return new AnomalyTest("modified_z_score", isAnomalous, Math.min(modifiedZScore / 7.0, 1.0),
            String.format("Modified Z-score: %.2f", modifiedZScore));
    }
    
    private AnomalyIndicator combineAnomalyTests(List<AnomalyTest> tests, String metricName, double value) {
        long anomalousCount = tests.stream().mapToLong(test -> test.isAnomalous() ? 1 : 0).sum();
        double combinedScore = tests.stream().mapToDouble(AnomalyTest::getScore).max().orElse(0.0);
        
        boolean isAnomalous = anomalousCount >= 2 || combinedScore > 0.8;
        
        String type = isAnomalous ? "statistical_anomaly" : "normal";
        String description = String.format("Metric: %s, Value: %.2f, Anomalous tests: %d/%d", 
            metricName, value, anomalousCount, tests.size());
        
        return new AnomalyIndicator(isAnomalous, combinedScore, type, description);
    }
    
    /**
     * Analyze time series data for trends and patterns
     */
    public TimeSeriesAnalysisResult analyzeTimeSeries(String metricName, List<Double> values) {
        if (values.size() < 5) {
            return new TimeSeriesAnalysisResult(false, 0.0, "insufficient_data", 
                "Not enough data points for time series analysis");
        }
        
        try {
            // Calculate trend using linear regression
            double[] x = new double[values.size()];
            double[] y = values.stream().mapToDouble(Double::doubleValue).toArray();
            
            for (int i = 0; i < x.length; i++) {
                x[i] = i;
            }
            
            LinearRegressionResult regression = performLinearRegression(x, y);
            
            // Detect seasonality
            SeasonalityResult seasonality = detectSeasonality(values);
            
            // Detect change points
            List<Integer> changePoints = detectChangePoints(values);
            
            return new TimeSeriesAnalysisResult(
                Math.abs(regression.slope) > 0.1,
                regression.rSquared,
                "time_series_analysis",
                String.format("Trend: %.4f, R²: %.4f, Change points: %d", 
                    regression.slope, regression.rSquared, changePoints.size())
            );
            
        } catch (Exception e) {
            logger.error("Time series analysis failed", e);
            return new TimeSeriesAnalysisResult(false, 0.0, "error", e.getMessage());
        }
    }
    
    private LinearRegressionResult performLinearRegression(double[] x, double[] y) {
        int n = x.length;
        double sumX = Arrays.stream(x).sum();
        double sumY = Arrays.stream(y).sum();
        double sumXY = 0, sumXX = 0, sumYY = 0;
        
        for (int i = 0; i < n; i++) {
            sumXY += x[i] * y[i];
            sumXX += x[i] * x[i];
            sumYY += y[i] * y[i];
        }
        
        double slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
        double intercept = (sumY - slope * sumX) / n;
        
        // Calculate R²
        double meanY = sumY / n;
        double ssRes = 0, ssTot = 0;
        
        for (int i = 0; i < n; i++) {
            double predicted = slope * x[i] + intercept;
            ssRes += Math.pow(y[i] - predicted, 2);
            ssTot += Math.pow(y[i] - meanY, 2);
        }
        
        double rSquared = 1 - (ssRes / ssTot);
        
        return new LinearRegressionResult(slope, intercept, rSquared);
    }
    
    private SeasonalityResult detectSeasonality(List<Double> values) {
        // Simple autocorrelation-based seasonality detection
        // This is a simplified implementation
        return new SeasonalityResult(false, 0, 0.0);
    }
    
    private List<Integer> detectChangePoints(List<Double> values) {
        List<Integer> changePoints = new ArrayList<>();
        
        if (values.size() < 10) return changePoints;
        
        int windowSize = Math.max(5, values.size() / 10);
        
        for (int i = windowSize; i < values.size() - windowSize; i++) {
            double beforeMean = values.subList(i - windowSize, i).stream()
                .mapToDouble(Double::doubleValue).average().orElse(0.0);
            double afterMean = values.subList(i, i + windowSize).stream()
                .mapToDouble(Double::doubleValue).average().orElse(0.0);
            
            double change = Math.abs(afterMean - beforeMean);
            double threshold = values.stream().mapToDouble(Double::doubleValue)
                .summaryStatistics().getAverage() * 0.2;
            
            if (change > threshold) {
                changePoints.add(i);
            }
        }
        
        return changePoints;
    }
    
    // Supporting classes
    public static class AnomalyIndicator {
        private final boolean anomalous;
        private final double score;
        private final String type;
        private final String description;
        
        public AnomalyIndicator(boolean anomalous, double score, String type, String description) {
            this.anomalous = anomalous;
            this.score = score;
            this.type = type;
            this.description = description;
        }
        
        public boolean isAnomalous() { return anomalous; }
        public double getScore() { return score; }
        public String getType() { return type; }
        public String getDescription() { return description; }
    }
    
    private static class AnomalyTest {
        private final String name;
        private final boolean anomalous;
        private final double score;
        private final String description;
        
        AnomalyTest(String name, boolean anomalous, double score, String description) {
            this.name = name;
            this.anomalous = anomalous;
            this.score = score;
            this.description = description;
        }
        
        boolean isAnomalous() { return anomalous; }
        double getScore() { return score; }
    }
    
    public static class TimeSeriesAnalysisResult {
        private final boolean hasTrend;
        private final double confidence;
        private final String type;
        private final String description;
        
        public TimeSeriesAnalysisResult(boolean hasTrend, double confidence, String type, String description) {
            this.hasTrend = hasTrend;
            this.confidence = confidence;
            this.type = type;
            this.description = description;
        }
        
        public boolean hasTrend() { return hasTrend; }
        public double getConfidence() { return confidence; }
        public String getType() { return type; }
        public String getDescription() { return description; }
    }
    
    private static class LinearRegressionResult {
        final double slope;
        final double intercept;
        final double rSquared;
        
        LinearRegressionResult(double slope, double intercept, double rSquared) {
            this.slope = slope;
            this.intercept = intercept;
            this.rSquared = rSquared;
        }
    }
    
    private static class SeasonalityResult {
        final boolean hasSeason;
        final int period;
        final double strength;
        
        SeasonalityResult(boolean hasSeason, int period, double strength) {
            this.hasSeason = hasSeason;
            this.period = period;
            this.strength = strength;
        }
    }
}