package com.secure.ai.burp.anomaly;

import com.secure.ai.burp.ml.ModelManager;
import com.secure.ai.burp.ml.MLPrediction;
import com.secure.ai.burp.learning.TrafficSample;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.time.LocalDateTime;
import java.time.Duration;

public class AnomalyDetectionEngine {
    private static final Logger logger = LoggerFactory.getLogger(AnomalyDetectionEngine.class);
    
    private final ModelManager modelManager;
    private final StatisticalAnomalyDetector statisticalDetector;
    private final BehavioralAnomalyDetector behavioralDetector;
    private final SequenceAnomalyDetector sequenceDetector;
    private final MLAnomalyDetector mlDetector;
    
    // Baseline models for normal behavior
    private final Map<String, ApplicationBaseline> applicationBaselines;
    private final Map<String, TrafficProfile> trafficProfiles;
    
    // Anomaly thresholds and configuration
    private final AnomalyConfiguration config;
    private final AnomalyHistoryManager historyManager;
    
    // Real-time monitoring
    private final Map<String, RequestSequence> activeSequences;
    private final Queue<AnomalyResult> recentAnomalies;
    
    public AnomalyDetectionEngine(ModelManager modelManager) {
        this.modelManager = modelManager;
        this.statisticalDetector = new StatisticalAnomalyDetector();
        this.behavioralDetector = new BehavioralAnomalyDetector();
        this.sequenceDetector = new SequenceAnomalyDetector();
        this.mlDetector = new MLAnomalyDetector(modelManager);
        
        this.applicationBaselines = new ConcurrentHashMap<>();
        this.trafficProfiles = new ConcurrentHashMap<>();
        this.activeSequences = new ConcurrentHashMap<>();
        this.recentAnomalies = new LinkedList<>();
        
        this.config = new AnomalyConfiguration();
        this.historyManager = new AnomalyHistoryManager();
        
        initialize();
    }
    
    private void initialize() {
        logger.info("Initializing Anomaly Detection Engine...");
        
        // Load pre-trained anomaly detection models
        loadAnomalyModels();
        
        // Initialize baseline detection algorithms
        initializeBaselineDetectors();
        
        logger.info("Anomaly Detection Engine initialized");
    }
    
    private void loadAnomalyModels() {
        try {
            // Load various anomaly detection models
            if (modelManager.isModelLoaded("anomaly_detection")) {
                logger.info("Loaded general anomaly detection model");
            }
            
            // Statistical anomaly model for numerical features
            if (modelManager.isModelLoaded("statistical_anomaly")) {
                logger.info("Loaded statistical anomaly model");
            }
            
            // Sequence anomaly model for request patterns
            if (modelManager.isModelLoaded("sequence_anomaly")) {
                logger.info("Loaded sequence anomaly model");
            }
            
            // Behavioral anomaly model for user behavior
            if (modelManager.isModelLoaded("behavioral_anomaly")) {
                logger.info("Loaded behavioral anomaly model");
            }
            
        } catch (Exception e) {
            logger.warn("Some anomaly detection models not available, using fallback methods", e);
        }
    }
    
    private void initializeBaselineDetectors() {
        // Initialize statistical thresholds
        statisticalDetector.initialize();
        
        // Initialize behavioral pattern baselines
        behavioralDetector.initialize();
        
        // Initialize sequence pattern detection
        sequenceDetector.initialize();
    }
    
    public AnomalyResult detectRealTimeAnomaly(TrafficSample sample) {
        try {
            String host = sample.getHost();
            
            // Get or create baseline for this application
            ApplicationBaseline baseline = getOrCreateBaseline(host);
            
            // Multi-layered anomaly detection
            List<AnomalyIndicator> indicators = new ArrayList<>();
            
            // 1. Statistical anomaly detection
            AnomalyIndicator statistical = statisticalDetector.detect(sample, baseline);
            if (statistical.isAnomalous()) {
                indicators.add(statistical);
            }
            
            // 2. Behavioral anomaly detection
            AnomalyIndicator behavioral = behavioralDetector.detect(sample, baseline);
            if (behavioral.isAnomalous()) {
                indicators.add(behavioral);
            }
            
            // 3. Sequence anomaly detection
            updateRequestSequence(sample);
            AnomalyIndicator sequence = sequenceDetector.detect(sample, getRequestSequence(host));
            if (sequence.isAnomalous()) {
                indicators.add(sequence);
            }
            
            // 4. ML-based anomaly detection
            AnomalyIndicator ml = mlDetector.detect(sample);
            if (ml.isAnomalous()) {
                indicators.add(ml);
            }
            
            // 5. Combined analysis
            AnomalyResult result = combineAnomalyIndicators(indicators, sample);
            
            // Update baseline with this sample (if normal)
            if (!result.isAnomaly() || result.getSeverity() < 5.0) {
                baseline.updateWithSample(sample);
            }
            
            // Record anomaly if significant
            if (result.isAnomaly()) {
                recordAnomaly(result);
            }
            
            return result;
            
        } catch (Exception e) {
            logger.error("Error in real-time anomaly detection", e);
            return new AnomalyResult(sample, false, 0.0, "detection_error", 
                                   "Error during anomaly detection");
        }
    }
    
    public List<AnomalyResult> detectAnomalies(List<TrafficSample> samples) {
        List<AnomalyResult> anomalies = new ArrayList<>();
        
        try {
            // Batch anomaly detection for efficiency
            Map<String, List<TrafficSample>> samplesByHost = groupSamplesByHost(samples);
            
            for (Map.Entry<String, List<TrafficSample>> entry : samplesByHost.entrySet()) {
                String host = entry.getKey();
                List<TrafficSample> hostSamples = entry.getValue();
                
                List<AnomalyResult> hostAnomalies = detectHostAnomalies(host, hostSamples);
                anomalies.addAll(hostAnomalies);
            }
            
            // Cross-host anomaly detection
            List<AnomalyResult> crossHostAnomalies = detectCrossHostAnomalies(samples);
            anomalies.addAll(crossHostAnomalies);
            
        } catch (Exception e) {
            logger.error("Error in batch anomaly detection", e);
        }
        
        return anomalies;
    }
    
    private Map<String, List<TrafficSample>> groupSamplesByHost(List<TrafficSample> samples) {
        Map<String, List<TrafficSample>> grouped = new HashMap<>();
        
        for (TrafficSample sample : samples) {
            grouped.computeIfAbsent(sample.getHost(), k -> new ArrayList<>()).add(sample);
        }
        
        return grouped;
    }
    
    private List<AnomalyResult> detectHostAnomalies(String host, List<TrafficSample> samples) {
        List<AnomalyResult> anomalies = new ArrayList<>();
        ApplicationBaseline baseline = getOrCreateBaseline(host);
        
        // Statistical analysis of samples
        AnomalyResult statisticalResult = statisticalDetector.analyzeBatch(samples, baseline);
        if (statisticalResult.isAnomaly()) {
            anomalies.add(statisticalResult);
        }
        
        // Temporal pattern analysis
        AnomalyResult temporalResult = analyzeTemporalPatterns(samples, baseline);
        if (temporalResult.isAnomaly()) {
            anomalies.add(temporalResult);
        }
        
        // Volume anomaly detection
        AnomalyResult volumeResult = analyzeVolumeAnomalies(samples, baseline);
        if (volumeResult.isAnomaly()) {
            anomalies.add(volumeResult);
        }
        
        return anomalies;
    }
    
    private AnomalyResult analyzeTemporalPatterns(List<TrafficSample> samples, ApplicationBaseline baseline) {
        try {
            // Analyze request timing patterns
            List<Duration> intervals = calculateRequestIntervals(samples);
            
            // Statistical analysis of intervals
            double[] intervalSeconds = intervals.stream().mapToDouble(d -> d.toMillis() / 1000.0).toArray();
            
            double mean = Arrays.stream(intervalSeconds).average().orElse(0.0);
            double stdDev = calculateStandardDeviation(intervalSeconds, mean);
            
            // Compare with baseline
            double baselineMean = baseline.getAverageRequestInterval();
            double baselineStdDev = baseline.getRequestIntervalStdDev();
            
            // Z-score analysis
            double zScore = Math.abs(mean - baselineMean) / Math.max(baselineStdDev, 0.1);
            
            if (zScore > config.getTemporalAnomalyThreshold()) {
                return new AnomalyResult(
                    samples.get(0),
                    true,
                    Math.min(zScore / 2.0, 10.0),
                    "temporal_anomaly",
                    String.format("Unusual request timing pattern detected (z-score: %.2f)", zScore)
                );
            }
            
        } catch (Exception e) {
            logger.debug("Error in temporal pattern analysis", e);
        }
        
        return new AnomalyResult(samples.get(0), false, 0.0, "temporal_normal", "Normal temporal pattern");
    }
    
    private List<Duration> calculateRequestIntervals(List<TrafficSample> samples) {
        List<Duration> intervals = new ArrayList<>();
        
        samples.sort(Comparator.comparing(TrafficSample::getTimestamp));
        
        for (int i = 1; i < samples.size(); i++) {
            Duration interval = Duration.between(
                samples.get(i-1).getTimestamp(),
                samples.get(i).getTimestamp()
            );
            intervals.add(interval);
        }
        
        return intervals;
    }
    
    private double calculateStandardDeviation(double[] values, double mean) {
        double sum = Arrays.stream(values)
                           .map(x -> Math.pow(x - mean, 2))
                           .sum();
        return Math.sqrt(sum / values.length);
    }
    
    private AnomalyResult analyzeVolumeAnomalies(List<TrafficSample> samples, ApplicationBaseline baseline) {
        try {
            // Analyze request volume patterns
            int currentVolume = samples.size();
            double timeSpanMinutes = calculateTimeSpan(samples);
            double requestRate = currentVolume / Math.max(timeSpanMinutes, 1.0);
            
            // Compare with baseline
            double baselineRate = baseline.getAverageRequestRate();
            double rateDeviation = Math.abs(requestRate - baselineRate) / Math.max(baselineRate, 1.0);
            
            if (rateDeviation > config.getVolumeAnomalyThreshold()) {
                double severity = Math.min(rateDeviation * 5.0, 10.0);
                
                return new AnomalyResult(
                    samples.get(0),
                    true,
                    severity,
                    "volume_anomaly",
                    String.format("Unusual request volume detected (rate: %.2f req/min, baseline: %.2f)", 
                                requestRate, baselineRate)
                );
            }
            
        } catch (Exception e) {
            logger.debug("Error in volume anomaly analysis", e);
        }
        
        return new AnomalyResult(samples.get(0), false, 0.0, "volume_normal", "Normal request volume");
    }
    
    private double calculateTimeSpan(List<TrafficSample> samples) {
        if (samples.size() < 2) return 1.0;
        
        LocalDateTime start = samples.stream()
                                    .map(TrafficSample::getTimestamp)
                                    .min(LocalDateTime::compareTo)
                                    .orElse(LocalDateTime.now());
        
        LocalDateTime end = samples.stream()
                                  .map(TrafficSample::getTimestamp)
                                  .max(LocalDateTime::compareTo)
                                  .orElse(LocalDateTime.now());
        
        return Duration.between(start, end).toMinutes();
    }
    
    private List<AnomalyResult> detectCrossHostAnomalies(List<TrafficSample> samples) {
        List<AnomalyResult> anomalies = new ArrayList<>();
        
        try {
            // Detect coordinated attacks across multiple hosts
            AnomalyResult coordinatedAttack = detectCoordinatedAttack(samples);
            if (coordinatedAttack.isAnomaly()) {
                anomalies.add(coordinatedAttack);
            }
            
            // Detect scanning activities
            AnomalyResult scanningActivity = detectScanningActivity(samples);
            if (scanningActivity.isAnomaly()) {
                anomalies.add(scanningActivity);
            }
            
        } catch (Exception e) {
            logger.debug("Error in cross-host anomaly detection", e);
        }
        
        return anomalies;
    }
    
    private AnomalyResult detectCoordinatedAttack(List<TrafficSample> samples) {
        // Group by source characteristics (IP, User-Agent, etc.)
        Map<String, List<TrafficSample>> sourceGroups = groupBySourceFingerprint(samples);
        
        for (Map.Entry<String, List<TrafficSample>> entry : sourceGroups.entrySet()) {
            List<TrafficSample> sourceSamples = entry.getValue();
            
            if (sourceSamples.size() < 3) continue; // Need minimum samples
            
            // Check for coordinated timing
            if (hasCoordinatedTiming(sourceSamples)) {
                return new AnomalyResult(
                    sourceSamples.get(0),
                    true,
                    8.0,
                    "coordinated_attack",
                    "Coordinated attack pattern detected across multiple targets"
                );
            }
        }
        
        return new AnomalyResult(samples.get(0), false, 0.0, "no_coordination", "No coordinated attack detected");
    }
    
    private Map<String, List<TrafficSample>> groupBySourceFingerprint(List<TrafficSample> samples) {
        Map<String, List<TrafficSample>> groups = new HashMap<>();
        
        for (TrafficSample sample : samples) {
            String fingerprint = createSourceFingerprint(sample);
            groups.computeIfAbsent(fingerprint, k -> new ArrayList<>()).add(sample);
        }
        
        return groups;
    }
    
    private String createSourceFingerprint(TrafficSample sample) {
        // Create fingerprint based on request characteristics
        StringBuilder fingerprint = new StringBuilder();
        
        // User-Agent fingerprint
        String userAgent = sample.getRequest().headerValue("User-Agent");
        if (userAgent != null) {
            fingerprint.append(userAgent.hashCode());
        }
        
        // Add other fingerprinting elements
        fingerprint.append("_").append(sample.getRequest().method());
        
        return fingerprint.toString();
    }
    
    private boolean hasCoordinatedTiming(List<TrafficSample> samples) {
        // Check if requests have suspiciously similar timing patterns
        List<LocalDateTime> timestamps = samples.stream()
                                               .map(TrafficSample::getTimestamp)
                                               .sorted()
                                               .collect(java.util.stream.Collectors.toList());
        
        // Calculate intervals between requests
        List<Duration> intervals = new ArrayList<>();
        for (int i = 1; i < timestamps.size(); i++) {
            intervals.add(Duration.between(timestamps.get(i-1), timestamps.get(i)));
        }
        
        // Check for regular intervals (potential automation)
        double avgInterval = intervals.stream()
                                    .mapToLong(Duration::toMillis)
                                    .average()
                                    .orElse(0.0);
        
        double variance = intervals.stream()
                                 .mapToDouble(d -> Math.pow(d.toMillis() - avgInterval, 2))
                                 .average()
                                 .orElse(0.0);
        
        double coefficient = variance / Math.max(avgInterval * avgInterval, 1.0);
        
        // Low coefficient of variation suggests automation
        return coefficient < 0.1 && avgInterval > 100; // Less than 10% variation
    }
    
    private AnomalyResult detectScanningActivity(List<TrafficSample> samples) {
        // Detect port scanning, directory enumeration, etc.
        Map<String, Set<String>> hostPaths = new HashMap<>();
        
        for (TrafficSample sample : samples) {
            String host = sample.getHost();
            String path = sample.getRequest().path();
            
            hostPaths.computeIfAbsent(host, k -> new HashSet<>()).add(path);
        }
        
        // Look for hosts with many unique paths in short time
        for (Map.Entry<String, Set<String>> entry : hostPaths.entrySet()) {
            String host = entry.getKey();
            Set<String> paths = entry.getValue();
            
            if (paths.size() > config.getScanningPathThreshold()) {
                return new AnomalyResult(
                    samples.get(0),
                    true,
                    7.0,
                    "scanning_activity",
                    String.format("Scanning activity detected on %s (%d unique paths)", host, paths.size())
                );
            }
        }
        
        return new AnomalyResult(samples.get(0), false, 0.0, "no_scanning", "No scanning activity detected");
    }
    
    private AnomalyResult combineAnomalyIndicators(List<AnomalyIndicator> indicators, TrafficSample sample) {
        if (indicators.isEmpty()) {
            return new AnomalyResult(sample, false, 0.0, "normal", "No anomalies detected");
        }
        
        // Weight and combine indicators
        double totalWeight = 0.0;
        double weightedScore = 0.0;
        StringBuilder description = new StringBuilder();
        
        for (AnomalyIndicator indicator : indicators) {
            double weight = indicator.getWeight();
            double score = indicator.getSeverity();
            
            totalWeight += weight;
            weightedScore += weight * score;
            
            if (description.length() > 0) {
                description.append("; ");
            }
            description.append(indicator.getDescription());
        }
        
        double finalScore = totalWeight > 0 ? weightedScore / totalWeight : 0.0;
        boolean isAnomaly = finalScore >= config.getAnomalyThreshold();
        
        String primaryType = indicators.get(0).getType();
        
        return new AnomalyResult(sample, isAnomaly, finalScore, primaryType, description.toString());
    }
    
    private ApplicationBaseline getOrCreateBaseline(String host) {
        return applicationBaselines.computeIfAbsent(host, k -> new ApplicationBaseline(k));
    }
    
    private void updateRequestSequence(TrafficSample sample) {
        String host = sample.getHost();
        RequestSequence sequence = activeSequences.computeIfAbsent(host, k -> new RequestSequence(k));
        sequence.addSample(sample);
    }
    
    private RequestSequence getRequestSequence(String host) {
        return activeSequences.get(host);
    }
    
    private void recordAnomaly(AnomalyResult anomaly) {
        // Add to recent anomalies queue
        if (recentAnomalies.size() >= 1000) {
            recentAnomalies.poll();
        }
        recentAnomalies.offer(anomaly);
        
        // Record in history manager
        historyManager.recordAnomaly(anomaly);
        
        logger.debug("Recorded anomaly: {} (severity: {})", anomaly.getType(), anomaly.getSeverity());
    }
    
    public void learnFromConfirmedAnomaly(AnomalyResult anomaly) {
        try {
            // Update detection models based on confirmed anomalies
            String host = anomaly.getSample().getHost();
            ApplicationBaseline baseline = getOrCreateBaseline(host);
            
            // Adjust thresholds based on this confirmed anomaly
            adjustDetectionThresholds(anomaly, baseline);
            
            // Update ML models if available
            if (modelManager.isModelLoaded("anomaly_detection")) {
                updateMLModelWithAnomaly(anomaly);
            }
            
            logger.info("Learned from confirmed anomaly: {}", anomaly.getType());
            
        } catch (Exception e) {
            logger.error("Error learning from confirmed anomaly", e);
        }
    }
    
    private void adjustDetectionThresholds(AnomalyResult anomaly, ApplicationBaseline baseline) {
        // Adjust sensitivity based on confirmed anomalies
        double currentThreshold = config.getAnomalyThreshold();
        double anomalySeverity = anomaly.getSeverity();
        
        // If this was a confirmed anomaly but scored low, increase sensitivity
        if (anomalySeverity < currentThreshold + 1.0) {
            config.adjustSensitivity(anomaly.getType(), 0.1);
        }
    }
    
    private void updateMLModelWithAnomaly(AnomalyResult anomaly) {
        // This would implement online learning for ML models
        // For now, we'll log the learning opportunity
        logger.debug("Updating ML model with anomaly: {}", anomaly.getType());
    }
    
    // Getters and utility methods
    public List<AnomalyResult> getRecentAnomalies(int count) {
        return recentAnomalies.stream()
                             .limit(count)
                             .collect(java.util.stream.Collectors.toList());
    }
    
    public ApplicationBaseline getBaseline(String host) {
        return applicationBaselines.get(host);
    }
    
    public AnomalyConfiguration getConfiguration() {
        return config;
    }
    
    public int getActiveSequencesCount() {
        return activeSequences.size();
    }
    
    public int getBaselinesCount() {
        return applicationBaselines.size();
    }
}