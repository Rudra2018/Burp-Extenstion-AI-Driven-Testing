package com.secure.ai.burp.learners.adaptive;

import burp.api.montoya.http.*;
import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.models.ml.ModelManager;
import com.secure.ai.burp.models.ml.MLPrediction;
import com.secure.ai.burp.integrations.nuclei.NucleiScanResult;
import com.secure.ai.burp.integrations.nuclei.NucleiFinding;
import com.secure.ai.burp.detectors.anomaly.AnomalyDetectionEngine;
import com.secure.ai.burp.patterns.PatternRecognitionEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.*;
import java.time.LocalDateTime;
import java.time.Duration;

class AdvancedLearningEngine {
    private static final Logger logger = LoggerFactory.getLogger(AdvancedLearningEngine.class);
    
    private final ModelManager modelManager;
    private final AnomalyDetectionEngine anomalyEngine;
    private final PatternRecognitionEngine patternEngine;
    private final TrafficLearningModule trafficLearner;
    private final VulnerabilityGapAnalyzer gapAnalyzer;
    private final KnowledgeGraph knowledgeGraph;
    
    // Learning data storage
    private final Map<String, ApplicationLearningProfile> applicationProfiles;
    private final Map<String, AttackPattern> discoveredPatterns;
    private final Map<String, VulnerabilitySignature> learnedSignatures;
    private final Queue<TrafficSample> trafficQueue;
    
    // Performance metrics
    private final LearningMetrics metrics;
    private final ExecutorService learningExecutor;
    
    // Configuration
    private final int maxTrafficSamples = 10000;
    private final int batchLearningSize = 100;
    private final Duration learningInterval = Duration.ofMinutes(5);
    
    public AdvancedLearningEngine(ModelManager modelManager) {
        this.modelManager = modelManager;
        this.anomalyEngine = new AnomalyDetectionEngine(modelManager);
        this.patternEngine = new PatternRecognitionEngine();
        this.trafficLearner = new TrafficLearningModule();
        this.gapAnalyzer = new VulnerabilityGapAnalyzer();
        this.knowledgeGraph = new KnowledgeGraph();
        
        this.applicationProfiles = new ConcurrentHashMap<>();
        this.discoveredPatterns = new ConcurrentHashMap<>();
        this.learnedSignatures = new ConcurrentHashMap<>();
        this.trafficQueue = new ConcurrentLinkedQueue<>();
        this.metrics = new LearningMetrics();
        this.learningExecutor = Executors.newFixedThreadPool(4);
        
        initialize();
    }
    
    public void initialize() {
        logger.info("Initializing Advanced Learning Engine...");
        
        // Start background learning processes
        startContinuousLearning();
        startAnomalyDetection();
        startPatternAnalysis();
        
        logger.info("Advanced Learning Engine initialized");
    }
    
    private void startContinuousLearning() {
        learningExecutor.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    performBatchLearning();
                    Thread.sleep(learningInterval.toMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in continuous learning", e);
                }
            }
        });
    }
    
    private void startAnomalyDetection() {
        learningExecutor.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    performAnomalyDetection();
                    Thread.sleep(30000); // Every 30 seconds
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in anomaly detection", e);
                }
            }
        });
    }
    
    private void startPatternAnalysis() {
        learningExecutor.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    analyzeTrafficPatterns();
                    Thread.sleep(60000); // Every minute
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in pattern analysis", e);
                }
            }
        });
    }
    
    // Main learning methods
    public void learnFromTraffic(HttpRequestToBeSent request, HttpResponseReceived response, ApplicationContext context) {
        try {
            // Create traffic sample
            TrafficSample sample = new TrafficSample(request, response, context, LocalDateTime.now());
            
            // Add to learning queue
            addTrafficSample(sample);
            
            // Immediate anomaly check for critical patterns
            checkForImmediateAnomalies(sample);
            
            // Update application profile
            updateApplicationProfile(sample, context);
            
            metrics.incrementTrafficSamples();
            
        } catch (Exception e) {
            logger.error("Error learning from traffic", e);
        }
    }
    
    private void addTrafficSample(TrafficSample sample) {
        if (trafficQueue.size() >= maxTrafficSamples) {
            trafficQueue.poll(); // Remove oldest sample
        }
        trafficQueue.offer(sample);
    }
    
    private void checkForImmediateAnomalies(TrafficSample sample) {
        try {
            // Real-time anomaly detection for critical patterns
            AnomalyResult anomaly = anomalyEngine.detectRealTimeAnomaly(sample);
            
            if (anomaly.isAnomaly() && anomaly.getSeverity() >= 8.0) {
                logger.warn("Critical anomaly detected: {}", anomaly);
                
                // Create alert
                createSecurityAlert(anomaly, sample);
            }
            
        } catch (Exception e) {
            logger.debug("Error in immediate anomaly detection", e);
        }
    }
    
    private void updateApplicationProfile(TrafficSample sample, ApplicationContext context) {
        String host = sample.getHost();
        ApplicationLearningProfile profile = applicationProfiles.computeIfAbsent(host, 
            k -> new ApplicationLearningProfile(k));
        
        profile.addTrafficSample(sample);
        profile.updateFromContext(context);
    }
    
    public void learnFromNucleiResults(NucleiScanResult result, ApplicationContext context) {
        try {
            logger.info("Learning from Nuclei results: {} findings", result.getFindings().size());
            
            // Analyze what Nuclei found vs our predictions
            analyzeNucleiFindings(result, context);
            
            // Update vulnerability signatures
            updateVulnerabilitySignatures(result);
            
            // Learn new attack patterns
            learnAttackPatternsFromNuclei(result);
            
            // Update knowledge graph
            updateKnowledgeGraph(result, context);
            
            metrics.incrementNucleiLearning();
            
        } catch (Exception e) {
            logger.error("Error learning from Nuclei results", e);
        }
    }
    
    private void analyzeNucleiFindings(NucleiScanResult result, ApplicationContext context) {
        for (NucleiFinding finding : result.getFindings()) {
            // Compare with our predictions
            String vulnType = mapNucleiTemplateToVulnType(finding.getTemplateId());
            
            if (!context.getVulnerabilityHistory().containsKey(vulnType)) {
                // We missed this vulnerability type
                learnFromMissedVulnerability(finding, context);
            } else {
                // We detected this type - validate our accuracy
                validateDetectionAccuracy(finding, context);
            }
        }
    }
    
    private void learnFromMissedVulnerability(NucleiFinding finding, ApplicationContext context) {
        logger.info("Learning from missed vulnerability: {}", finding.getTemplateId());
        
        // Create new vulnerability signature
        VulnerabilitySignature signature = createSignatureFromNucleiFinding(finding);
        learnedSignatures.put(finding.getTemplateId(), signature);
        
        // Update pattern recognition
        patternEngine.learnNewVulnerabilityPattern(finding, context);
        
        // Improve our models
        if (modelManager.isModelLoaded("vulnerability_classifier")) {
            improvePredictionModel(finding, context);
        }
        
        metrics.incrementMissedVulnerabilities();
    }
    
    private VulnerabilitySignature createSignatureFromNucleiFinding(NucleiFinding finding) {
        return new VulnerabilitySignature(
            finding.getTemplateId(),
            finding.getSeverity(),
            extractSignaturePatterns(finding),
            LocalDateTime.now()
        );
    }
    
    private List<String> extractSignaturePatterns(NucleiFinding finding) {
        List<String> patterns = new ArrayList<>();
        
        if (finding.getMatchedAt() != null) {
            patterns.add(finding.getMatchedAt());
        }
        
        if (finding.getExtractedResults() != null) {
            patterns.add(finding.getExtractedResults());
        }
        
        return patterns;
    }
    
    private void validateDetectionAccuracy(NucleiFinding finding, ApplicationContext context) {
        String vulnType = mapNucleiTemplateToVulnType(finding.getTemplateId());
        
        // Check if our confidence was accurate
        double ourRiskScore = context.getRiskScores().getOrDefault(vulnType, 0.0);
        double nucleiRiskScore = finding.getRiskScore();
        
        double accuracy = 1.0 - Math.abs(ourRiskScore - nucleiRiskScore) / 10.0;
        
        if (accuracy > 0.8) {
            metrics.incrementAccurateDetections();
        } else {
            // Learn from inaccurate prediction
            learnFromInaccuratePrediction(vulnType, ourRiskScore, nucleiRiskScore, context);
        }
    }
    
    private void learnFromInaccuratePrediction(String vulnType, double predicted, double actual, ApplicationContext context) {
        logger.debug("Learning from inaccurate prediction: {} (predicted: {}, actual: {})", 
                    vulnType, predicted, actual);
        
        // Adjust our risk scoring algorithm
        adjustRiskScoringWeights(vulnType, predicted, actual, context);
        
        metrics.incrementInaccurateDetections();
    }
    
    private void adjustRiskScoringWeights(String vulnType, double predicted, double actual, ApplicationContext context) {
        // This would implement adaptive weight adjustment for risk scoring
        // For now, we'll log the learning opportunity
        logger.debug("Adjusting risk scoring weights for vulnerability type: {}", vulnType);
    }
    
    public void learnFromTestingGaps(List<String> missedVulnerabilities, ApplicationContext context) {
        logger.info("Learning from {} testing gaps", missedVulnerabilities.size());
        
        for (String vulnType : missedVulnerabilities) {
            // Analyze why we missed this vulnerability type
            TestingGap gap = gapAnalyzer.analyzeGap(vulnType, context);
            
            // Create remediation strategy
            createRemediationStrategy(gap, context);
            
            // Update testing priorities
            updateTestingPriorities(vulnType, context);
        }
        
        metrics.incrementIdentifiedGaps(missedVulnerabilities.size());
    }
    
    private void createRemediationStrategy(TestingGap gap, ApplicationContext context) {
        // Create strategy to improve coverage for this gap
        RemediationStrategy strategy = new RemediationStrategy(gap);
        
        // Update testing algorithms
        strategy.apply(context);
        
        logger.info("Created remediation strategy for gap: {}", gap.getVulnerabilityType());
    }
    
    private void updateTestingPriorities(String vulnType, ApplicationContext context) {
        // Increase priority for this vulnerability type in future testing
        context.getVulnerabilityHistory().put(vulnType + "_priority", 
                                             context.getVulnerabilityHistory().getOrDefault(vulnType + "_priority", 0) + 1);
    }
    
    // Background learning processes
    private void performBatchLearning() {
        try {
            List<TrafficSample> batch = extractLearningBatch();
            if (batch.isEmpty()) return;
            
            logger.debug("Performing batch learning on {} samples", batch.size());
            
            // Pattern recognition
            List<AttackPattern> newPatterns = patternEngine.identifyPatterns(batch);
            for (AttackPattern pattern : newPatterns) {
                discoveredPatterns.put(pattern.getId(), pattern);
            }
            
            // Traffic behavior learning
            trafficLearner.learnFromBatch(batch);
            
            // Update ML models
            updateMLModelsFromBatch(batch);
            
            metrics.incrementBatchLearning();
            
        } catch (Exception e) {
            logger.error("Error in batch learning", e);
        }
    }
    
    private List<TrafficSample> extractLearningBatch() {
        List<TrafficSample> batch = new ArrayList<>();
        for (int i = 0; i < batchLearningSize && !trafficQueue.isEmpty(); i++) {
            TrafficSample sample = trafficQueue.poll();
            if (sample != null) {
                batch.add(sample);
            }
        }
        return batch;
    }
    
    private void updateMLModelsFromBatch(List<TrafficSample> batch) {
        // This would implement online learning for ML models
        // For now, we'll prepare features for future model training
        
        List<float[]> features = new ArrayList<>();
        List<String> labels = new ArrayList<>();
        
        for (TrafficSample sample : batch) {
            float[] sampleFeatures = extractFeaturesFromSample(sample);
            String label = determineLabelFromSample(sample);
            
            features.add(sampleFeatures);
            labels.add(label);
        }
        
        // Store for future model retraining
        storeTrainingData(features, labels);
    }
    
    private float[] extractFeaturesFromSample(TrafficSample sample) {
        // Extract ML features from traffic sample
        float[] features = new float[100]; // Feature vector size
        
        // Request features
        HttpRequestToBeSent request = sample.getRequest();
        features[0] = request.url().length() / 1000.0f;
        features[1] = request.headers().size() / 20.0f;
        features[2] = request.hasBody() ? 1.0f : 0.0f;
        features[3] = request.method().equals("POST") ? 1.0f : 0.0f;
        
        // Response features if available
        if (sample.getResponse() != null) {
            HttpResponseReceived response = sample.getResponse();
            features[10] = response.statusCode() / 600.0f;
            features[11] = response.body().length() / 10000.0f;
            features[12] = response.headers().size() / 20.0f;
        }
        
        // Context features
        ApplicationContext context = sample.getContext();
        features[20] = context.getDetectedTechnologies().size() / 10.0f;
        features[21] = context.getOverallRiskScore() / 10.0f;
        features[22] = context.getRequestCount() / 1000.0f;
        
        return features;
    }
    
    private String determineLabelFromSample(TrafficSample sample) {
        // Determine if this sample represents normal or anomalous behavior
        if (sample.getContext().isHighRiskApplication()) {
            return "high_risk";
        } else if (sample.hasAnomalies()) {
            return "anomalous";
        } else {
            return "normal";
        }
    }
    
    private void storeTrainingData(List<float[]> features, List<String> labels) {
        // Store training data for future model improvement
        // This would typically save to a training dataset
        logger.debug("Stored {} training samples for future model improvement", features.size());
    }
    
    private void performAnomalyDetection() {
        try {
            // Get recent traffic samples
            List<TrafficSample> recentSamples = getRecentTrafficSamples(Duration.ofMinutes(10));
            
            if (recentSamples.isEmpty()) return;
            
            // Detect anomalies
            List<AnomalyResult> anomalies = anomalyEngine.detectAnomalies(recentSamples);
            
            // Process and report significant anomalies
            for (AnomalyResult anomaly : anomalies) {
                if (anomaly.getSeverity() >= 6.0) {
                    processSignificantAnomaly(anomaly);
                }
            }
            
            metrics.incrementAnomalyDetections(anomalies.size());
            
        } catch (Exception e) {
            logger.error("Error in anomaly detection", e);
        }
    }
    
    private List<TrafficSample> getRecentTrafficSamples(Duration duration) {
        LocalDateTime cutoff = LocalDateTime.now().minus(duration);
        
        return trafficQueue.stream()
                          .filter(sample -> sample.getTimestamp().isAfter(cutoff))
                          .limit(1000) // Limit for performance
                          .collect(java.util.stream.Collectors.toList());
    }
    
    private void processSignificantAnomaly(AnomalyResult anomaly) {
        logger.warn("Significant anomaly detected: {}", anomaly);
        
        // Create detailed anomaly report
        AnomalyReport report = new AnomalyReport(anomaly);
        
        // Update security alerts
        createSecurityAlert(anomaly, anomaly.getSample());
        
        // Learn from this anomaly
        learnFromAnomaly(anomaly);
    }
    
    private void createSecurityAlert(AnomalyResult anomaly, TrafficSample sample) {
        SecurityAlert alert = new SecurityAlert(
            anomaly.getType(),
            anomaly.getSeverity(),
            sample.getHost(),
            anomaly.getDescription(),
            LocalDateTime.now()
        );
        
        // This would integrate with alerting systems
        logger.warn("Security Alert: {}", alert);
    }
    
    private void learnFromAnomaly(AnomalyResult anomaly) {
        // Update anomaly detection models based on confirmed anomalies
        anomalyEngine.learnFromConfirmedAnomaly(anomaly);
        
        // Update pattern recognition
        patternEngine.learnAnomalousPattern(anomaly);
    }
    
    private void analyzeTrafficPatterns() {
        try {
            // Analyze all application profiles for patterns
            for (ApplicationLearningProfile profile : applicationProfiles.values()) {
                analyzeApplicationPatterns(profile);
            }
            
            // Cross-application pattern analysis
            analyzeCrossApplicationPatterns();
            
            metrics.incrementPatternAnalysis();
            
        } catch (Exception e) {
            logger.error("Error in pattern analysis", e);
        }
    }
    
    private void analyzeApplicationPatterns(ApplicationLearningProfile profile) {
        // Analyze patterns within a single application
        List<AttackPattern> patterns = patternEngine.analyzeApplicationTraffic(profile);
        
        for (AttackPattern pattern : patterns) {
            if (pattern.isSignificant()) {
                discoveredPatterns.put(pattern.getId(), pattern);
                logger.info("Discovered significant pattern: {}", pattern);
            }
        }
    }
    
    private void analyzeCrossApplicationPatterns() {
        // Analyze patterns across multiple applications
        List<AttackPattern> crossPatterns = patternEngine.analyzeCrossApplicationPatterns(
            new ArrayList<>(applicationProfiles.values())
        );
        
        for (AttackPattern pattern : crossPatterns) {
            discoveredPatterns.put(pattern.getId(), pattern);
            logger.info("Discovered cross-application pattern: {}", pattern);
        }
    }
    
    // Knowledge graph updates
    private void updateKnowledgeGraph(NucleiScanResult result, ApplicationContext context) {
        try {
            // Add findings to knowledge graph
            for (NucleiFinding finding : result.getFindings()) {
                knowledgeGraph.addVulnerabilityFinding(finding, context);
            }
            
            // Update relationships
            knowledgeGraph.updateTechnologyVulnerabilityRelationships(context);
            
            // Generate insights
            List<SecurityInsight> insights = knowledgeGraph.generateInsights();
            processSecurityInsights(insights);
            
        } catch (Exception e) {
            logger.error("Error updating knowledge graph", e);
        }
    }
    
    private void processSecurityInsights(List<SecurityInsight> insights) {
        for (SecurityInsight insight : insights) {
            logger.info("Security Insight: {}", insight);
            
            // Apply insights to improve testing
            applyInsightToTesting(insight);
        }
    }
    
    private void applyInsightToTesting(SecurityInsight insight) {
        // This would modify testing strategies based on insights
        logger.debug("Applying security insight to testing strategy: {}", insight.getType());
    }
    
    // Utility methods
    private String mapNucleiTemplateToVulnType(String templateId) {
        if (templateId.contains("xss")) return "xss";
        if (templateId.contains("sqli") || templateId.contains("sql")) return "sqli";
        if (templateId.contains("ssrf")) return "ssrf";
        if (templateId.contains("lfi") || templateId.contains("file")) return "lfi";
        if (templateId.contains("rce") || templateId.contains("command")) return "rce";
        if (templateId.contains("xxe")) return "xxe";
        if (templateId.contains("csrf")) return "csrf";
        if (templateId.contains("idor")) return "idor";
        if (templateId.contains("cve")) return "cve";
        return "misconfiguration";
    }
    
    // Getters for metrics and status
    public LearningMetrics getMetrics() { return metrics; }
    public int getDiscoveredPatternsCount() { return discoveredPatterns.size(); }
    public int getApplicationProfilesCount() { return applicationProfiles.size(); }
    public int getLearnedSignaturesCount() { return learnedSignatures.size(); }
    public int getTrafficQueueSize() { return trafficQueue.size(); }
    
    public ApplicationLearningProfile getApplicationProfile(String host) {
        return applicationProfiles.get(host);
    }
    
    public List<AttackPattern> getSignificantPatterns() {
        return discoveredPatterns.values().stream()
                                .filter(AttackPattern::isSignificant)
                                .collect(java.util.stream.Collectors.toList());
    }
    
    public void shutdown() {
        logger.info("Shutting down Advanced Learning Engine...");
        
        learningExecutor.shutdown();
        try {
            if (!learningExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                learningExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            learningExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.info("Advanced Learning Engine shut down");
    }
}