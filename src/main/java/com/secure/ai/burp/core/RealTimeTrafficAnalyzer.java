package com.secure.ai.burp.core;

import com.secure.ai.burp.ml.*;
import com.secure.ai.burp.nuclei.ComprehensiveNucleiIntegration;
import com.secure.ai.burp.utils.SecurityTestingUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class RealTimeTrafficAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(RealTimeTrafficAnalyzer.class);
    
    // Core ML Components
    private final AdvancedModelManager modelManager;
    private final MultiLayerAnomalyDetection anomalyDetection;
    private final IntelligentPayloadGenerator payloadGenerator;
    private final ComprehensiveNucleiIntegration nucleiIntegration;
    
    // Traffic Processing Infrastructure
    private final ExecutorService analysisExecutor;
    private final ExecutorService payloadGenerationExecutor;
    private final ScheduledExecutorService scheduledExecutor;
    
    // Request Processing Pipeline
    private final BlockingQueue<TrafficAnalysisRequest> requestQueue;
    private final Map<String, CompletableFuture<RealTimeAnalysisResult>> pendingAnalyses;
    private final Map<String, SessionContext> activeSessions;
    
    // Context Building and Learning
    private final ApplicationContextBuilder contextBuilder;
    private final VulnerabilityLearningEngine learningEngine;
    private final ContinuousMonitoringSystem monitoringSystem;
    
    // Configuration and State
    private final RealTimeAnalysisConfig config;
    private final AtomicBoolean isActive;
    private final AtomicLong processedRequests;
    private final AtomicLong detectedVulnerabilities;
    
    // Performance Monitoring
    private final PerformanceMetrics performanceMetrics;
    private final ObjectMapper objectMapper;
    
    public RealTimeTrafficAnalyzer(AdvancedModelManager modelManager,
                                  MultiLayerAnomalyDetection anomalyDetection,
                                  ComprehensiveNucleiIntegration nucleiIntegration) {
        this.modelManager = modelManager;
        this.anomalyDetection = anomalyDetection;
        this.nucleiIntegration = nucleiIntegration;
        
        // Initialize payload generation and learning components
        this.payloadGenerator = new IntelligentPayloadGenerator(modelManager);
        this.learningEngine = new VulnerabilityLearningEngine(modelManager);
        this.contextBuilder = new ApplicationContextBuilder();
        this.monitoringSystem = new ContinuousMonitoringSystem();
        
        // Initialize processing infrastructure
        this.config = new RealTimeAnalysisConfig();
        this.analysisExecutor = Executors.newFixedThreadPool(config.getAnalysisThreads());
        this.payloadGenerationExecutor = Executors.newFixedThreadPool(config.getPayloadGenerationThreads());
        this.scheduledExecutor = Executors.newScheduledThreadPool(2);
        
        // Initialize data structures
        this.requestQueue = new LinkedBlockingQueue<>(config.getQueueCapacity());
        this.pendingAnalyses = new ConcurrentHashMap<>();
        this.activeSessions = new ConcurrentHashMap<>();
        
        // Initialize state tracking
        this.isActive = new AtomicBoolean(false);
        this.processedRequests = new AtomicLong(0);
        this.detectedVulnerabilities = new AtomicLong(0);
        
        // Initialize monitoring
        this.performanceMetrics = new PerformanceMetrics();
        this.objectMapper = new ObjectMapper();
        
        logger.info("Real-time traffic analyzer initialized with {} analysis threads", config.getAnalysisThreads());
    }
    
    public CompletableFuture<RealTimeAnalysisResult> analyzeTraffic(TrafficAnalysisRequest request) {
        if (!isActive.get()) {
            return CompletableFuture.completedFuture(createInactiveResult(request));
        }
        
        String requestId = request.getRequestId();
        
        // Check for duplicate requests
        if (pendingAnalyses.containsKey(requestId)) {
            logger.debug("Request {} already being analyzed, returning existing future", requestId);
            return pendingAnalyses.get(requestId);
        }
        
        // Create analysis future
        CompletableFuture<RealTimeAnalysisResult> analysisFuture = new CompletableFuture<>();
        pendingAnalyses.put(requestId, analysisFuture);
        
        // Queue request for processing
        try {
            if (!requestQueue.offer(request, config.getQueueTimeoutMs(), TimeUnit.MILLISECONDS)) {
                logger.warn("Request queue full, rejecting request {}", requestId);
                analysisFuture.complete(createQueueFullResult(request));
                pendingAnalyses.remove(requestId);
                return analysisFuture;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            analysisFuture.complete(createErrorResult(request, e));
            pendingAnalyses.remove(requestId);
            return analysisFuture;
        }
        
        logger.debug("Queued request {} for real-time analysis", requestId);
        return analysisFuture;
    }
    
    private void processRequestQueue() {
        while (isActive.get() || !requestQueue.isEmpty()) {
            try {
                TrafficAnalysisRequest request = requestQueue.poll(1, TimeUnit.SECONDS);
                if (request != null) {
                    processTrafficRequest(request);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.info("Request processing thread interrupted");
                break;
            } catch (Exception e) {
                logger.error("Error processing request queue", e);
            }
        }
    }
    
    private void processTrafficRequest(TrafficAnalysisRequest request) {
        CompletableFuture<RealTimeAnalysisResult> future = pendingAnalyses.get(request.getRequestId());
        if (future == null) {
            logger.warn("No pending analysis found for request {}", request.getRequestId());
            return;
        }
        
        CompletableFuture.supplyAsync(() -> {
            try {
                return performComprehensiveAnalysis(request);
            } catch (Exception e) {
                logger.error("Analysis failed for request {}", request.getRequestId(), e);
                return createErrorResult(request, e);
            }
        }, analysisExecutor).whenComplete((result, throwable) -> {
            if (throwable != null) {
                logger.error("Analysis completion failed for request {}", request.getRequestId(), throwable);
                future.complete(createErrorResult(request, throwable));
            } else {
                future.complete(result);
            }
            pendingAnalyses.remove(request.getRequestId());
            
            // Update metrics
            processedRequests.incrementAndGet();
            if (result.hasVulnerabilities()) {
                detectedVulnerabilities.incrementAndGet();
            }
        });
    }
    
    private RealTimeAnalysisResult performComprehensiveAnalysis(TrafficAnalysisRequest request) {
        long startTime = System.currentTimeMillis();
        String requestId = request.getRequestId();
        String sessionId = request.getSessionId();
        
        logger.debug("Starting comprehensive analysis for request {}", requestId);
        
        try {
            // Phase 1: Build application context
            SessionContext sessionContext = getOrCreateSessionContext(sessionId);
            ApplicationContext appContext = contextBuilder.buildContext(request, sessionContext);
            
            // Phase 2: Multi-layer anomaly detection
            CompletableFuture<MultiLayerAnomalyResult> anomalyFuture = 
                anomalyDetection.detectAnomalies(request);
            
            // Phase 3: ML-based vulnerability detection (parallel)
            CompletableFuture<List<VulnerabilityPrediction>> mlPredictionsFuture = 
                CompletableFuture.supplyAsync(() -> performMLAnalysis(request, appContext), analysisExecutor);
            
            // Phase 4: Context-aware payload generation (parallel)
            CompletableFuture<List<GeneratedPayload>> payloadsFuture = 
                CompletableFuture.supplyAsync(() -> generateContextAwarePayloads(request, appContext), payloadGenerationExecutor);
            
            // Phase 5: Wait for all parallel analyses to complete
            CompletableFuture<Void> allAnalyses = CompletableFuture.allOf(
                anomalyFuture, mlPredictionsFuture, payloadsFuture
            );
            
            allAnalyses.get(config.getAnalysisTimeoutMs(), TimeUnit.MILLISECONDS);
            
            // Phase 6: Aggregate results
            MultiLayerAnomalyResult anomalyResult = anomalyFuture.get();
            List<VulnerabilityPrediction> mlPredictions = mlPredictionsFuture.get();
            List<GeneratedPayload> generatedPayloads = payloadsFuture.get();
            
            // Phase 7: Vulnerability correlation and scoring
            List<CorrelatedVulnerability> correlatedVulns = correlateVulnerabilities(
                anomalyResult, mlPredictions, request, appContext);
            
            // Phase 8: Generate adaptive test cases
            List<AdaptiveTestCase> testCases = generateAdaptiveTestCases(
                correlatedVulns, generatedPayloads, appContext);
            
            // Phase 9: Update learning systems
            updateLearningSystemsAsync(request, appContext, correlatedVulns, anomalyResult);
            
            // Phase 10: Generate comprehensive result
            RealTimeAnalysisResult result = createComprehensiveResult(
                request, sessionContext, appContext, anomalyResult, mlPredictions, 
                correlatedVulns, testCases, generatedPayloads, startTime);
            
            // Phase 11: Continuous monitoring update
            monitoringSystem.updateMonitoring(request, result, sessionContext);
            
            logger.debug("Completed comprehensive analysis for request {} in {}ms", 
                        requestId, System.currentTimeMillis() - startTime);
            
            return result;
            
        } catch (TimeoutException e) {
            logger.warn("Analysis timeout for request {}", requestId);
            return createTimeoutResult(request, startTime);
        } catch (Exception e) {
            logger.error("Comprehensive analysis failed for request {}", requestId, e);
            return createErrorResult(request, e);
        }
    }
    
    private SessionContext getOrCreateSessionContext(String sessionId) {
        return activeSessions.computeIfAbsent(sessionId, id -> {
            SessionContext context = new SessionContext(id, LocalDateTime.now());
            logger.debug("Created new session context for session {}", id);
            return context;
        });
    }
    
    private List<VulnerabilityPrediction> performMLAnalysis(TrafficAnalysisRequest request, ApplicationContext appContext) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        
        try {
            String payload = request.getPayload();
            Map<String, Object> context = createMLContext(request, appContext);
            
            // XSS Detection
            PredictionResult xssResult = modelManager.predictXSS(payload, context);
            if (xssResult.getConfidence() > config.getVulnerabilityThreshold()) {
                predictions.add(new VulnerabilityPrediction("XSS", xssResult.getConfidence(), 
                    "Cross-Site Scripting vulnerability detected", xssResult.getMetadata()));
            }
            
            // SQL Injection Detection
            PredictionResult sqlResult = modelManager.predictSQLInjection(payload, context);
            if (sqlResult.getConfidence() > config.getVulnerabilityThreshold()) {
                predictions.add(new VulnerabilityPrediction("SQL_INJECTION", sqlResult.getConfidence(),
                    "SQL Injection vulnerability detected", sqlResult.getMetadata()));
            }
            
            // Additional ML-based detections based on context
            if (appContext.getDetectedTechnologies().contains("PHP")) {
                PredictionResult rceResult = modelManager.predictRCE(payload, context);
                if (rceResult.getConfidence() > config.getVulnerabilityThreshold()) {
                    predictions.add(new VulnerabilityPrediction("RCE", rceResult.getConfidence(),
                        "Remote Code Execution vulnerability detected", rceResult.getMetadata()));
                }
            }
            
            // Context-aware vulnerability detection
            predictions.addAll(performContextAwareDetection(request, appContext));
            
        } catch (Exception e) {
            logger.error("ML analysis failed for request {}", request.getRequestId(), e);
        }
        
        return predictions;
    }
    
    private List<GeneratedPayload> generateContextAwarePayloads(TrafficAnalysisRequest request, ApplicationContext appContext) {
        return payloadGenerator.generatePayloads(request, appContext);
    }
    
    private Map<String, Object> createMLContext(TrafficAnalysisRequest request, ApplicationContext appContext) {
        Map<String, Object> context = new HashMap<>();
        context.put("detected_technologies", appContext.getDetectedTechnologies());
        context.put("session_id", request.getSessionId());
        context.put("request_method", request.getHttpMethod());
        context.put("url", request.getUrl());
        context.put("headers", request.getHeaders());
        context.put("application_type", appContext.getApplicationType());
        context.put("security_features", appContext.getSecurityFeatures());
        return context;
    }
    
    private List<VulnerabilityPrediction> performContextAwareDetection(TrafficAnalysisRequest request, ApplicationContext appContext) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        
        // Technology-specific vulnerability detection
        for (String technology : appContext.getDetectedTechnologies()) {
            switch (technology.toLowerCase()) {
                case "wordpress":
                    predictions.addAll(detectWordPressVulnerabilities(request));
                    break;
                case "joomla":
                    predictions.addAll(detectJoomlaVulnerabilities(request));
                    break;
                case "drupal":
                    predictions.addAll(detectDrupalVulnerabilities(request));
                    break;
                case "apache":
                    predictions.addAll(detectApacheVulnerabilities(request));
                    break;
                case "nginx":
                    predictions.addAll(detectNginxVulnerabilities(request));
                    break;
            }
        }
        
        return predictions;
    }
    
    private List<VulnerabilityPrediction> detectWordPressVulnerabilities(TrafficAnalysisRequest request) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        String payload = request.getPayload().toLowerCase();
        
        // WordPress-specific vulnerability patterns
        if (payload.contains("wp-admin") || payload.contains("wp-content") || payload.contains("wp-includes")) {
            if (payload.contains("../") || payload.contains("%2e%2e%2f")) {
                predictions.add(new VulnerabilityPrediction("PATH_TRAVERSAL", 0.8,
                    "WordPress path traversal attempt detected", Map.of("technology", "WordPress")));
            }
            
            if (payload.contains("wp_user") || payload.contains("wp_posts")) {
                predictions.add(new VulnerabilityPrediction("SQL_INJECTION", 0.7,
                    "WordPress database injection attempt", Map.of("technology", "WordPress")));
            }
        }
        
        return predictions;
    }
    
    private List<VulnerabilityPrediction> detectJoomlaVulnerabilities(TrafficAnalysisRequest request) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        String payload = request.getPayload().toLowerCase();
        
        // Joomla-specific patterns
        if (payload.contains("index.php?option=") || payload.contains("administrator")) {
            if (payload.contains("com_") && (payload.contains("../") || payload.contains("http://"))) {
                predictions.add(new VulnerabilityPrediction("LFI_RFI", 0.8,
                    "Joomla component vulnerability detected", Map.of("technology", "Joomla")));
            }
        }
        
        return predictions;
    }
    
    private List<VulnerabilityPrediction> detectDrupalVulnerabilities(TrafficAnalysisRequest request) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        String payload = request.getPayload().toLowerCase();
        
        // Drupal-specific patterns
        if (payload.contains("drupal") || payload.contains("node/") || payload.contains("admin/")) {
            if (payload.contains("destination=") && payload.contains("../")) {
                predictions.add(new VulnerabilityPrediction("OPEN_REDIRECT", 0.7,
                    "Drupal open redirect vulnerability", Map.of("technology", "Drupal")));
            }
        }
        
        return predictions;
    }
    
    private List<VulnerabilityPrediction> detectApacheVulnerabilities(TrafficAnalysisRequest request) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        String payload = request.getPayload().toLowerCase();
        
        // Apache-specific patterns
        if (payload.contains(".htaccess") || payload.contains("server-info") || payload.contains("server-status")) {
            predictions.add(new VulnerabilityPrediction("INFO_DISCLOSURE", 0.6,
                "Apache information disclosure attempt", Map.of("technology", "Apache")));
        }
        
        return predictions;
    }
    
    private List<VulnerabilityPrediction> detectNginxVulnerabilities(TrafficAnalysisRequest request) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        String payload = request.getPayload().toLowerCase();
        
        // Nginx-specific patterns
        if (payload.contains("nginx") || payload.contains("fastcgi")) {
            if (payload.contains("php") && payload.contains("../")) {
                predictions.add(new VulnerabilityPrediction("PATH_TRAVERSAL", 0.7,
                    "Nginx path traversal via FastCGI", Map.of("technology", "Nginx")));
            }
        }
        
        return predictions;
    }
    
    private List<CorrelatedVulnerability> correlateVulnerabilities(MultiLayerAnomalyResult anomalyResult,
                                                                 List<VulnerabilityPrediction> mlPredictions,
                                                                 TrafficAnalysisRequest request,
                                                                 ApplicationContext appContext) {
        List<CorrelatedVulnerability> correlated = new ArrayList<>();
        
        // Group vulnerabilities by type
        Map<String, List<VulnerabilityPrediction>> vulnsByType = mlPredictions.stream()
            .collect(Collectors.groupingBy(VulnerabilityPrediction::getType));
        
        // Correlate with anomaly detection results
        for (Map.Entry<String, List<VulnerabilityPrediction>> entry : vulnsByType.entrySet()) {
            String vulnType = entry.getKey();
            List<VulnerabilityPrediction> predictions = entry.getValue();
            
            // Find supporting anomaly indicators
            List<AnomalyIndicator> supportingIndicators = anomalyResult.getIndicators().stream()
                .filter(indicator -> isIndicatorSupportingVulnerability(indicator, vulnType))
                .collect(Collectors.toList());
            
            // Calculate correlation confidence
            double correlationConfidence = calculateCorrelationConfidence(predictions, supportingIndicators, anomalyResult);
            
            // Create correlated vulnerability if confidence is sufficient
            if (correlationConfidence > config.getCorrelationThreshold()) {
                CorrelatedVulnerability correlatedVuln = new CorrelatedVulnerability(
                    vulnType, predictions, supportingIndicators, correlationConfidence,
                    generateCorrelationEvidence(predictions, supportingIndicators),
                    assessVulnerabilityImpact(vulnType, appContext),
                    generateMitigationRecommendations(vulnType, predictions)
                );
                
                correlated.add(correlatedVuln);
            }
        }
        
        return correlated;
    }
    
    private boolean isIndicatorSupportingVulnerability(AnomalyIndicator indicator, String vulnType) {
        String indicatorType = indicator.getType().toLowerCase();
        String vulnerability = vulnType.toLowerCase();
        
        // Map anomaly indicators to vulnerability types
        Map<String, Set<String>> supportingMap = Map.of(
            "xss", Set.of("malicious_pattern", "high_entropy", "structural_anomaly"),
            "sql_injection", Set.of("malicious_pattern", "pattern_anomaly", "structural_anomaly"),
            "rce", Set.of("threat_signature", "malicious_pattern", "high_entropy"),
            "path_traversal", Set.of("pattern_anomaly", "structural_anomaly"),
            "lfi_rfi", Set.of("malicious_pattern", "threat_signature")
        );
        
        return supportingMap.getOrDefault(vulnerability, Collections.emptySet()).contains(indicatorType);
    }
    
    private double calculateCorrelationConfidence(List<VulnerabilityPrediction> predictions,
                                                List<AnomalyIndicator> supportingIndicators,
                                                MultiLayerAnomalyResult anomalyResult) {
        // Base confidence from ML predictions
        double avgMLConfidence = predictions.stream()
            .mapToDouble(VulnerabilityPrediction::getConfidence)
            .average()
            .orElse(0.0);
        
        // Anomaly support boost
        double anomalyBoost = Math.min(supportingIndicators.size() * 0.1, 0.3);
        
        // Overall anomaly score consideration
        double anomalyFactor = Math.min(anomalyResult.getAggregatedScore() * 0.2, 0.2);
        
        return Math.min(avgMLConfidence + anomalyBoost + anomalyFactor, 1.0);
    }
    
    private Map<String, Object> generateCorrelationEvidence(List<VulnerabilityPrediction> predictions,
                                                          List<AnomalyIndicator> supportingIndicators) {
        Map<String, Object> evidence = new HashMap<>();
        evidence.put("ml_predictions", predictions.size());
        evidence.put("anomaly_indicators", supportingIndicators.size());
        evidence.put("prediction_details", predictions.stream()
            .collect(Collectors.toMap(VulnerabilityPrediction::getType, VulnerabilityPrediction::getConfidence)));
        evidence.put("indicator_types", supportingIndicators.stream()
            .map(AnomalyIndicator::getType)
            .collect(Collectors.toList()));
        return evidence;
    }
    
    private String assessVulnerabilityImpact(String vulnType, ApplicationContext appContext) {
        // Impact assessment based on vulnerability type and application context
        Map<String, String> baseImpacts = Map.of(
            "XSS", "MEDIUM",
            "SQL_INJECTION", "HIGH", 
            "RCE", "CRITICAL",
            "PATH_TRAVERSAL", "MEDIUM",
            "LFI_RFI", "HIGH"
        );
        
        String baseImpact = baseImpacts.getOrDefault(vulnType, "LOW");
        
        // Adjust based on application sensitivity
        if (appContext.getSecurityFeatures().contains("authentication") ||
            appContext.getSecurityFeatures().contains("payment")) {
            // Upgrade impact for sensitive applications
            return upgradeImpact(baseImpact);
        }
        
        return baseImpact;
    }
    
    private String upgradeImpact(String impact) {
        switch (impact) {
            case "LOW": return "MEDIUM";
            case "MEDIUM": return "HIGH";
            case "HIGH": return "CRITICAL";
            default: return impact;
        }
    }
    
    private List<String> generateMitigationRecommendations(String vulnType, List<VulnerabilityPrediction> predictions) {
        List<String> recommendations = new ArrayList<>();
        
        switch (vulnType) {
            case "XSS":
                recommendations.add("Implement output encoding/escaping");
                recommendations.add("Use Content Security Policy (CSP)");
                recommendations.add("Validate and sanitize user input");
                break;
            case "SQL_INJECTION":
                recommendations.add("Use parameterized queries/prepared statements");
                recommendations.add("Implement input validation");
                recommendations.add("Apply principle of least privilege to database accounts");
                break;
            case "RCE":
                recommendations.add("Disable dangerous functions");
                recommendations.add("Implement strict input validation");
                recommendations.add("Use sandboxing and containerization");
                break;
            case "PATH_TRAVERSAL":
                recommendations.add("Validate file paths against whitelist");
                recommendations.add("Use absolute paths for file operations");
                recommendations.add("Implement proper access controls");
                break;
        }
        
        return recommendations;
    }
    
    private List<AdaptiveTestCase> generateAdaptiveTestCases(List<CorrelatedVulnerability> vulnerabilities,
                                                           List<GeneratedPayload> payloads,
                                                           ApplicationContext appContext) {
        List<AdaptiveTestCase> testCases = new ArrayList<>();
        
        for (CorrelatedVulnerability vuln : vulnerabilities) {
            // Find relevant payloads for this vulnerability type
            List<GeneratedPayload> relevantPayloads = payloads.stream()
                .filter(payload -> payload.getTargetVulnerability().equals(vuln.getType()))
                .collect(Collectors.toList());
            
            if (!relevantPayloads.isEmpty()) {
                AdaptiveTestCase testCase = new AdaptiveTestCase(
                    vuln.getType(),
                    vuln.getCorrelationConfidence(),
                    relevantPayloads,
                    generateTestParameters(vuln, appContext),
                    generateValidationCriteria(vuln),
                    generateTestMetadata(vuln, appContext)
                );
                
                testCases.add(testCase);
            }
        }
        
        return testCases;
    }
    
    private Map<String, Object> generateTestParameters(CorrelatedVulnerability vuln, ApplicationContext appContext) {
        Map<String, Object> params = new HashMap<>();
        params.put("vulnerability_type", vuln.getType());
        params.put("confidence", vuln.getCorrelationConfidence());
        params.put("target_technologies", appContext.getDetectedTechnologies());
        params.put("test_priority", calculateTestPriority(vuln));
        return params;
    }
    
    private List<String> generateValidationCriteria(CorrelatedVulnerability vuln) {
        List<String> criteria = new ArrayList<>();
        
        switch (vuln.getType()) {
            case "XSS":
                criteria.add("Check for script execution in response");
                criteria.add("Verify payload reflection without encoding");
                criteria.add("Monitor for DOM manipulation");
                break;
            case "SQL_INJECTION":
                criteria.add("Look for database error messages");
                criteria.add("Check for blind SQL injection timing delays");
                criteria.add("Monitor for data extraction indicators");
                break;
            case "RCE":
                criteria.add("Check for command execution evidence");
                criteria.add("Monitor system process creation");
                criteria.add("Look for file system modifications");
                break;
        }
        
        return criteria;
    }
    
    private Map<String, Object> generateTestMetadata(CorrelatedVulnerability vuln, ApplicationContext appContext) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("impact_assessment", vuln.getImpactAssessment());
        metadata.put("evidence", vuln.getCorrelationEvidence());
        metadata.put("application_context", appContext.getApplicationType());
        metadata.put("generation_timestamp", LocalDateTime.now());
        return metadata;
    }
    
    private String calculateTestPriority(CorrelatedVulnerability vuln) {
        double confidence = vuln.getCorrelationConfidence();
        String impact = vuln.getImpactAssessment();
        
        if (confidence > 0.8 && "CRITICAL".equals(impact)) return "URGENT";
        if (confidence > 0.7 && ("CRITICAL".equals(impact) || "HIGH".equals(impact))) return "HIGH";
        if (confidence > 0.6) return "MEDIUM";
        return "LOW";
    }
    
    private void updateLearningSystemsAsync(TrafficAnalysisRequest request, ApplicationContext appContext,
                                          List<CorrelatedVulnerability> vulnerabilities,
                                          MultiLayerAnomalyResult anomalyResult) {
        CompletableFuture.runAsync(() -> {
            try {
                // Update vulnerability learning
                for (CorrelatedVulnerability vuln : vulnerabilities) {
                    learningEngine.learnVulnerabilityPattern(
                        request.getPayload(), vuln.getType(), vuln.getCorrelationConfidence());
                }
                
                // Update context learning
                contextBuilder.updateContextLearning(request, appContext, vulnerabilities);
                
                // Update payload generation learning
                payloadGenerator.updateGenerationLearning(request, vulnerabilities);
                
            } catch (Exception e) {
                logger.error("Error updating learning systems for request {}", request.getRequestId(), e);
            }
        }, analysisExecutor);
    }
    
    private RealTimeAnalysisResult createComprehensiveResult(TrafficAnalysisRequest request,
                                                           SessionContext sessionContext,
                                                           ApplicationContext appContext,
                                                           MultiLayerAnomalyResult anomalyResult,
                                                           List<VulnerabilityPrediction> mlPredictions,
                                                           List<CorrelatedVulnerability> correlatedVulns,
                                                           List<AdaptiveTestCase> testCases,
                                                           List<GeneratedPayload> generatedPayloads,
                                                           long startTime) {
        
        long processingTime = System.currentTimeMillis() - startTime;
        
        // Calculate overall risk score
        double overallRisk = calculateOverallRisk(anomalyResult, correlatedVulns);
        
        // Generate comprehensive recommendations
        List<String> recommendations = generateComprehensiveRecommendations(
            anomalyResult, correlatedVulns, appContext);
        
        // Create security assessment
        SecurityAssessment securityAssessment = new SecurityAssessment(
            overallRisk, correlatedVulns.size(), 
            assessSecurityPosture(correlatedVulns, appContext),
            generateSecurityRecommendations(correlatedVulns, appContext));
        
        return new RealTimeAnalysisResult(
            request.getRequestId(), request.getSessionId(), LocalDateTime.now(),
            anomalyResult, mlPredictions, correlatedVulns, testCases,
            generatedPayloads, appContext, sessionContext, securityAssessment,
            recommendations, processingTime, overallRisk,
            correlatedVulns.size() > 0, performanceMetrics.getCurrentMetrics()
        );
    }
    
    private double calculateOverallRisk(MultiLayerAnomalyResult anomalyResult, List<CorrelatedVulnerability> vulns) {
        double anomalyWeight = 0.3;
        double vulnerabilityWeight = 0.7;
        
        double anomalyScore = anomalyResult.getAggregatedScore();
        double vulnScore = vulns.stream()
            .mapToDouble(v -> v.getCorrelationConfidence())
            .max()
            .orElse(0.0);
        
        return Math.min(anomalyScore * anomalyWeight + vulnScore * vulnerabilityWeight, 1.0);
    }
    
    private List<String> generateComprehensiveRecommendations(MultiLayerAnomalyResult anomalyResult,
                                                            List<CorrelatedVulnerability> vulns,
                                                            ApplicationContext appContext) {
        Set<String> recommendations = new LinkedHashSet<>();
        
        // Add anomaly-based recommendations
        recommendations.addAll(anomalyResult.getRecommendations());
        
        // Add vulnerability-specific recommendations
        vulns.forEach(vuln -> recommendations.addAll(vuln.getMitigationRecommendations()));
        
        // Add context-aware recommendations
        if (appContext.getDetectedTechnologies().contains("WordPress")) {
            recommendations.add("Keep WordPress core and plugins updated");
            recommendations.add("Use security plugins like Wordfence or Sucuri");
        }
        
        return new ArrayList<>(recommendations);
    }
    
    private String assessSecurityPosture(List<CorrelatedVulnerability> vulns, ApplicationContext appContext) {
        if (vulns.isEmpty()) return "GOOD";
        
        long criticalCount = vulns.stream()
            .mapToLong(v -> "CRITICAL".equals(v.getImpactAssessment()) ? 1 : 0)
            .sum();
        
        if (criticalCount > 0) return "POOR";
        
        long highCount = vulns.stream()
            .mapToLong(v -> "HIGH".equals(v.getImpactAssessment()) ? 1 : 0)
            .sum();
        
        if (highCount > 2) return "POOR";
        if (highCount > 0 || vulns.size() > 3) return "MODERATE";
        
        return "GOOD";
    }
    
    private List<String> generateSecurityRecommendations(List<CorrelatedVulnerability> vulns, ApplicationContext appContext) {
        Set<String> recommendations = new LinkedHashSet<>();
        
        // Priority-based recommendations
        if (vulns.stream().anyMatch(v -> "CRITICAL".equals(v.getImpactAssessment()))) {
            recommendations.add("URGENT: Address critical vulnerabilities immediately");
            recommendations.add("Implement emergency security patches");
            recommendations.add("Consider temporary service restrictions");
        }
        
        // Technology-specific recommendations
        appContext.getDetectedTechnologies().forEach(tech -> {
            switch (tech.toLowerCase()) {
                case "apache":
                    recommendations.add("Review Apache configuration for security hardening");
                    break;
                case "php":
                    recommendations.add("Ensure PHP security settings are properly configured");
                    break;
                case "mysql":
                    recommendations.add("Review database security configuration");
                    break;
            }
        });
        
        return new ArrayList<>(recommendations);
    }
    
    // Result creation helper methods
    private RealTimeAnalysisResult createInactiveResult(TrafficAnalysisRequest request) {
        return new RealTimeAnalysisResult(
            request.getRequestId(), request.getSessionId(), LocalDateTime.now(),
            null, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList(), null, null, null,
            Arrays.asList("Real-time analyzer is not active"), 0L, 0.0,
            false, Collections.emptyMap()
        );
    }
    
    private RealTimeAnalysisResult createQueueFullResult(TrafficAnalysisRequest request) {
        return new RealTimeAnalysisResult(
            request.getRequestId(), request.getSessionId(), LocalDateTime.now(),
            null, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList(), null, null, null,
            Arrays.asList("Request queue is full, analysis skipped"), 0L, 0.0,
            false, Collections.emptyMap()
        );
    }
    
    private RealTimeAnalysisResult createTimeoutResult(TrafficAnalysisRequest request, long startTime) {
        return new RealTimeAnalysisResult(
            request.getRequestId(), request.getSessionId(), LocalDateTime.now(),
            null, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList(), null, null, null,
            Arrays.asList("Analysis timeout exceeded"), System.currentTimeMillis() - startTime, 0.0,
            false, Collections.emptyMap()
        );
    }
    
    private RealTimeAnalysisResult createErrorResult(TrafficAnalysisRequest request, Throwable error) {
        return new RealTimeAnalysisResult(
            request.getRequestId(), request.getSessionId(), LocalDateTime.now(),
            null, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(),
            Collections.emptyList(), null, null, null,
            Arrays.asList("Analysis error: " + error.getMessage()), 0L, 0.0,
            false, Collections.emptyMap()
        );
    }
    
    // Lifecycle management
    public void start() {
        if (isActive.compareAndSet(false, true)) {
            // Start request processing threads
            for (int i = 0; i < config.getAnalysisThreads(); i++) {
                analysisExecutor.submit(this::processRequestQueue);
            }
            
            // Start monitoring tasks
            scheduledExecutor.scheduleAtFixedRate(this::performPeriodicMaintenance, 
                                                 60, 60, TimeUnit.SECONDS);
            scheduledExecutor.scheduleAtFixedRate(performanceMetrics::updateMetrics, 
                                                 30, 30, TimeUnit.SECONDS);
            
            logger.info("Real-time traffic analyzer started successfully");
        }
    }
    
    public void stop() {
        if (isActive.compareAndSet(true, false)) {
            logger.info("Stopping real-time traffic analyzer...");
            
            // Shutdown executors gracefully
            analysisExecutor.shutdown();
            payloadGenerationExecutor.shutdown();
            scheduledExecutor.shutdown();
            
            try {
                if (!analysisExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                    analysisExecutor.shutdownNow();
                }
                if (!payloadGenerationExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    payloadGenerationExecutor.shutdownNow();
                }
                if (!scheduledExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduledExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                analysisExecutor.shutdownNow();
                payloadGenerationExecutor.shutdownNow();
                scheduledExecutor.shutdownNow();
            }
            
            logger.info("Real-time traffic analyzer stopped");
        }
    }
    
    private void performPeriodicMaintenance() {
        try {
            // Clean up old session contexts
            LocalDateTime cutoff = LocalDateTime.now().minusHours(config.getSessionTimeoutHours());
            activeSessions.entrySet().removeIf(entry -> 
                entry.getValue().getLastActivity().isBefore(cutoff));
            
            // Update performance metrics
            performanceMetrics.recordProcessingStats(
                processedRequests.get(), detectedVulnerabilities.get(), 
                pendingAnalyses.size(), requestQueue.size()
            );
            
            logger.debug("Periodic maintenance completed. Active sessions: {}, Queue size: {}", 
                        activeSessions.size(), requestQueue.size());
            
        } catch (Exception e) {
            logger.error("Error during periodic maintenance", e);
        }
    }
    
    // Getters for monitoring and metrics
    public boolean isActive() { return isActive.get(); }
    public long getProcessedRequests() { return processedRequests.get(); }
    public long getDetectedVulnerabilities() { return detectedVulnerabilities.get(); }
    public int getQueueSize() { return requestQueue.size(); }
    public int getActiveSessionsCount() { return activeSessions.size(); }
    public int getPendingAnalysesCount() { return pendingAnalyses.size(); }
    public PerformanceMetrics getPerformanceMetrics() { return performanceMetrics; }
    public RealTimeAnalysisConfig getConfig() { return config; }
}