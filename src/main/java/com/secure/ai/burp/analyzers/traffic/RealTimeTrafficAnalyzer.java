package com.secure.ai.burp.analyzers.traffic;

import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.detectors.anomaly.AnomalyDetectionEngine;
import com.secure.ai.burp.detectors.anomaly.TrafficData;
import com.secure.ai.burp.models.ml.AdvancedModelManager;
import com.secure.ai.burp.models.ml.FeatureExtractor;
import com.secure.ai.burp.generators.payload.IntelligentPayloadGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Real-time traffic analyzer with ML-powered vulnerability detection
 * Intercepts traffic, performs feature extraction, anomaly detection, and intelligent payload generation
 */
class RealTimeTrafficAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(RealTimeTrafficAnalyzer.class);
    
    private final AdvancedModelManager modelManager;
    private final AnomalyDetectionEngine anomalyEngine;
    private final FeatureExtractor featureExtractor;
    private final IntelligentPayloadGenerator payloadGenerator;
    private final ExecutorService analysisExecutor;
    private final ScheduledExecutorService scheduler;
    
    // Traffic processing
    private final BlockingQueue<TrafficAnalysisTask> analysisQueue = new LinkedBlockingQueue<>();
    private final Map<String, SessionContext> activeSessions = new ConcurrentHashMap<>();
    private final Map<String, VulnerabilityContext> vulnerabilityContexts = new ConcurrentHashMap<>();
    
    // Configuration
    private final TrafficAnalyzerConfig config;
    private volatile boolean isRunning = false;
    
    // Real-time metrics
    private final TrafficMetrics metrics = new TrafficMetrics();
    private final List<TrafficAnalysisResult> recentAnalyses = Collections.synchronizedList(new ArrayList<>());
    
    public RealTimeTrafficAnalyzer(AdvancedModelManager modelManager,
                                  AnomalyDetectionEngine anomalyEngine,
                                  FeatureExtractor featureExtractor,
                                  IntelligentPayloadGenerator payloadGenerator,
                                  TrafficAnalyzerConfig config) {
        this.modelManager = modelManager;
        this.anomalyEngine = anomalyEngine;
        this.featureExtractor = featureExtractor;
        this.payloadGenerator = payloadGenerator;
        this.config = config;
        this.analysisExecutor = Executors.newFixedThreadPool(config.getAnalysisThreads());
        this.scheduler = Executors.newScheduledThreadPool(2);
    }
    
    /**
     * Start real-time traffic analysis
     */
    public void start() {
        if (isRunning) {
            logger.warn("Real-time traffic analyzer already running");
            return;
        }
        
        isRunning = true;
        
        // Start analysis workers
        for (int i = 0; i < config.getAnalysisThreads(); i++) {
            analysisExecutor.submit(new AnalysisWorker());
        }
        
        // Start background tasks
        scheduler.scheduleAtFixedRate(this::cleanupExpiredSessions, 5, 5, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(this::updateMetrics, 1, 1, TimeUnit.MINUTES);
        
        // Start anomaly detection
        anomalyEngine.startRealTimeMonitoring();
        
        logger.info("Real-time traffic analyzer started with {} analysis threads", 
                   config.getAnalysisThreads());
    }
    
    /**
     * Stop real-time traffic analysis
     */
    public void stop() {
        isRunning = false;
        
        analysisExecutor.shutdown();
        scheduler.shutdown();
        anomalyEngine.stopRealTimeMonitoring();
        
        try {
            if (!analysisExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                analysisExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            analysisExecutor.shutdownNow();
        }
        
        logger.info("Real-time traffic analyzer stopped");
    }
    
    /**
     * Analyze incoming HTTP request/response
     */
    public CompletableFuture<TrafficAnalysisResult> analyzeTraffic(HttpRequestResponse requestResponse,
                                                                  ApplicationContext context) {
        if (!isRunning) {
            return CompletableFuture.completedFuture(
                createErrorResult("Analyzer not running", requestResponse));
        }
        
        CompletableFuture<TrafficAnalysisResult> future = new CompletableFuture<>();
        
        TrafficAnalysisTask task = new TrafficAnalysisTask(
            requestResponse, context, future, System.currentTimeMillis());
        
        if (!analysisQueue.offer(task)) {
            logger.warn("Analysis queue full, dropping analysis task");
            future.complete(createErrorResult("Analysis queue full", requestResponse));
        }
        
        return future;
    }
    
    /**
     * Get real-time traffic metrics
     */
    public TrafficMetrics getMetrics() {
        return metrics.copy();
    }
    
    /**
     * Get recent analysis results
     */
    public List<TrafficAnalysisResult> getRecentAnalyses(int limit) {
        synchronized (recentAnalyses) {
            return recentAnalyses.stream()
                .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
                .limit(limit)
                .collect(Collectors.toList());
        }
    }
    
    /**
     * Get vulnerability contexts for active sessions
     */
    public Map<String, VulnerabilityContext> getVulnerabilityContexts() {
        return new HashMap<>(vulnerabilityContexts);
    }
    
    private class AnalysisWorker implements Runnable {
        @Override
        public void run() {
            while (isRunning) {
                try {
                    TrafficAnalysisTask task = analysisQueue.poll(1, TimeUnit.SECONDS);
                    if (task != null) {
                        processTrafficAnalysisTask(task);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in analysis worker", e);
                }
            }
        }
        
        private void processTrafficAnalysisTask(TrafficAnalysisTask task) {
            try {
                TrafficAnalysisResult result = performDeepAnalysis(
                    task.requestResponse, task.context, task.startTime);
                task.future.complete(result);
                
                // Store recent analysis
                synchronized (recentAnalyses) {
                    recentAnalyses.add(result);
                    if (recentAnalyses.size() > config.getMaxRecentAnalyses()) {
                        recentAnalyses.remove(0);
                    }
                }
                
                // Update metrics
                metrics.incrementAnalyzedRequests();
                
                if (result.getVulnerabilities().size() > 0) {
                    metrics.incrementVulnerabilitiesDetected(result.getVulnerabilities().size());
                }
                
            } catch (Exception e) {
                logger.error("Failed to analyze traffic", e);
                task.future.complete(createErrorResult("Analysis failed: " + e.getMessage(), 
                                                     task.requestResponse));
            }
        }
    }
    
    private TrafficAnalysisResult performDeepAnalysis(HttpRequestResponse requestResponse,
                                                    ApplicationContext context,
                                                    long startTime) {
        
        String sessionId = extractSessionId(requestResponse);
        SessionContext sessionContext = activeSessions.computeIfAbsent(
            sessionId, k -> new SessionContext(sessionId));
        
        // Extract traffic data
        TrafficData trafficData = extractTrafficData(requestResponse, sessionId);
        
        // Update session context
        sessionContext.updateWithTraffic(trafficData);
        
        // Perform multi-layer analysis
        List<VulnerabilityFinding> vulnerabilities = new ArrayList<>();
        
        // 1. ML-based vulnerability detection
        vulnerabilities.addAll(performMLAnalysis(requestResponse, context));
        
        // 2. Anomaly detection
        AnomalyDetectionEngine.AnomalyDetectionResult anomalyResult = 
            anomalyEngine.detectAnomalies(trafficData, context);
        
        // 3. Pattern-based analysis
        vulnerabilities.addAll(performPatternAnalysis(requestResponse, sessionContext));
        
        // 4. Context-aware analysis
        vulnerabilities.addAll(performContextAnalysis(requestResponse, context, sessionContext));
        
        // 5. Payload generation for discovered vulnerabilities
        List<IntelligentPayload> generatedPayloads = generateTestPayloads(
            requestResponse, vulnerabilities, context);
        
        // Update vulnerability context
        updateVulnerabilityContext(sessionId, vulnerabilities, context);
        
        long processingTime = System.currentTimeMillis() - startTime;
        
        return new TrafficAnalysisResult(
            sessionId,
            LocalDateTime.now(),
            requestResponse,
            vulnerabilities,
            anomalyResult,
            generatedPayloads,
            sessionContext.getRequestCount(),
            processingTime
        );
    }
    
    private List<VulnerabilityFinding> performMLAnalysis(HttpRequestResponse requestResponse,
                                                       ApplicationContext context) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();
        
        if (response == null) return findings;
        
        try {
            // Extract request/response content for analysis
            String requestBody = request.bodyToString();
            String responseBody = response.bodyToString();
            String url = request.url();
            
            Map<String, Object> analysisContext = createAnalysisContext(request, response, context);
            
            // XSS Detection
            if (!requestBody.isEmpty()) {
                AdvancedModelManager.PredictionResult xssResult = 
                    modelManager.predictXSS(requestBody, analysisContext);
                
                if (xssResult.getConfidence() > config.getVulnerabilityThreshold()) {
                    findings.add(new VulnerabilityFinding(
                        "ML_XSS_" + System.currentTimeMillis(),
                        "Potential XSS Vulnerability (ML)",
                        "Cross-Site Scripting",
                        calculateSeverity(xssResult.getConfidence()),
                        "ML model detected potential XSS vulnerability in request body",
                        url,
                        "Implement proper input validation and output encoding",
                        List.of("https://owasp.org/www-community/attacks/xss/"),
                        createMetadata("ml_xss", xssResult)
                    ));
                }
            }
            
            // SQL Injection Detection
            if (!requestBody.isEmpty()) {
                AdvancedModelManager.PredictionResult sqlResult = 
                    modelManager.predictSQLInjection(requestBody, analysisContext);
                
                if (sqlResult.getConfidence() > config.getVulnerabilityThreshold()) {
                    findings.add(new VulnerabilityFinding(
                        "ML_SQLI_" + System.currentTimeMillis(),
                        "Potential SQL Injection Vulnerability (ML)",
                        "SQL Injection",
                        calculateSeverity(sqlResult.getConfidence()),
                        "ML model detected potential SQL injection vulnerability in request",
                        url,
                        "Use parameterized queries and input validation",
                        List.of("https://owasp.org/www-community/attacks/SQL_Injection"),
                        createMetadata("ml_sqli", sqlResult)
                    ));
                }
            }
            
            // Response analysis for information disclosure
            if (responseBody.length() > 1000) {
                double entropyScore = calculateEntropy(responseBody);
                if (entropyScore > 7.5) { // High entropy might indicate data leakage
                    findings.add(new VulnerabilityFinding(
                        "ML_INFO_DISC_" + System.currentTimeMillis(),
                        "Potential Information Disclosure (ML)",
                        "Information Disclosure",
                        "medium",
                        "Response contains high entropy content that might indicate sensitive data exposure",
                        url,
                        "Review response content for sensitive information leakage",
                        List.of(),
                        Map.of("entropy_score", entropyScore, "response_length", responseBody.length())
                    ));
                }
            }
            
        } catch (Exception e) {
            logger.debug("ML analysis failed for request", e);
        }
        
        return findings;
    }
    
    private List<VulnerabilityFinding> performPatternAnalysis(HttpRequestResponse requestResponse,
                                                            SessionContext sessionContext) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        
        HttpRequest request = requestResponse.request();
        String url = request.url();
        String requestBody = request.bodyToString();
        
        // Common attack patterns
        Map<String, String> attackPatterns = Map.of(
            "' OR 1=1", "SQL Injection Pattern",
            "<script>", "XSS Pattern",
            "../../../", "Path Traversal Pattern",
            "${jndi:", "Log4Shell Pattern",
            "eval\\(", "Code Injection Pattern",
            "\\bUNION\\b.*\\bSELECT\\b", "SQL Union Injection"
        );
        
        for (Map.Entry<String, String> pattern : attackPatterns.entrySet()) {
            Pattern regex = Pattern.compile(pattern.getKey(), Pattern.CASE_INSENSITIVE);
            Matcher matcher = regex.matcher(requestBody);
            
            if (matcher.find()) {
                findings.add(new VulnerabilityFinding(
                    "PATTERN_" + pattern.getValue().replaceAll(" ", "_").toUpperCase() + "_" + System.currentTimeMillis(),
                    pattern.getValue() + " Detected",
                    extractVulnType(pattern.getValue()),
                    "high",
                    "Attack pattern detected in request: " + matcher.group(),
                    url,
                    "Implement input validation and sanitization",
                    List.of(),
                    Map.of("pattern", pattern.getKey(), "matched_text", matcher.group())
                ));
            }
        }
        
        return findings;
    }
    
    private List<VulnerabilityFinding> performContextAnalysis(HttpRequestResponse requestResponse,
                                                            ApplicationContext context,
                                                            SessionContext sessionContext) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();
        String url = request.url();
        
        if (response == null) return findings;
        
        // Technology-specific analysis
        Set<String> technologies = context.getDetectedTechnologies();
        
        if (technologies.contains("WordPress")) {
            findings.addAll(analyzeWordPress(request, response, url));
        }
        
        if (technologies.contains("PHP")) {
            findings.addAll(analyzePHP(request, response, url));
        }
        
        // Session-based analysis
        if (sessionContext.getRequestCount() > 100) {
            findings.add(new VulnerabilityFinding(
                "SESSION_ABUSE_" + System.currentTimeMillis(),
                "Potential Session Abuse",
                "Session Management",
                "medium",
                "High number of requests in session: " + sessionContext.getRequestCount(),
                url,
                "Implement rate limiting and session monitoring",
                List.of(),
                Map.of("request_count", sessionContext.getRequestCount())
            ));
        }
        
        return findings;
    }
    
    private List<IntelligentPayload> generateTestPayloads(HttpRequestResponse requestResponse,
                                                        List<VulnerabilityFinding> vulnerabilities,
                                                        ApplicationContext context) {
        if (vulnerabilities.isEmpty()) {
            return List.of();
        }
        
        HttpRequest request = requestResponse.request();
        List<IntelligentPayload> payloads = new ArrayList<>();
        
        try {
            // Generate payloads for each detected vulnerability type
            Set<String> vulnTypes = vulnerabilities.stream()
                .map(VulnerabilityFinding::getType)
                .collect(Collectors.toSet());
            
            for (String vulnType : vulnTypes) {
                List<IntelligentPayload> typePayloads = payloadGenerator.generatePayloads(
                    vulnType, request, context, config.getMaxPayloadsPerType());
                payloads.addAll(typePayloads);
            }
            
            // Limit total payloads
            if (payloads.size() > config.getMaxTotalPayloads()) {
                payloads = payloads.stream()
                    .sorted((a, b) -> Double.compare(b.getRelevanceScore(), a.getRelevanceScore()))
                    .limit(config.getMaxTotalPayloads())
                    .collect(Collectors.toList());
            }
            
        } catch (Exception e) {
            logger.debug("Payload generation failed", e);
        }
        
        return payloads;
    }
    
    private List<VulnerabilityFinding> analyzeWordPress(HttpRequest request, HttpResponse response, String url) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        
        // WordPress specific patterns
        String responseBody = response.bodyToString();
        
        if (responseBody.contains("wp-includes") && responseBody.contains("wp-content")) {
            if (responseBody.contains("The plugin generated")) {
                findings.add(new VulnerabilityFinding(
                    "WP_PLUGIN_ERROR_" + System.currentTimeMillis(),
                    "WordPress Plugin Error Disclosure",
                    "Information Disclosure",
                    "low",
                    "WordPress plugin error information disclosed",
                    url,
                    "Configure proper error handling for WordPress plugins",
                    List.of(),
                    Map.of("platform", "WordPress")
                ));
            }
        }
        
        return findings;
    }
    
    private List<VulnerabilityFinding> analyzePHP(HttpRequest request, HttpResponse response, String url) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        
        String responseBody = response.bodyToString();
        
        // PHP error disclosure
        if (responseBody.contains("Fatal error:") || responseBody.contains("Parse error:") ||
            responseBody.contains("Warning:") && responseBody.contains(".php")) {
            findings.add(new VulnerabilityFinding(
                "PHP_ERROR_" + System.currentTimeMillis(),
                "PHP Error Disclosure",
                "Information Disclosure",
                "medium",
                "PHP error information disclosed in response",
                url,
                "Configure PHP to hide error details in production",
                List.of(),
                Map.of("platform", "PHP")
            ));
        }
        
        return findings;
    }
    
    private TrafficData extractTrafficData(HttpRequestResponse requestResponse, String sessionId) {
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();
        
        Map<String, String> headers = new HashMap<>();
        request.headers().forEach(header -> headers.put(header.name(), header.value()));
        
        Map<String, String> parameters = new HashMap<>();
        request.parameters().forEach(param -> parameters.put(param.name(), param.value()));
        
        return new TrafficData(
            sessionId,
            LocalDateTime.now(),
            extractSourceIP(request),
            request.method(),
            request.path(),
            response != null ? response.statusCode() : 0,
            response != null ? response.body().length() : 0,
            0, // Response time would need to be measured elsewhere
            parameters.size(),
            headers.size(),
            request.headerValue("User-Agent"),
            extractUserId(request),
            request.bodyToString(),
            calculateEntropy(request.bodyToString()),
            request.body().length(),
            headers,
            parameters
        );
    }
    
    private String extractSessionId(HttpRequestResponse requestResponse) {
        HttpRequest request = requestResponse.request();
        
        // Try to extract session ID from cookies
        String cookie = request.headerValue("Cookie");
        if (cookie != null) {
            Pattern sessionPattern = Pattern.compile("(?:JSESSIONID|PHPSESSID|SESSIONID)=([^;]+)");
            Matcher matcher = sessionPattern.matcher(cookie);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        
        // Fallback to IP + User-Agent hash
        String userAgent = request.headerValue("User-Agent");
        String sourceIP = extractSourceIP(request);
        return String.valueOf((sourceIP + userAgent).hashCode());
    }
    
    private String extractSourceIP(HttpRequest request) {
        // Try common forwarding headers first
        String[] headers = {"X-Forwarded-For", "X-Real-IP", "X-Client-IP"};
        for (String header : headers) {
            String value = request.headerValue(header);
            if (value != null && !value.isEmpty()) {
                return value.split(",")[0].trim();
            }
        }
        return "unknown";
    }
    
    private String extractUserId(HttpRequest request) {
        // Try to extract user ID from Authorization header or cookies
        String auth = request.headerValue("Authorization");
        if (auth != null && auth.contains("user")) {
            // Simple extraction - in practice, this would be more sophisticated
            return String.valueOf(auth.hashCode());
        }
        return null;
    }
    
    private Map<String, Object> createAnalysisContext(HttpRequest request, HttpResponse response,
                                                    ApplicationContext context) {
        Map<String, Object> analysisContext = new HashMap<>();
        analysisContext.put("method", request.method());
        analysisContext.put("status_code", response.statusCode());
        analysisContext.put("content_type", response.headerValue("Content-Type"));
        analysisContext.put("technologies", context.getDetectedTechnologies());
        analysisContext.put("endpoint", request.path());
        analysisContext.put("parameter_count", request.parameters().size());
        return analysisContext;
    }
    
    private double calculateEntropy(String data) {
        if (data.isEmpty()) return 0.0;
        
        Map<Character, Integer> frequencies = new HashMap<>();
        for (char c : data.toCharArray()) {
            frequencies.merge(c, 1, Integer::sum);
        }
        
        double entropy = 0.0;
        int length = data.length();
        
        for (int frequency : frequencies.values()) {
            double probability = (double) frequency / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
    
    private String calculateSeverity(double confidence) {
        if (confidence >= 0.9) return "critical";
        if (confidence >= 0.7) return "high";
        if (confidence >= 0.5) return "medium";
        return "low";
    }
    
    private String extractVulnType(String patternDescription) {
        if (patternDescription.contains("SQL")) return "SQL Injection";
        if (patternDescription.contains("XSS")) return "Cross-Site Scripting";
        if (patternDescription.contains("Path Traversal")) return "Path Traversal";
        if (patternDescription.contains("Log4Shell")) return "Remote Code Execution";
        if (patternDescription.contains("Code Injection")) return "Code Injection";
        return "Security Issue";
    }
    
    private Map<String, Object> createMetadata(String source, AdvancedModelManager.PredictionResult result) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", source);
        metadata.put("confidence", result.getConfidence());
        metadata.put("model_prediction", result.getPrediction());
        metadata.put("timestamp", System.currentTimeMillis());
        return metadata;
    }
    
    private void updateVulnerabilityContext(String sessionId, List<VulnerabilityFinding> vulnerabilities,
                                          ApplicationContext context) {
        if (!vulnerabilities.isEmpty()) {
            VulnerabilityContext vulnContext = vulnerabilityContexts.computeIfAbsent(
                sessionId, k -> new VulnerabilityContext(sessionId));
            vulnContext.addVulnerabilities(vulnerabilities);
        }
    }
    
    private TrafficAnalysisResult createErrorResult(String error, HttpRequestResponse requestResponse) {
        String sessionId = extractSessionId(requestResponse);
        return new TrafficAnalysisResult(
            sessionId,
            LocalDateTime.now(),
            requestResponse,
            List.of(),
            null,
            List.of(),
            0,
            0
        );
    }
    
    private void cleanupExpiredSessions() {
        LocalDateTime cutoff = LocalDateTime.now().minus(config.getSessionTimeoutMinutes(), 
                                                        java.time.temporal.ChronoUnit.MINUTES);
        
        activeSessions.entrySet().removeIf(entry -> 
            entry.getValue().getLastActivity().isBefore(cutoff));
            
        vulnerabilityContexts.entrySet().removeIf(entry ->
            entry.getValue().getLastUpdate().isBefore(cutoff));
    }
    
    private void updateMetrics() {
        metrics.setActiveSessions(activeSessions.size());
        metrics.setVulnerabilityContexts(vulnerabilityContexts.size());
    }
    
    // Data classes
    private static class TrafficAnalysisTask {
        final HttpRequestResponse requestResponse;
        final ApplicationContext context;
        final CompletableFuture<TrafficAnalysisResult> future;
        final long startTime;
        
        TrafficAnalysisTask(HttpRequestResponse requestResponse, ApplicationContext context,
                           CompletableFuture<TrafficAnalysisResult> future, long startTime) {
            this.requestResponse = requestResponse;
            this.context = context;
            this.future = future;
            this.startTime = startTime;
        }
    }
    
    public static class SessionContext {
        private final String sessionId;
        private volatile LocalDateTime firstSeen;
        private volatile LocalDateTime lastActivity;
        private volatile int requestCount = 0;
        private final Set<String> visitedEndpoints = ConcurrentHashMap.newKeySet();
        private final Map<String, Integer> methodCounts = new ConcurrentHashMap<>();
        
        public SessionContext(String sessionId) {
            this.sessionId = sessionId;
            this.firstSeen = LocalDateTime.now();
            this.lastActivity = LocalDateTime.now();
        }
        
        public void updateWithTraffic(TrafficData traffic) {
            lastActivity = traffic.getTimestamp();
            requestCount++;
            visitedEndpoints.add(traffic.getEndpoint());
            methodCounts.merge(traffic.getMethod(), 1, Integer::sum);
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public LocalDateTime getFirstSeen() { return firstSeen; }
        public LocalDateTime getLastActivity() { return lastActivity; }
        public int getRequestCount() { return requestCount; }
        public Set<String> getVisitedEndpoints() { return new HashSet<>(visitedEndpoints); }
        public Map<String, Integer> getMethodCounts() { return new HashMap<>(methodCounts); }
    }
    
    public static class VulnerabilityContext {
        private final String sessionId;
        private final List<VulnerabilityFinding> vulnerabilities = new ArrayList<>();
        private volatile LocalDateTime lastUpdate;
        private final Map<String, Integer> vulnerabilityTypeCounts = new HashMap<>();
        
        public VulnerabilityContext(String sessionId) {
            this.sessionId = sessionId;
            this.lastUpdate = LocalDateTime.now();
        }
        
        public void addVulnerabilities(List<VulnerabilityFinding> newVulns) {
            synchronized (vulnerabilities) {
                vulnerabilities.addAll(newVulns);
                for (VulnerabilityFinding vuln : newVulns) {
                    vulnerabilityTypeCounts.merge(vuln.getType(), 1, Integer::sum);
                }
            }
            lastUpdate = LocalDateTime.now();
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public List<VulnerabilityFinding> getVulnerabilities() { 
            synchronized (vulnerabilities) {
                return new ArrayList<>(vulnerabilities);
            }
        }
        public LocalDateTime getLastUpdate() { return lastUpdate; }
        public Map<String, Integer> getVulnerabilityTypeCounts() { 
            return new HashMap<>(vulnerabilityTypeCounts); 
        }
    }
    
    public static class TrafficAnalysisResult {
        private final String sessionId;
        private final LocalDateTime timestamp;
        private final HttpRequestResponse requestResponse;
        private final List<VulnerabilityFinding> vulnerabilities;
        private final AnomalyDetectionEngine.AnomalyDetectionResult anomalyResult;
        private final List<IntelligentPayload> generatedPayloads;
        private final int sessionRequestCount;
        private final long processingTimeMs;
        
        public TrafficAnalysisResult(String sessionId, LocalDateTime timestamp,
                                   HttpRequestResponse requestResponse,
                                   List<VulnerabilityFinding> vulnerabilities,
                                   AnomalyDetectionEngine.AnomalyDetectionResult anomalyResult,
                                   List<IntelligentPayload> generatedPayloads,
                                   int sessionRequestCount, long processingTimeMs) {
            this.sessionId = sessionId;
            this.timestamp = timestamp;
            this.requestResponse = requestResponse;
            this.vulnerabilities = vulnerabilities;
            this.anomalyResult = anomalyResult;
            this.generatedPayloads = generatedPayloads;
            this.sessionRequestCount = sessionRequestCount;
            this.processingTimeMs = processingTimeMs;
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public HttpRequestResponse getRequestResponse() { return requestResponse; }
        public List<VulnerabilityFinding> getVulnerabilities() { return vulnerabilities; }
        public AnomalyDetectionEngine.AnomalyDetectionResult getAnomalyResult() { return anomalyResult; }
        public List<IntelligentPayload> getGeneratedPayloads() { return generatedPayloads; }
        public int getSessionRequestCount() { return sessionRequestCount; }
        public long getProcessingTimeMs() { return processingTimeMs; }
    }
    
    public static class VulnerabilityFinding {
        private final String id;
        private final String name;
        private final String type;
        private final String severity;
        private final String description;
        private final String location;
        private final String recommendation;
        private final List<String> references;
        private final Map<String, Object> metadata;
        
        public VulnerabilityFinding(String id, String name, String type, String severity,
                                  String description, String location, String recommendation,
                                  List<String> references, Map<String, Object> metadata) {
            this.id = id;
            this.name = name;
            this.type = type;
            this.severity = severity;
            this.description = description;
            this.location = location;
            this.recommendation = recommendation;
            this.references = references;
            this.metadata = metadata;
        }
        
        // Getters
        public String getId() { return id; }
        public String getName() { return name; }
        public String getType() { return type; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public String getLocation() { return location; }
        public String getRecommendation() { return recommendation; }
        public List<String> getReferences() { return references; }
        public Map<String, Object> getMetadata() { return metadata; }
    }
    
    public static class IntelligentPayload {
        private final String type;
        private final String payload;
        private final double relevanceScore;
        private final String description;
        private final Map<String, Object> metadata;
        
        public IntelligentPayload(String type, String payload, double relevanceScore,
                                String description, Map<String, Object> metadata) {
            this.type = type;
            this.payload = payload;
            this.relevanceScore = relevanceScore;
            this.description = description;
            this.metadata = metadata;
        }
        
        // Getters
        public String getType() { return type; }
        public String getPayload() { return payload; }
        public double getRelevanceScore() { return relevanceScore; }
        public String getDescription() { return description; }
        public Map<String, Object> getMetadata() { return metadata; }
    }
    
    public static class TrafficMetrics {
        private volatile long totalAnalyzedRequests = 0;
        private volatile long totalVulnerabilitiesDetected = 0;
        private volatile int activeSessions = 0;
        private volatile int vulnerabilityContexts = 0;
        private volatile LocalDateTime lastUpdate = LocalDateTime.now();
        
        public void incrementAnalyzedRequests() {
            totalAnalyzedRequests++;
            lastUpdate = LocalDateTime.now();
        }
        
        public void incrementVulnerabilitiesDetected(int count) {
            totalVulnerabilitiesDetected += count;
        }
        
        public void setActiveSessions(int count) { activeSessions = count; }
        public void setVulnerabilityContexts(int count) { vulnerabilityContexts = count; }
        
        public TrafficMetrics copy() {
            TrafficMetrics copy = new TrafficMetrics();
            copy.totalAnalyzedRequests = this.totalAnalyzedRequests;
            copy.totalVulnerabilitiesDetected = this.totalVulnerabilitiesDetected;
            copy.activeSessions = this.activeSessions;
            copy.vulnerabilityContexts = this.vulnerabilityContexts;
            copy.lastUpdate = this.lastUpdate;
            return copy;
        }
        
        // Getters
        public long getTotalAnalyzedRequests() { return totalAnalyzedRequests; }
        public long getTotalVulnerabilitiesDetected() { return totalVulnerabilitiesDetected; }
        public int getActiveSessions() { return activeSessions; }
        public int getVulnerabilityContexts() { return vulnerabilityContexts; }
        public LocalDateTime getLastUpdate() { return lastUpdate; }
    }
}