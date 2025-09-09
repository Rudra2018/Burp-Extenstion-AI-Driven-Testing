package com.secure.ai.burp.generators.payload;

import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.models.ml.ModelManager;
import com.secure.ai.burp.models.ml.MLPrediction;
import com.secure.ai.burp.generators.payload.generators.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

class PayloadGenerator {
    private static final Logger logger = LoggerFactory.getLogger(PayloadGenerator.class);
    
    private final ModelManager modelManager;
    private final Map<String, PayloadGeneratorStrategy> generators;
    private final PayloadContextAnalyzer contextAnalyzer;
    private final PayloadOptimizer optimizer;
    
    public PayloadGenerator(ModelManager modelManager) {
        this.modelManager = modelManager;
        this.generators = new ConcurrentHashMap<>();
        this.contextAnalyzer = new PayloadContextAnalyzer();
        this.optimizer = new PayloadOptimizer(modelManager);
        
        initializeGenerators();
        logger.info("Payload Generator initialized with {} generators", generators.size());
    }
    
    private void initializeGenerators() {
        // Initialize all payload generation strategies
        generators.put("xss", new XSSPayloadGenerator(modelManager));
        generators.put("sqli", new SQLiPayloadGenerator(modelManager));
        generators.put("ssrf", new SSRFPayloadGenerator(modelManager));
        generators.put("lfi", new LFIPayloadGenerator(modelManager));
        generators.put("rce", new RCEPayloadGenerator(modelManager));
        generators.put("auth_bypass", new AuthBypassPayloadGenerator(modelManager));
        generators.put("business_logic", new BusinessLogicPayloadGenerator(modelManager));
        generators.put("xxe", new XXEPayloadGenerator(modelManager));
        generators.put("csrf", new CSRFPayloadGenerator(modelManager));
        generators.put("idor", new IDORPayloadGenerator(modelManager));
        generators.put("deserialization", new DeserializationPayloadGenerator(modelManager));
        generators.put("nosql", new NoSQLPayloadGenerator(modelManager));
    }
    
    public List<GeneratedPayload> generatePayloads(HttpRequestToBeSent request, ApplicationContext context) {
        try {
            logger.debug("Generating payloads for request: {} {}", request.method(), request.path());
            
            // Analyze context to determine which payload types to generate
            PayloadContext payloadContext = contextAnalyzer.analyzeContext(request, context);
            
            // Generate payloads based on context
            List<GeneratedPayload> allPayloads = new ArrayList<>();
            
            // Generate context-aware payloads for each vulnerability type
            for (String vulnerabilityType : getRelevantVulnerabilityTypes(payloadContext)) {
                PayloadGeneratorStrategy generator = generators.get(vulnerabilityType);
                if (generator != null) {
                    List<GeneratedPayload> typePayloads = generator.generatePayloads(request, payloadContext);
                    allPayloads.addAll(typePayloads);
                }
            }
            
            // Optimize and filter payloads
            List<GeneratedPayload> optimizedPayloads = optimizer.optimizePayloads(allPayloads, payloadContext);
            
            // Score and prioritize payloads using ML
            scorePayloads(optimizedPayloads, payloadContext);
            
            // Sort by effectiveness score
            optimizedPayloads.sort((p1, p2) -> Double.compare(p2.getEffectivenessScore(), p1.getEffectivenessScore()));
            
            logger.info("Generated {} optimized payloads for {} vulnerability types", 
                       optimizedPayloads.size(), getRelevantVulnerabilityTypes(payloadContext).size());
            
            return optimizedPayloads;
            
        } catch (Exception e) {
            logger.error("Error generating payloads", e);
            return Collections.emptyList();
        }
    }
    
    private Set<String> getRelevantVulnerabilityTypes(PayloadContext context) {
        Set<String> relevantTypes = new HashSet<>();
        
        // Always test for common vulnerabilities
        relevantTypes.add("xss");
        relevantTypes.add("sqli");
        
        // Context-specific vulnerabilities
        if (context.hasFileParameters() || context.hasUploadFunctionality()) {
            relevantTypes.add("lfi");
            relevantTypes.add("rce");
        }
        
        if (context.hasUrlParameters() || context.hasHttpParameters()) {
            relevantTypes.add("ssrf");
        }
        
        if (context.hasAuthenticationContext()) {
            relevantTypes.add("auth_bypass");
            relevantTypes.add("csrf");
        }
        
        if (context.hasIdParameters()) {
            relevantTypes.add("idor");
            relevantTypes.add("business_logic");
        }
        
        if (context.hasXmlContent()) {
            relevantTypes.add("xxe");
        }
        
        if (context.hasSerializedData()) {
            relevantTypes.add("deserialization");
        }
        
        if (context.hasNoSQLIndicators()) {
            relevantTypes.add("nosql");
        }
        
        // Technology-specific vulnerabilities
        if (context.getApplicationContext().hasTechnology("php")) {
            relevantTypes.add("lfi");
            relevantTypes.add("rce");
        }
        
        if (context.getApplicationContext().hasTechnology("java")) {
            relevantTypes.add("deserialization");
            relevantTypes.add("xxe");
        }
        
        if (context.getApplicationContext().hasDatabase("mongodb")) {
            relevantTypes.add("nosql");
        }
        
        return relevantTypes;
    }
    
    private void scorePayloads(List<GeneratedPayload> payloads, PayloadContext context) {
        for (GeneratedPayload payload : payloads) {
            try {
                // Use ML model to score payload effectiveness
                if (modelManager.isModelLoaded("payload_generator")) {
                    float[] features = extractPayloadFeatures(payload, context);
                    MLPrediction prediction = modelManager.predict("payload_generator", features);
                    payload.setEffectivenessScore(prediction.getMaxPrediction());
                } else {
                    // Fallback scoring
                    payload.setEffectivenessScore(calculateFallbackScore(payload, context));
                }
                
                // Additional scoring based on context relevance
                payload.setContextRelevanceScore(calculateContextRelevance(payload, context));
                
                // Final combined score
                double finalScore = (payload.getEffectivenessScore() * 0.7) + 
                                  (payload.getContextRelevanceScore() * 0.3);
                payload.setFinalScore(finalScore);
                
            } catch (Exception e) {
                logger.warn("Error scoring payload: {}", payload.getPayload(), e);
                payload.setEffectivenessScore(0.1); // Low default score
            }
        }
    }
    
    private float[] extractPayloadFeatures(GeneratedPayload payload, PayloadContext context) {
        float[] features = new float[50];
        
        String payloadStr = payload.getPayload();
        
        // Basic payload characteristics
        features[0] = payloadStr.length() / 1000.0f; // Normalized length
        features[1] = countSpecialChars(payloadStr) / 10.0f;
        features[2] = payload.getVulnerabilityType().equals("xss") ? 1.0f : 0.0f;
        features[3] = payload.getVulnerabilityType().equals("sqli") ? 1.0f : 0.0f;
        features[4] = payload.getVulnerabilityType().equals("ssrf") ? 1.0f : 0.0f;
        
        // Context features
        features[10] = context.hasAuthenticationContext() ? 1.0f : 0.0f;
        features[11] = context.hasFileParameters() ? 1.0f : 0.0f;
        features[12] = context.hasIdParameters() ? 1.0f : 0.0f;
        features[13] = context.hasXmlContent() ? 1.0f : 0.0f;
        features[14] = context.hasJsonContent() ? 1.0f : 0.0f;
        
        // Technology-specific features
        ApplicationContext appContext = context.getApplicationContext();
        features[20] = appContext.hasTechnology("php") ? 1.0f : 0.0f;
        features[21] = appContext.hasTechnology("java") ? 1.0f : 0.0f;
        features[22] = appContext.hasTechnology("node.js") ? 1.0f : 0.0f;
        features[23] = appContext.hasTechnology("python") ? 1.0f : 0.0f;
        
        // Framework-specific features
        features[30] = appContext.hasFramework("spring") ? 1.0f : 0.0f;
        features[31] = appContext.hasFramework("django") ? 1.0f : 0.0f;
        features[32] = appContext.hasFramework("express") ? 1.0f : 0.0f;
        features[33] = appContext.hasFramework("laravel") ? 1.0f : 0.0f;
        
        // Security context features
        features[40] = appContext.hasXSSProtection() ? 0.3f : 1.0f; // Lower score if protected
        features[41] = appContext.hasCSRFProtection() ? 0.3f : 1.0f;
        features[42] = appContext.hasSQLiProtection() ? 0.3f : 1.0f;
        
        return features;
    }
    
    private int countSpecialChars(String payload) {
        return (int) payload.chars()
                          .filter(ch -> !Character.isLetterOrDigit(ch) && !Character.isWhitespace(ch))
                          .count();
    }
    
    private double calculateFallbackScore(GeneratedPayload payload, PayloadContext context) {
        double score = 0.5; // Base score
        
        // Type-specific scoring
        switch (payload.getVulnerabilityType()) {
            case "xss":
                if (payload.getPayload().contains("<script") || 
                    payload.getPayload().contains("javascript:")) {
                    score += 0.3;
                }
                break;
            case "sqli":
                if (payload.getPayload().contains("UNION") || 
                    payload.getPayload().contains("' OR ")) {
                    score += 0.3;
                }
                break;
            case "ssrf":
                if (payload.getPayload().contains("localhost") || 
                    payload.getPayload().contains("169.254")) {
                    score += 0.3;
                }
                break;
        }
        
        // Context relevance
        if (isPayloadRelevantToContext(payload, context)) {
            score += 0.2;
        }
        
        return Math.min(score, 1.0);
    }
    
    private double calculateContextRelevance(GeneratedPayload payload, PayloadContext context) {
        double relevance = 0.0;
        
        String vulnType = payload.getVulnerabilityType();
        ApplicationContext appContext = context.getApplicationContext();
        
        // Technology relevance
        switch (vulnType) {
            case "lfi":
            case "rce":
                if (appContext.hasTechnology("php")) relevance += 0.3;
                break;
            case "xxe":
            case "deserialization":
                if (appContext.hasTechnology("java")) relevance += 0.3;
                break;
            case "nosql":
                if (appContext.hasDatabase("mongodb")) relevance += 0.3;
                break;
        }
        
        // Parameter relevance
        if (vulnType.equals("idor") && context.hasIdParameters()) {
            relevance += 0.4;
        }
        
        if (vulnType.equals("csrf") && context.hasAuthenticationContext()) {
            relevance += 0.4;
        }
        
        // Protection relevance (higher relevance if not protected)
        switch (vulnType) {
            case "xss":
                if (!appContext.hasXSSProtection()) relevance += 0.3;
                break;
            case "csrf":
                if (!appContext.hasCSRFProtection()) relevance += 0.3;
                break;
        }
        
        return Math.min(relevance, 1.0);
    }
    
    private boolean isPayloadRelevantToContext(GeneratedPayload payload, PayloadContext context) {
        String vulnType = payload.getVulnerabilityType();
        
        switch (vulnType) {
            case "xss":
                return context.hasReflectedParameters() || context.hasFormInputs();
            case "sqli":
                return context.hasSearchParameters() || context.hasDatabaseInteraction();
            case "ssrf":
                return context.hasUrlParameters() || context.hasHttpParameters();
            case "lfi":
                return context.hasFileParameters() || context.hasPathParameters();
            case "idor":
                return context.hasIdParameters();
            case "csrf":
                return context.hasAuthenticationContext() && context.hasStateChangingOperations();
            default:
                return true;
        }
    }
    
    public List<GeneratedPayload> generateTargetedPayloads(String vulnerabilityType, 
                                                          HttpRequestToBeSent request, 
                                                          ApplicationContext context) {
        try {
            PayloadGeneratorStrategy generator = generators.get(vulnerabilityType);
            if (generator == null) {
                logger.warn("No generator found for vulnerability type: {}", vulnerabilityType);
                return Collections.emptyList();
            }
            
            PayloadContext payloadContext = contextAnalyzer.analyzeContext(request, context);
            List<GeneratedPayload> payloads = generator.generatePayloads(request, payloadContext);
            
            // Score and optimize targeted payloads
            scorePayloads(payloads, payloadContext);
            payloads = optimizer.optimizePayloads(payloads, payloadContext);
            
            payloads.sort((p1, p2) -> Double.compare(p2.getFinalScore(), p1.getFinalScore()));
            
            logger.debug("Generated {} targeted payloads for {}", payloads.size(), vulnerabilityType);
            return payloads;
            
        } catch (Exception e) {
            logger.error("Error generating targeted payloads for {}", vulnerabilityType, e);
            return Collections.emptyList();
        }
    }
    
    public GeneratedPayload generateCustomPayload(String vulnerabilityType, 
                                                 String basePayload, 
                                                 PayloadContext context) {
        try {
            PayloadGeneratorStrategy generator = generators.get(vulnerabilityType);
            if (generator == null) {
                // Create basic payload
                return new GeneratedPayload(basePayload, vulnerabilityType, "custom", 0.5, context);
            }
            
            return generator.customizePayload(basePayload, context);
            
        } catch (Exception e) {
            logger.error("Error generating custom payload", e);
            return new GeneratedPayload(basePayload, vulnerabilityType, "custom", 0.1, context);
        }
    }
    
    public Map<String, Integer> getGeneratorStatistics() {
        Map<String, Integer> stats = new ConcurrentHashMap<>();
        
        for (Map.Entry<String, PayloadGeneratorStrategy> entry : generators.entrySet()) {
            stats.put(entry.getKey(), entry.getValue().getGeneratedCount());
        }
        
        return stats;
    }
    
    public void updateGeneratorLearning(String vulnerabilityType, 
                                      GeneratedPayload payload, 
                                      boolean wasSuccessful,
                                      double actualEffectiveness) {
        try {
            PayloadGeneratorStrategy generator = generators.get(vulnerabilityType);
            if (generator != null) {
                generator.updateLearning(payload, wasSuccessful, actualEffectiveness);
            }
            
            // Update global optimizer learning
            optimizer.updateLearning(payload, wasSuccessful, actualEffectiveness);
            
        } catch (Exception e) {
            logger.warn("Error updating generator learning", e);
        }
    }
    
    public List<String> getSupportedVulnerabilityTypes() {
        return new ArrayList<>(generators.keySet());
    }
    
    public boolean supportsVulnerabilityType(String vulnerabilityType) {
        return generators.containsKey(vulnerabilityType);
    }
}