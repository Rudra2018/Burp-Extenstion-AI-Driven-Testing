package com.secure.ai.burp.payload;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * PayloadGeneratorAgent - Advanced Context-Aware Payload Generation
 * 
 * Generates intelligent payloads based on analysis context, technology stack detection,
 * and evolutionary algorithms for maximum effectiveness.
 */
public class PayloadGeneratorAgent {
    
    private final ObjectMapper objectMapper;
    private final IntelligentPayloadGenerator intelligentGenerator;
    private final PayloadEvolutionEngine evolutionEngine;
    private final Map<String, List<String>> contextualPayloads;
    private final Map<String, TechStackInfo> techStackDatabase;
    
    public PayloadGeneratorAgent() {
        this.objectMapper = new ObjectMapper();
        this.intelligentGenerator = new IntelligentPayloadGenerator();
        this.evolutionEngine = new PayloadEvolutionEngine();
        this.contextualPayloads = new ConcurrentHashMap<>();
        this.techStackDatabase = new ConcurrentHashMap<>();
        
        initializePayloadDatabase();
        initializeTechStackDatabase();
    }
    
    /**
     * Generate context-aware payloads based on analysis results
     */
    public String generatePayloads(String analysisJson, String targetUrl, Map<String, String> headers) {
        try {
            JsonNode analysisNode = objectMapper.readTree(analysisJson);
            TechStackInfo techStack = detectTechStack(headers, targetUrl);
            
            ObjectNode payloadsResult = objectMapper.createObjectNode();
            payloadsResult.put("target", targetUrl);
            payloadsResult.put("timestamp", System.currentTimeMillis());
            payloadsResult.set("tech_stack", objectMapper.valueToTree(techStack));
            
            // Generate payloads for each vulnerability type
            ObjectNode payloadCategories = objectMapper.createObjectNode();
            
            // SQL Injection Payloads
            payloadCategories.set("sqli", generateSQLiPayloads(analysisNode, techStack));
            
            // XSS Payloads
            payloadCategories.set("xss", generateXSSPayloads(analysisNode, techStack));
            
            // RCE Payloads
            payloadCategories.set("rce", generateRCEPayloads(analysisNode, techStack));
            
            // SSRF Payloads
            payloadCategories.set("ssrf", generateSSRFPayloads(analysisNode, techStack));
            
            // XXE Payloads
            payloadCategories.set("xxe", generateXXEPayloads(analysisNode, techStack));
            
            // CSRF Payloads
            payloadCategories.set("csrf", generateCSRFPayloads(analysisNode, techStack));
            
            // LFI Payloads
            payloadCategories.set("lfi", generateLFIPayloads(analysisNode, techStack));
            
            // IDOR Payloads
            payloadCategories.set("idor", generateIDORPayloads(analysisNode, techStack));
            
            // Deserialization Payloads
            payloadCategories.set("deserialization", generateDeserializationPayloads(analysisNode, techStack));
            
            // Business Logic Payloads
            payloadCategories.set("business_logic", generateBusinessLogicPayloads(analysisNode, techStack));
            
            payloadsResult.set("payloads", payloadCategories);
            
            // Apply evolutionary optimization
            optimizePayloadsWithEvolution(payloadsResult, techStack);
            
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payloadsResult);
            
        } catch (Exception e) {
            return createErrorResponse("Payload generation failed: " + e.getMessage());
        }
    }
    
    private TechStackInfo detectTechStack(Map<String, String> headers, String url) {
        TechStackInfo techStack = new TechStackInfo();
        
        // Server detection
        String server = headers.getOrDefault("Server", "").toLowerCase();
        if (server.contains("apache")) techStack.webServer = "Apache";
        else if (server.contains("nginx")) techStack.webServer = "Nginx";
        else if (server.contains("iis")) techStack.webServer = "IIS";
        
        // Framework detection
        String xPoweredBy = headers.getOrDefault("X-Powered-By", "").toLowerCase();
        if (xPoweredBy.contains("php")) techStack.language = "PHP";
        else if (xPoweredBy.contains("asp.net")) techStack.framework = "ASP.NET";
        
        // Cookie analysis for framework detection
        String setCookie = headers.getOrDefault("Set-Cookie", "").toLowerCase();
        if (setCookie.contains("jsessionid")) techStack.language = "Java";
        else if (setCookie.contains("asp.net_sessionid")) techStack.framework = "ASP.NET";
        else if (setCookie.contains("phpsessid")) techStack.language = "PHP";
        
        // URL pattern analysis
        if (url.contains(".php")) techStack.language = "PHP";
        else if (url.contains(".aspx")) techStack.framework = "ASP.NET";
        else if (url.contains(".jsp")) techStack.language = "Java";
        
        // Database hints from error patterns
        techStack.database = detectDatabaseFromContext(headers);
        
        return techStack;
    }
    
    private String detectDatabaseFromContext(Map<String, String> headers) {
        // This would be enhanced based on error analysis from previous requests
        return "Unknown";
    }
    
    private ArrayNode generateSQLiPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateSQLiPayloads(techStack);
        
        // Context-specific adaptations
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "sqli");
            payload.put("risk_level", calculateRiskLevel(basePayload, "sqli"));
            payload.put("description", generatePayloadDescription(basePayload, "sqli"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateXSSPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateXSSPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "xss");
            payload.put("risk_level", calculateRiskLevel(basePayload, "xss"));
            payload.put("description", generatePayloadDescription(basePayload, "xss"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateRCEPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateRCEPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "rce");
            payload.put("risk_level", calculateRiskLevel(basePayload, "rce"));
            payload.put("description", generatePayloadDescription(basePayload, "rce"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateSSRFPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateSSRFPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "ssrf");
            payload.put("risk_level", calculateRiskLevel(basePayload, "ssrf"));
            payload.put("description", generatePayloadDescription(basePayload, "ssrf"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateXXEPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateXXEPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "xxe");
            payload.put("risk_level", calculateRiskLevel(basePayload, "xxe"));
            payload.put("description", generatePayloadDescription(basePayload, "xxe"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateCSRFPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateCSRFPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "csrf");
            payload.put("risk_level", calculateRiskLevel(basePayload, "csrf"));
            payload.put("description", generatePayloadDescription(basePayload, "csrf"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateLFIPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateLFIPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "lfi");
            payload.put("risk_level", calculateRiskLevel(basePayload, "lfi"));
            payload.put("description", generatePayloadDescription(basePayload, "lfi"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateIDORPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateIDORPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "idor");
            payload.put("risk_level", calculateRiskLevel(basePayload, "idor"));
            payload.put("description", generatePayloadDescription(basePayload, "idor"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateDeserializationPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateDeserializationPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "deserialization");
            payload.put("risk_level", calculateRiskLevel(basePayload, "deserialization"));
            payload.put("description", generatePayloadDescription(basePayload, "deserialization"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generateBusinessLogicPayloads(JsonNode analysis, TechStackInfo techStack) {
        ArrayNode payloads = objectMapper.createArrayNode();
        List<String> basePayloads = intelligentGenerator.generateBusinessLogicPayloads(techStack);
        
        for (String basePayload : basePayloads) {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("payload", basePayload);
            payload.put("type", "business_logic");
            payload.put("risk_level", calculateRiskLevel(basePayload, "business_logic"));
            payload.put("description", generatePayloadDescription(basePayload, "business_logic"));
            payload.set("variations", generatePayloadVariations(basePayload, techStack));
            payloads.add(payload);
        }
        
        return payloads;
    }
    
    private ArrayNode generatePayloadVariations(String basePayload, TechStackInfo techStack) {
        ArrayNode variations = objectMapper.createArrayNode();
        
        // URL encoding variations
        variations.add(urlEncode(basePayload));
        variations.add(doubleUrlEncode(basePayload));
        
        // HTML encoding variations
        variations.add(htmlEncode(basePayload));
        
        // Unicode variations
        variations.add(unicodeEncode(basePayload));
        
        // Case variations
        variations.add(basePayload.toUpperCase());
        variations.add(mixedCase(basePayload));
        
        return variations;
    }
    
    private void optimizePayloadsWithEvolution(ObjectNode payloadsResult, TechStackInfo techStack) {
        // Apply genetic algorithm optimization
        evolutionEngine.evolvePayloads(payloadsResult, techStack);
    }
    
    private int calculateRiskLevel(String payload, String type) {
        // Risk scoring based on payload complexity and type
        int baseRisk;
        switch (type) {
            case "sqli":
            case "rce":
                baseRisk = 10;
                break;
            case "xss":
            case "xxe":
                baseRisk = 8;
                break;
            case "ssrf":
            case "deserialization":
                baseRisk = 7;
                break;
            case "lfi":
            case "csrf":
                baseRisk = 6;
                break;
            case "idor":
            case "business_logic":
                baseRisk = 5;
                break;
            default:
                baseRisk = 3;
                break;
        }
        
        // Adjust based on payload complexity
        if (payload.length() > 100) baseRisk += 1;
        if (payload.contains("system") || payload.contains("exec")) baseRisk += 2;
        
        return Math.min(baseRisk, 10);
    }
    
    private String generatePayloadDescription(String payload, String type) {
        switch (type) {
            case "sqli":
                return "SQL injection payload targeting database queries";
            case "xss":
                return "Cross-site scripting payload for script injection";
            case "rce":
                return "Remote code execution payload for command injection";
            case "ssrf":
                return "Server-side request forgery payload for internal access";
            case "xxe":
                return "XML external entity payload for XML parsing vulnerabilities";
            case "csrf":
                return "Cross-site request forgery payload for unauthorized actions";
            case "lfi":
                return "Local file inclusion payload for file system access";
            case "idor":
                return "Insecure direct object reference payload for access control bypass";
            case "deserialization":
                return "Deserialization payload for object injection";
            case "business_logic":
                return "Business logic bypass payload for workflow manipulation";
            default:
                return "Generic security payload";
        }
    }
    
    private String urlEncode(String input) {
        return input.replace(" ", "%20").replace("<", "%3C").replace(">", "%3E");
    }
    
    private String doubleUrlEncode(String input) {
        return urlEncode(urlEncode(input));
    }
    
    private String htmlEncode(String input) {
        return input.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
    
    private String unicodeEncode(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c > 127) {
                result.append("\\u").append(String.format("%04x", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String mixedCase(String input) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            result.append(i % 2 == 0 ? Character.toLowerCase(c) : Character.toUpperCase(c));
        }
        return result.toString();
    }
    
    private void initializePayloadDatabase() {
        // Initialize contextual payload database
        contextualPayloads.put("php_sqli", Arrays.asList(
            "' OR 1=1 -- ",
            "'; DROP TABLE users; -- ",
            "' UNION SELECT NULL,user(),version() -- "
        ));
        
        contextualPayloads.put("java_sqli", Arrays.asList(
            "' OR '1'='1",
            "'; INSERT INTO logs VALUES('attack'); --",
            "' UNION SELECT NULL FROM INFORMATION_SCHEMA.TABLES --"
        ));
        
        // Add more contextual payloads...
    }
    
    private void initializeTechStackDatabase() {
        // Initialize technology stack patterns
        TechStackInfo phpStack = new TechStackInfo();
        phpStack.language = "PHP";
        phpStack.database = "MySQL";
        phpStack.webServer = "Apache";
        techStackDatabase.put("php_mysql_apache", phpStack);
        
        // Add more tech stack combinations...
    }
    
    private String createErrorResponse(String error) {
        try {
            ObjectNode errorNode = objectMapper.createObjectNode();
            errorNode.put("error", error);
            errorNode.put("timestamp", System.currentTimeMillis());
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(errorNode);
        } catch (Exception e) {
            return "{\"error\":\"Failed to generate error response\"}";
        }
    }
    
    // Supporting data class
    public static class TechStackInfo {
        public String language = "Unknown";
        public String framework = "Unknown";
        public String database = "Unknown";
        public String webServer = "Unknown";
        public String operatingSystem = "Unknown";
        public List<String> libraries = new ArrayList<>();
        public Map<String, String> customHeaders = new HashMap<>();
        
        @Override
        public String toString() {
            return String.format("TechStack{lang=%s, framework=%s, db=%s, server=%s}", 
                language, framework, database, webServer);
        }
    }
}