package com.secure.ai.burp.examples.standalone;

import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.models.ml.ModelManager;
import com.secure.ai.burp.payload.PayloadGenerator;
import com.secure.ai.burp.testing.poc.POCResults;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Standalone demonstration of AI Security Testing capabilities
 * This class shows how the AI-driven security testing works without requiring Burp Suite
 */
class AISecurityDemo {
    private static final Logger logger = LoggerFactory.getLogger(AISecurityDemo.class);
    
    private final ModelManager modelManager;
    private final PayloadGenerator payloadGenerator;
    private final Map<String, ApplicationContext> applicationContexts;
    private final DemoTrafficAnalyzer trafficAnalyzer;
    
    public AISecurityDemo() {
        this.modelManager = new ModelManager();
        this.payloadGenerator = new PayloadGenerator(modelManager);
        this.applicationContexts = new ConcurrentHashMap<>();
        this.trafficAnalyzer = new DemoTrafficAnalyzer();
        
        logger.info("AI Security Demo initialized");
    }
    
    public void runComprehensiveDemo() {
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("    AI-DRIVEN SECURITY TESTING - STANDALONE DEMO");
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println();
        
        POCResults results = new POCResults();
        
        // Phase 1: Traffic Analysis and Context Extraction
        demonstrateTrafficAnalysis(results);
        
        // Phase 2: AI-Powered Payload Generation
        demonstratePayloadGeneration(results);
        
        // Phase 3: Vulnerability Detection Simulation
        demonstrateVulnerabilityDetection(results);
        
        // Phase 4: Pattern Recognition and Learning
        demonstratePatternLearning(results);
        
        // Phase 5: Anomaly Detection
        demonstrateAnomalyDetection(results);
        
        // Generate final report
        generateDemoReport(results);
    }
    
    private void demonstrateTrafficAnalysis(POCResults results) {
        System.out.println("🔍 Phase 1: Traffic Analysis & Context Extraction");
        System.out.println("─────────────────────────────────────────────────");
        
        // Simulate analyzing different types of web applications
        String[] testHosts = {
            "example-ecommerce.com",
            "api.banking-demo.com", 
            "social-media-app.com",
            "enterprise-cms.com"
        };
        
        for (String host : testHosts) {
            ApplicationContext context = analyzeApplication(host);
            applicationContexts.put(host, context);
            results.setTargetsAnalyzed(results.getTargetsAnalyzed() + 1);
            
            System.out.println("  ✓ Analyzed: " + host);
            System.out.println("    - Technologies: " + String.join(", ", context.getDetectedTechnologies()));
            System.out.println("    - Endpoints: " + context.getDiscoveredEndpoints().size());
            System.out.println("    - Parameters: " + context.getParameters().size());
            System.out.println();
        }
        
        results.setTechnologiesDetected(getTotalTechnologiesDetected());
        System.out.println("📊 Analysis Complete: " + results.getTargetsAnalyzed() + " targets, " + 
                          results.getTechnologiesDetected() + " technologies detected");
        System.out.println();
    }
    
    private void demonstratePayloadGeneration(POCResults results) {
        System.out.println("🤖 Phase 2: AI-Powered Payload Generation");
        System.out.println("─────────────────────────────────────────────────");
        
        for (Map.Entry<String, ApplicationContext> entry : applicationContexts.entrySet()) {
            String host = entry.getKey();
            ApplicationContext context = entry.getValue();
            
            System.out.println("  🎯 Generating payloads for: " + host);
            
            // Generate context-aware payloads
            List<String> xssPayloads = payloadGenerator.generateXSSPayloads(context, 5);
            List<String> sqliPayloads = payloadGenerator.generateSQLiPayloads(context, 5);
            List<String> xxePayloads = payloadGenerator.generateXXEPayloads(context, 3);
            
            results.setPayloadsGenerated(results.getPayloadsGenerated() + 
                xssPayloads.size() + sqliPayloads.size() + xxePayloads.size());
            
            System.out.println("    - XSS Payloads: " + xssPayloads.size());
            System.out.println("    - SQLi Payloads: " + sqliPayloads.size());
            System.out.println("    - XXE Payloads: " + xxePayloads.size());
            
            // Show sample payloads
            if (!xssPayloads.isEmpty()) {
                System.out.println("    - Sample XSS: " + xssPayloads.get(0));
            }
            if (!sqliPayloads.isEmpty()) {
                System.out.println("    - Sample SQLi: " + sqliPayloads.get(0));
            }
            System.out.println();
        }
        
        System.out.println("🚀 Payload Generation Complete: " + results.getPayloadsGenerated() + " payloads generated");
        System.out.println();
    }
    
    private void demonstrateVulnerabilityDetection(POCResults results) {
        System.out.println("🔒 Phase 3: ML-Based Vulnerability Detection");
        System.out.println("─────────────────────────────────────────────────");
        
        for (String host : applicationContexts.keySet()) {
            System.out.println("  🔍 Scanning: " + host);
            
            // Simulate ML model predictions
            List<String> vulnerabilities = simulateVulnerabilityDetection(host);
            results.setVulnerabilitiesFound(results.getVulnerabilitiesFound() + vulnerabilities.size());
            
            for (String vuln : vulnerabilities) {
                System.out.println("    ⚠️  " + vuln);
            }
            System.out.println();
        }
        
        System.out.println("🛡️  Vulnerability Detection Complete: " + results.getVulnerabilitiesFound() + " issues found");
        System.out.println();
    }
    
    private void demonstratePatternLearning(POCResults results) {
        System.out.println("🧠 Phase 4: Pattern Recognition & Learning");
        System.out.println("─────────────────────────────────────────────────");
        
        // Simulate pattern learning from traffic
        Map<String, Integer> patterns = simulatePatternLearning();
        results.setPatternsDiscovered(patterns.size());
        
        System.out.println("  📈 Discovered Attack Patterns:");
        for (Map.Entry<String, Integer> pattern : patterns.entrySet()) {
            System.out.println("    - " + pattern.getKey() + " (confidence: " + pattern.getValue() + "%)");
        }
        
        System.out.println();
        System.out.println("🎯 Pattern Learning Complete: " + results.getPatternsDiscovered() + " patterns identified");
        System.out.println();
    }
    
    private void demonstrateAnomalyDetection(POCResults results) {
        System.out.println("🚨 Phase 5: Real-Time Anomaly Detection");
        System.out.println("─────────────────────────────────────────────────");
        
        // Simulate anomaly detection
        List<String> anomalies = simulateAnomalyDetection();
        results.setAnomaliesDetected(anomalies.size());
        
        System.out.println("  ⚡ Detected Anomalies:");
        for (String anomaly : anomalies) {
            System.out.println("    🔴 " + anomaly);
        }
        
        System.out.println();
        System.out.println("📊 Anomaly Detection Complete: " + results.getAnomaliesDetected() + " anomalies detected");
        System.out.println();
    }
    
    private void generateDemoReport(POCResults results) {
        // Calculate overall score based on findings
        double score = calculateOverallScore(results);
        results.setOverallScore(score);
        
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("                    DEMO RESULTS");
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println();
        System.out.println("📊 Comprehensive Security Analysis Summary:");
        System.out.println("  • Targets Analyzed: " + results.getTargetsAnalyzed());
        System.out.println("  • Technologies Detected: " + results.getTechnologiesDetected());
        System.out.println("  • AI Payloads Generated: " + results.getPayloadsGenerated());
        System.out.println("  • Vulnerabilities Found: " + results.getVulnerabilitiesFound());
        System.out.println("  • Attack Patterns Discovered: " + results.getPatternsDiscovered());
        System.out.println("  • Anomalies Detected: " + results.getAnomaliesDetected());
        System.out.println("  • Overall Security Score: " + String.format("%.1f", score) + "/100");
        System.out.println();
        
        if (score >= 80) {
            System.out.println("🟢 Security Status: EXCELLENT - Low risk detected");
        } else if (score >= 60) {
            System.out.println("🟡 Security Status: GOOD - Some issues need attention");
        } else if (score >= 40) {
            System.out.println("🟠 Security Status: MODERATE - Multiple vulnerabilities found");
        } else {
            System.out.println("🔴 Security Status: HIGH RISK - Immediate action required");
        }
        
        System.out.println();
        System.out.println("✅ AI-Driven Security Testing Demo Complete!");
        System.out.println("═══════════════════════════════════════════════════════");
    }
    
    // Helper methods for simulation
    private ApplicationContext analyzeApplication(String host) {
        ApplicationContext context = new ApplicationContext(host);
        
        // Simulate technology detection based on host patterns
        if (host.contains("ecommerce")) {
            context.addDetectedTechnology("React");
            context.addDetectedTechnology("Node.js");
            context.addDetectedTechnology("MongoDB");
            context.addDiscoveredEndpoint("/api/products");
            context.addDiscoveredEndpoint("/api/cart");
            context.addDiscoveredEndpoint("/api/checkout");
            context.addParameter("productId", "number");
            context.addParameter("userId", "string");
        } else if (host.contains("banking")) {
            context.addDetectedTechnology("Java Spring");
            context.addDetectedTechnology("Oracle");
            context.addDetectedTechnology("JWT");
            context.addDiscoveredEndpoint("/api/account");
            context.addDiscoveredEndpoint("/api/transfer");
            context.addParameter("accountId", "string");
            context.addParameter("amount", "decimal");
        } else if (host.contains("social")) {
            context.addDetectedTechnology("Python Django");
            context.addDetectedTechnology("PostgreSQL");
            context.addDetectedTechnology("Redis");
            context.addDiscoveredEndpoint("/api/posts");
            context.addDiscoveredEndpoint("/api/users");
            context.addParameter("userId", "number");
            context.addParameter("content", "text");
        } else if (host.contains("cms")) {
            context.addDetectedTechnology("PHP");
            context.addDetectedTechnology("MySQL");
            context.addDetectedTechnology("WordPress");
            context.addDiscoveredEndpoint("/wp-admin/");
            context.addDiscoveredEndpoint("/api/posts");
            context.addParameter("postId", "number");
            context.addParameter("title", "string");
        }
        
        return context;
    }
    
    private int getTotalTechnologiesDetected() {
        return applicationContexts.values().stream()
            .mapToInt(ctx -> ctx.getDetectedTechnologies().size())
            .sum();
    }
    
    private List<String> simulateVulnerabilityDetection(String host) {
        List<String> vulnerabilities = new ArrayList<>();
        
        // Simulate ML model predictions based on context
        if (host.contains("ecommerce")) {
            vulnerabilities.add("XSS in product search parameter");
            vulnerabilities.add("Insecure Direct Object Reference in cart API");
        } else if (host.contains("banking")) {
            vulnerabilities.add("SQL Injection in account lookup");
            vulnerabilities.add("JWT token manipulation possible");
        } else if (host.contains("social")) {
            vulnerabilities.add("XSS in user profile fields");
            vulnerabilities.add("CSRF in post creation");
        } else if (host.contains("cms")) {
            vulnerabilities.add("File upload restriction bypass");
            vulnerabilities.add("PHP code injection in template");
            vulnerabilities.add("SQL injection in admin panel");
        }
        
        return vulnerabilities;
    }
    
    private Map<String, Integer> simulatePatternLearning() {
        Map<String, Integer> patterns = new LinkedHashMap<>();
        patterns.put("Automated XSS probing detected", 92);
        patterns.put("SQL injection fingerprinting", 87);
        patterns.put("Directory traversal attempts", 78);
        patterns.put("Authentication bypass patterns", 85);
        patterns.put("Session fixation attempts", 72);
        return patterns;
    }
    
    private List<String> simulateAnomalyDetection() {
        return Arrays.asList(
            "Unusual request frequency from 192.168.1.100 (500% above baseline)",
            "Suspicious parameter tampering in checkout process",
            "Abnormal response time patterns suggesting SQL injection",
            "Unexpected HTTP methods on API endpoints",
            "Malformed User-Agent strings indicating bot activity"
        );
    }
    
    private double calculateOverallScore(POCResults results) {
        // Simple scoring algorithm - lower vulnerabilities = higher score
        double baseScore = 100.0;
        baseScore -= Math.min(results.getVulnerabilitiesFound() * 15, 70); // Max 70 point deduction
        baseScore -= Math.min(results.getAnomaliesDetected() * 5, 20); // Max 20 point deduction
        baseScore += Math.min(results.getTechnologiesDetected() * 2, 10); // Bonus for thorough analysis
        return Math.max(baseScore, 0.0);
    }
    
    public static void main(String[] args) {
        try {
            AISecurityDemo demo = new AISecurityDemo();
            demo.runComprehensiveDemo();
        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // Helper class for traffic analysis
    private static class DemoTrafficAnalyzer {
        public void analyzeTraffic(String host) {
            // Simulate traffic analysis
        }
    }
}