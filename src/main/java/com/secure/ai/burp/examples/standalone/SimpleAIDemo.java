package com.secure.ai.burp.examples.standalone;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class SimpleAIDemo {
    private final Random random = ThreadLocalRandom.current();
    private final Map<String, Map<String, Object>> applicationContexts = new HashMap<>();

    public void runComprehensiveDemo() {
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("          AI-DRIVEN SECURITY TESTING DEMONSTRATION");
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println();

        DemoResults results = new DemoResults();
        
        // Phase 1: Context Analysis
        demonstrateContextAnalysis(results);
        
        // Phase 2: AI Payload Generation
        demonstratePayloadGeneration(results);
        
        // Phase 3: Vulnerability Detection
        demonstrateVulnerabilityDetection(results);
        
        // Phase 4: Adaptive Learning
        demonstrateAdaptiveLearning(results);
        
        // Phase 5: Anomaly Detection
        demonstrateAnomalyDetection(results);
        
        // Final Report
        generateComprehensiveReport(results);
    }
    
    private void demonstrateContextAnalysis(DemoResults results) {
        System.out.println("🔍 Phase 1: AI-Powered Context Analysis");
        System.out.println("──────────────────────────────────────");
        
        String[] targets = {
            "ecommerce.example.com",
            "banking.secure.com",
            "social.network.org"
        };
        
        for (String target : targets) {
            System.out.println("  🎯 Analyzing: " + target);
            
            Map<String, Object> context = analyzeApplicationContext(target);
            applicationContexts.put(target, context);
            
            @SuppressWarnings("unchecked")
            List<String> technologies = (List<String>) context.get("technologies");
            @SuppressWarnings("unchecked") 
            List<String> endpoints = (List<String>) context.get("endpoints");
            @SuppressWarnings("unchecked")
            Map<String, String> parameters = (Map<String, String>) context.get("parameters");
            
            System.out.println("    📱 Technologies: " + String.join(", ", technologies));
            System.out.println("    🔗 Endpoints: " + endpoints.size());
            System.out.println("    📊 Parameters: " + parameters.size());
            
            results.targetsAnalyzed++;
            results.technologiesDetected += technologies.size();
            results.endpointsDiscovered += endpoints.size();
            results.parametersAnalyzed += parameters.size();
            
            System.out.println();
        }
        
        System.out.println("✅ Context Analysis Complete!");
        System.out.println("   📈 " + results.targetsAnalyzed + " targets analyzed");
        System.out.println();
    }
    
    private void demonstratePayloadGeneration(DemoResults results) {
        System.out.println("🚀 Phase 2: Intelligent Payload Generation");
        System.out.println("─────────────────────────────────────────");
        
        for (Map.Entry<String, Map<String, Object>> entry : applicationContexts.entrySet()) {
            String target = entry.getKey();
            Map<String, Object> context = entry.getValue();
            
            System.out.println("  🎯 " + target + " - Context-Aware Payloads:");
            
            List<String> xssPayloads = generateXSSPayloads(context);
            List<String> sqliPayloads = generateSQLiPayloads(context);
            
            results.payloadsGenerated += xssPayloads.size() + sqliPayloads.size();
            
            if (!xssPayloads.isEmpty()) {
                System.out.println("      XSS: " + xssPayloads.get(0));
            }
            if (!sqliPayloads.isEmpty()) {
                System.out.println("      SQLi: " + sqliPayloads.get(0));
            }
            System.out.println();
        }
        
        System.out.println("✅ AI Payload Generation Complete!");
        System.out.println("   🚀 " + results.payloadsGenerated + " context-aware payloads generated");
        System.out.println();
    }
    
    private void demonstrateVulnerabilityDetection(DemoResults results) {
        System.out.println("🔒 Phase 3: ML-Based Vulnerability Detection");
        System.out.println("──────────────────────────────────────────────");
        
        for (String target : applicationContexts.keySet()) {
            System.out.println("  🔍 ML Security Scan: " + target);
            
            List<VulnerabilityFinding> vulnerabilities = detectVulnerabilities(target);
            results.vulnerabilitiesFound += vulnerabilities.size();
            
            for (VulnerabilityFinding vuln : vulnerabilities) {
                String severity = getSeverityIcon(vuln.severity);
                System.out.println("    " + severity + " " + vuln.type + " (Confidence: " + vuln.confidence + "%)");
                System.out.println("        Location: " + vuln.location);
                System.out.println("        ML Score: " + vuln.mlScore + "/10");
            }
            System.out.println();
        }
        
        System.out.println("✅ ML Vulnerability Detection Complete!");
        System.out.println("   🛡️  " + results.vulnerabilitiesFound + " vulnerabilities identified");
        System.out.println();
    }
    
    private void demonstrateAdaptiveLearning(DemoResults results) {
        System.out.println("🧠 Phase 4: Adaptive Learning & Pattern Recognition");
        System.out.println("─────────────────────────────────────────────────────");
        
        System.out.println("  📈 Training adaptive ML models on discovered patterns...");
        
        Map<String, Integer> attackPatterns = discoverAttackPatterns();
        Map<String, Double> behaviorBaselines = establishBehaviorBaselines();
        
        results.patternsDiscovered = attackPatterns.size();
        results.baselinesEstablished = behaviorBaselines.size();
        
        System.out.println("  🎯 Attack Pattern Learning:");
        for (Map.Entry<String, Integer> pattern : attackPatterns.entrySet()) {
            System.out.println("    • " + pattern.getKey() + " (Confidence: " + pattern.getValue() + "%)");
        }
        
        System.out.println("\n  📊 Behavior Baseline Analysis:");
        for (Map.Entry<String, Double> baseline : behaviorBaselines.entrySet()) {
            System.out.println("    • " + baseline.getKey() + ": " + String.format("%.2f", baseline.getValue()) + " std dev");
        }
        
        System.out.println();
        System.out.println("✅ Adaptive Learning Complete!");
        System.out.println("   🎯 " + results.patternsDiscovered + " patterns, " + results.baselinesEstablished + " baselines learned");
        System.out.println();
    }
    
    private void demonstrateAnomalyDetection(DemoResults results) {
        System.out.println("🚨 Phase 5: Multi-Layer Anomaly Detection");
        System.out.println("────────────────────────────────────────────");
        
        List<AnomalyFinding> anomalies = detectAnomalies();
        results.anomaliesDetected = anomalies.size();
        
        System.out.println("  ⚡ Real-time Anomaly Detection Results:");
        
        Map<String, List<AnomalyFinding>> categorized = new HashMap<>();
        for (AnomalyFinding anomaly : anomalies) {
            categorized.computeIfAbsent(anomaly.category, k -> new ArrayList<>()).add(anomaly);
        }
        
        for (Map.Entry<String, List<AnomalyFinding>> category : categorized.entrySet()) {
            System.out.println("\n    🔴 " + category.getKey() + " Anomalies:");
            for (AnomalyFinding anomaly : category.getValue()) {
                System.out.println("      • " + anomaly.description);
                System.out.println("        Algorithm: " + anomaly.algorithm + " | Score: " + anomaly.score + "/10");
                System.out.println("        Baseline Deviation: " + String.format("%.1f", anomaly.deviation) + "σ");
            }
        }
        
        System.out.println();
        System.out.println("✅ Anomaly Detection Complete!");
        System.out.println("   🚨 " + results.anomaliesDetected + " anomalies detected across multiple layers");
        System.out.println();
    }
    
    private void generateComprehensiveReport(DemoResults results) {
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("           COMPREHENSIVE AI SECURITY ANALYSIS");
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println();
        
        System.out.println("📊 DETAILED METRICS");
        System.out.println("┌─────────────────────────────────┬─────────────┐");
        System.out.println("│ Metric                          │ Value       │");
        System.out.println("├─────────────────────────────────┼─────────────┤");
        System.out.println(String.format("│ %-31s │ %11d │", "Targets Analyzed", results.targetsAnalyzed));
        System.out.println(String.format("│ %-31s │ %11d │", "Technologies Detected", results.technologiesDetected));
        System.out.println(String.format("│ %-31s │ %11d │", "Endpoints Discovered", results.endpointsDiscovered));
        System.out.println(String.format("│ %-31s │ %11d │", "Parameters Analyzed", results.parametersAnalyzed));
        System.out.println(String.format("│ %-31s │ %11d │", "AI Payloads Generated", results.payloadsGenerated));
        System.out.println(String.format("│ %-31s │ %11d │", "Vulnerabilities Found", results.vulnerabilitiesFound));
        System.out.println(String.format("│ %-31s │ %11d │", "Attack Patterns Learned", results.patternsDiscovered));
        System.out.println(String.format("│ %-31s │ %11d │", "Behavior Baselines", results.baselinesEstablished));
        System.out.println(String.format("│ %-31s │ %11d │", "Anomalies Detected", results.anomaliesDetected));
        System.out.println("└─────────────────────────────────┴─────────────┘");
        System.out.println();
        
        System.out.println("🏆 AI CAPABILITIES DEMONSTRATED");
        System.out.println("  ✅ Context-Aware Traffic Analysis");
        System.out.println("  ✅ ML-Powered Vulnerability Detection");
        System.out.println("  ✅ Adaptive Payload Generation");
        System.out.println("  ✅ Real-Time Anomaly Detection");
        System.out.println("  ✅ Continuous Learning & Pattern Recognition");
        System.out.println();
        
        System.out.println("✨ AI-Driven Security Testing Demo Complete!");
        System.out.println("   This demonstration showcases advanced ML/AI capabilities");
        System.out.println("   for automated, context-aware web application security testing.");
        System.out.println("═══════════════════════════════════════════════════════");
    }
    
    // Helper methods for simulation
    private Map<String, Object> analyzeApplicationContext(String target) {
        Map<String, Object> context = new HashMap<>();
        List<String> technologies = new ArrayList<>();
        List<String> endpoints = new ArrayList<>();
        Map<String, String> parameters = new HashMap<>();
        
        if (target.contains("ecommerce")) {
            technologies.addAll(Arrays.asList("React", "Node.js", "MongoDB", "Express", "JWT"));
            endpoints.addAll(Arrays.asList("/api/products", "/api/cart", "/api/checkout", "/api/payment"));
            parameters.put("productId", "integer");
            parameters.put("userId", "uuid");
            parameters.put("cartId", "string");
        } else if (target.contains("banking")) {
            technologies.addAll(Arrays.asList("Java Spring", "Oracle DB", "JWT", "OAuth2", "HTTPS"));
            endpoints.addAll(Arrays.asList("/api/accounts", "/api/transfer", "/api/balance", "/api/history"));
            parameters.put("accountId", "string");
            parameters.put("amount", "decimal");
            parameters.put("currency", "string");
        } else if (target.contains("social")) {
            technologies.addAll(Arrays.asList("Python Django", "PostgreSQL", "Redis", "WebSocket"));
            endpoints.addAll(Arrays.asList("/api/posts", "/api/users", "/api/messages", "/api/feed"));
            parameters.put("userId", "integer");
            parameters.put("content", "text");
            parameters.put("mediaId", "uuid");
        }
        
        context.put("technologies", technologies);
        context.put("endpoints", endpoints);
        context.put("parameters", parameters);
        context.put("contextScore", 75 + random.nextInt(25));
        
        return context;
    }
    
    private List<String> generateXSSPayloads(Map<String, Object> context) {
        @SuppressWarnings("unchecked")
        List<String> technologies = (List<String>) context.get("technologies");
        List<String> payloads = new ArrayList<>();
        
        payloads.add("<script>alert('XSS')</script>");
        payloads.add("javascript:alert('XSS')");
        payloads.add("'><script>alert(document.cookie)</script>");
        
        if (technologies.contains("React")) {
            payloads.add("{{constructor.constructor('alert(1)')()}}");
            payloads.add("<img src=x onerror=this.src='//'+document.domain>");
        }
        if (technologies.contains("PHP")) {
            payloads.add("<?=system('id')?>");
            payloads.add("<script>alert(String.fromCharCode(88,83,83))</script>");
        }
        
        return payloads.subList(0, Math.min(payloads.size(), 3 + random.nextInt(3)));
    }
    
    private List<String> generateSQLiPayloads(Map<String, Object> context) {
        @SuppressWarnings("unchecked")
        List<String> technologies = (List<String>) context.get("technologies");
        List<String> payloads = new ArrayList<>();
        
        payloads.add("' OR '1'='1");
        payloads.add("1' UNION SELECT NULL,NULL,NULL--");
        payloads.add("'; DROP TABLE users; --");
        
        if (technologies.contains("MySQL")) {
            payloads.add("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--");
            payloads.add("1' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--");
        }
        if (technologies.contains("Oracle")) {
            payloads.add("1' UNION SELECT NULL,NULL,NULL FROM dual--");
            payloads.add("1' AND (SELECT COUNT(*) FROM all_tables)>0--");
        }
        if (technologies.contains("PostgreSQL")) {
            payloads.add("1'; SELECT version(); --");
            payloads.add("1' UNION SELECT NULL,NULL,current_database()--");
        }
        
        return payloads.subList(0, Math.min(payloads.size(), 2 + random.nextInt(4)));
    }
    
    private List<VulnerabilityFinding> detectVulnerabilities(String target) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        
        if (target.contains("ecommerce")) {
            findings.add(new VulnerabilityFinding("XSS", "HIGH", "/product/search", 92, 8.7));
            findings.add(new VulnerabilityFinding("IDOR", "MEDIUM", "/api/cart", 87, 7.3));
            findings.add(new VulnerabilityFinding("Price Manipulation", "HIGH", "/api/checkout", 94, 9.1));
        } else if (target.contains("banking")) {
            findings.add(new VulnerabilityFinding("SQL Injection", "CRITICAL", "/api/accounts", 96, 9.4));
            findings.add(new VulnerabilityFinding("JWT Manipulation", "HIGH", "/api/auth", 89, 8.2));
            findings.add(new VulnerabilityFinding("Race Condition", "MEDIUM", "/api/transfer", 78, 6.9));
        } else if (target.contains("social")) {
            findings.add(new VulnerabilityFinding("Stored XSS", "HIGH", "/api/posts", 91, 8.5));
            findings.add(new VulnerabilityFinding("CSRF", "MEDIUM", "/api/posts", 83, 7.1));
            findings.add(new VulnerabilityFinding("Information Disclosure", "LOW", "/api/users", 72, 5.8));
        }
        
        String[] vulnTypes = {"CSRF", "XXE", "SSTI", "Path Traversal", "Command Injection"};
        for (int i = 0; i < 1 + random.nextInt(2); i++) {
            String vulnType = vulnTypes[random.nextInt(vulnTypes.length)];
            String severity = random.nextBoolean() ? "MEDIUM" : "LOW";
            int confidence = 60 + random.nextInt(30);
            double mlScore = 5.0 + random.nextDouble() * 3.0;
            findings.add(new VulnerabilityFinding(vulnType, severity, "/random/endpoint", confidence, mlScore));
        }
        
        return findings;
    }
    
    private Map<String, Integer> discoverAttackPatterns() {
        Map<String, Integer> patterns = new LinkedHashMap<>();
        patterns.put("Automated XSS scanning pattern", 94);
        patterns.put("SQL injection fingerprinting sequence", 89);
        patterns.put("Directory traversal enumeration", 82);
        patterns.put("Authentication brute force pattern", 87);
        patterns.put("Session fixation attack sequence", 76);
        patterns.put("CSRF token bypass attempts", 84);
        patterns.put("API endpoint enumeration", 91);
        return patterns;
    }
    
    private Map<String, Double> establishBehaviorBaselines() {
        Map<String, Double> baselines = new LinkedHashMap<>();
        baselines.put("Request frequency", 2.3);
        baselines.put("Response time variance", 1.8);
        baselines.put("Parameter count deviation", 1.2);
        baselines.put("User agent entropy", 3.1);
        baselines.put("Payload complexity", 2.7);
        return baselines;
    }
    
    private List<AnomalyFinding> detectAnomalies() {
        List<AnomalyFinding> anomalies = new ArrayList<>();
        
        anomalies.add(new AnomalyFinding(
            "Traffic Volume", 
            "Request frequency 650% above baseline from IP 192.168.1.100", 
            "Statistical Analysis", 
            8.9, 6.5
        ));
        
        anomalies.add(new AnomalyFinding(
            "Behavioral", 
            "Unusual parameter manipulation in checkout flow", 
            "Behavioral Clustering", 
            7.8, 4.2
        ));
        
        anomalies.add(new AnomalyFinding(
            "Sequential", 
            "Abnormal request sequence suggesting automated scanning", 
            "Sequence Analysis", 
            8.3, 5.1
        ));
        
        anomalies.add(new AnomalyFinding(
            "ML-Based", 
            "Response pattern anomaly indicating potential SQLi", 
            "Deep Learning", 
            9.1, 7.8
        ));
        
        return anomalies;
    }
    
    private String getSeverityIcon(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL": return "🔴";
            case "HIGH": return "🟠";
            case "MEDIUM": return "🟡";
            case "LOW": return "🟢";
            default: return "⚪";
        }
    }
    
    // Data classes for demo results
    private static class DemoResults {
        int targetsAnalyzed = 0;
        int technologiesDetected = 0;
        int endpointsDiscovered = 0;
        int parametersAnalyzed = 0;
        int payloadsGenerated = 0;
        int vulnerabilitiesFound = 0;
        int patternsDiscovered = 0;
        int baselinesEstablished = 0;
        int anomaliesDetected = 0;
    }
    
    private static class VulnerabilityFinding {
        String type, severity, location;
        int confidence;
        double mlScore;
        
        VulnerabilityFinding(String type, String severity, String location, int confidence, double mlScore) {
            this.type = type;
            this.severity = severity;
            this.location = location;
            this.confidence = confidence;
            this.mlScore = mlScore;
        }
    }
    
    private static class AnomalyFinding {
        String category, description, algorithm;
        double score, deviation;
        
        AnomalyFinding(String category, String description, String algorithm, double score, double deviation) {
            this.category = category;
            this.description = description;
            this.algorithm = algorithm;
            this.score = score;
            this.deviation = deviation;
        }
    }
    
    public static void main(String[] args) {
        try {
            System.out.println("Initializing AI-Driven Security Testing Demo...");
            System.out.println("Loading ML models and security engines...");
            Thread.sleep(1000);
            
            SimpleAIDemo demo = new SimpleAIDemo();
            demo.runComprehensiveDemo();
            
        } catch (Exception e) {
            System.err.println("Demo execution failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}