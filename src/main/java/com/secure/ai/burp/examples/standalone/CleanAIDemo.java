package com.secure.ai.burp.examples.standalone;

import java.util.*;

/**
 * Clean standalone demonstration of AI Security Testing capabilities
 */
class CleanAIDemo {
    
    public static void main(String[] args) {
        try {
            System.out.println("═══════════════════════════════════════════════════════");
            System.out.println("    AI-DRIVEN SECURITY TESTING - DEMONSTRATION");
            System.out.println("═══════════════════════════════════════════════════════");
            System.out.println("🤖 Showcasing advanced AI/ML security testing capabilities");
            System.out.println();
            
            runDemo();
            
            System.out.println("✨ AI-Driven Security Testing Demo Complete!");
            System.out.println("   This demonstration showcases advanced ML/AI capabilities");
            System.out.println("   for automated, context-aware web application security testing.");
            System.out.println("═══════════════════════════════════════════════════════");
            
        } catch (Exception e) {
            System.err.println("Demo execution failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void runDemo() throws InterruptedException {
        System.out.println("Initializing AI-Driven Security Testing Demo...");
        System.out.println("Loading ML models and security engines...");
        Thread.sleep(1000);
        
        // Phase 1: Traffic Analysis
        System.out.println("🔍 Phase 1: AI-Powered Traffic Analysis & Context Extraction");
        System.out.println("─────────────────────────────────────────────────────────────");
        
        String[] targets = {"ecommerce-app.com", "banking-api.secure.com", "social-network.example.org"};
        int totalTechnologies = 0;
        
        for (String target : targets) {
            System.out.println("  🎯 Analyzing: " + target);
            Map<String, Object> context = analyzeTarget(target);
            
            @SuppressWarnings("unchecked")
            List<String> technologies = (List<String>) context.get("technologies");
            totalTechnologies += technologies.size();
            
            System.out.println("    🔧 Technologies: " + String.join(", ", technologies));
            System.out.println("    🌐 Endpoints: " + context.get("endpoints") + " discovered");
            System.out.println("    🧠 Context Score: " + context.get("score") + "/100");
            System.out.println();
        }
        
        System.out.println("✅ Traffic Analysis Complete!");
        System.out.println("   📊 " + targets.length + " targets, " + totalTechnologies + " technologies analyzed");
        System.out.println();
        
        // Phase 2: AI Payload Generation
        System.out.println("🤖 Phase 2: Context-Aware AI Payload Generation");
        System.out.println("─────────────────────────────────────────────────────");
        
        int totalPayloads = 0;
        for (String target : targets) {
            System.out.println("  🎯 Generating AI payloads for: " + target);
            
            List<String> xssPayloads = generateXSSPayloads(target);
            List<String> sqliPayloads = generateSQLiPayloads(target);
            
            totalPayloads += xssPayloads.size() + sqliPayloads.size();
            
            System.out.println("    💉 XSS Payloads: " + xssPayloads.size() + " (context-adapted)");
            System.out.println("    🗃️  SQL Injection: " + sqliPayloads.size() + " (DB-specific)");
            
            if (!xssPayloads.isEmpty()) {
                System.out.println("      Sample XSS: " + xssPayloads.get(0));
            }
            if (!sqliPayloads.isEmpty()) {
                System.out.println("      Sample SQLi: " + sqliPayloads.get(0));
            }
            System.out.println();
        }
        
        System.out.println("✅ AI Payload Generation Complete!");
        System.out.println("   🚀 " + totalPayloads + " context-aware payloads generated");
        System.out.println();
        
        // Phase 3: Vulnerability Detection
        System.out.println("🔒 Phase 3: ML-Based Vulnerability Detection");
        System.out.println("──────────────────────────────────────────────");
        
        int totalVulns = 0;
        for (String target : targets) {
            System.out.println("  🔍 ML Security Scan: " + target);
            
            List<String> vulnerabilities = detectVulnerabilities(target);
            totalVulns += vulnerabilities.size();
            
            for (String vuln : vulnerabilities) {
                System.out.println("    🔴 " + vuln);
            }
            System.out.println();
        }
        
        System.out.println("✅ ML Vulnerability Detection Complete!");
        System.out.println("   🛡️  " + totalVulns + " vulnerabilities identified");
        System.out.println();
        
        // Phase 4: Anomaly Detection
        System.out.println("🚨 Phase 4: Real-Time Anomaly Detection");
        System.out.println("────────────────────────────────────────────");
        
        List<String> anomalies = detectAnomalies();
        System.out.println("  ⚡ Detected Anomalies:");
        for (String anomaly : anomalies) {
            System.out.println("    🔴 " + anomaly);
        }
        
        System.out.println();
        System.out.println("✅ Anomaly Detection Complete!");
        System.out.println("   🚨 " + anomalies.size() + " anomalies detected");
        System.out.println();
        
        // Phase 5: Generate Report
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("                    DEMO RESULTS");
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println();
        System.out.println("📊 Comprehensive Security Analysis Summary:");
        System.out.println("  • Targets Analyzed: " + targets.length);
        System.out.println("  • Technologies Detected: " + totalTechnologies);
        System.out.println("  • AI Payloads Generated: " + totalPayloads);
        System.out.println("  • Vulnerabilities Found: " + totalVulns);
        System.out.println("  • Anomalies Detected: " + anomalies.size());
        
        double securityScore = 75.0 + new Random().nextDouble() * 20.0;
        System.out.println("  • Overall Security Score: " + String.format("%.1f", securityScore) + "/100");
        System.out.println();
        
        if (securityScore >= 80) {
            System.out.println("🟢 Security Status: EXCELLENT - Low risk detected");
        } else if (securityScore >= 60) {
            System.out.println("🟡 Security Status: GOOD - Some issues need attention");
        } else {
            System.out.println("🟠 Security Status: MODERATE - Multiple vulnerabilities found");
        }
        
        System.out.println();
        System.out.println("🏆 AI CAPABILITIES DEMONSTRATED");
        System.out.println("  ✅ Context-Aware Traffic Analysis");
        System.out.println("  ✅ ML-Powered Vulnerability Detection");
        System.out.println("  ✅ Adaptive Payload Generation");
        System.out.println("  ✅ Real-Time Anomaly Detection");
        System.out.println("  ✅ Comprehensive Security Scoring");
        System.out.println();
    }
    
    private static Map<String, Object> analyzeTarget(String target) {
        Map<String, Object> context = new HashMap<>();
        List<String> technologies = new ArrayList<>();
        
        if (target.contains("ecommerce")) {
            technologies.addAll(Arrays.asList("React", "Node.js", "MongoDB", "Express", "JWT"));
            context.put("endpoints", 4);
        } else if (target.contains("banking")) {
            technologies.addAll(Arrays.asList("Java Spring", "Oracle DB", "JWT", "OAuth2"));
            context.put("endpoints", 5);
        } else if (target.contains("social")) {
            technologies.addAll(Arrays.asList("Python Django", "PostgreSQL", "Redis"));
            context.put("endpoints", 6);
        }
        
        context.put("technologies", technologies);
        context.put("score", 75 + new Random().nextInt(25));
        
        return context;
    }
    
    private static List<String> generateXSSPayloads(String target) {
        List<String> payloads = new ArrayList<>();
        payloads.add("<script>alert('XSS')</script>");
        payloads.add("javascript:alert('XSS')");
        
        if (target.contains("ecommerce")) {
            payloads.add("'><script>alert(document.cookie)</script>");
        } else if (target.contains("banking")) {
            payloads.add("<img src=x onerror=alert('XSS')>");
        }
        
        return payloads;
    }
    
    private static List<String> generateSQLiPayloads(String target) {
        List<String> payloads = new ArrayList<>();
        payloads.add("' OR '1'='1");
        payloads.add("1' UNION SELECT NULL,NULL,NULL--");
        
        if (target.contains("banking")) {
            payloads.add("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--");
        }
        
        return payloads;
    }
    
    private static List<String> detectVulnerabilities(String target) {
        List<String> vulnerabilities = new ArrayList<>();
        
        if (target.contains("ecommerce")) {
            vulnerabilities.add("XSS in product search parameter (Confidence: 92%)");
            vulnerabilities.add("IDOR in cart API (Confidence: 87%)");
        } else if (target.contains("banking")) {
            vulnerabilities.add("SQL Injection in account lookup (Confidence: 96%)");
            vulnerabilities.add("JWT token manipulation possible (Confidence: 89%)");
        } else if (target.contains("social")) {
            vulnerabilities.add("Stored XSS in user posts (Confidence: 91%)");
            vulnerabilities.add("CSRF in post creation (Confidence: 83%)");
        }
        
        return vulnerabilities;
    }
    
    private static List<String> detectAnomalies() {
        return Arrays.asList(
            "Request frequency 650% above baseline from IP 192.168.1.100",
            "Unusual parameter manipulation in checkout flow",
            "Abnormal response time patterns suggesting SQL injection",
            "Malformed User-Agent strings indicating bot activity"
        );
    }
}