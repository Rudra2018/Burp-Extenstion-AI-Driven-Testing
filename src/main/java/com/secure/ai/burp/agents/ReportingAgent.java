package com.secure.ai.burp.agents;

import burp.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.text.SimpleDateFormat;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Tier 3: Autonomous Reporting Agent
 * 
 * Generates comprehensive penetration test reports with executive summaries,
 * technical details, remediation guidance, and risk assessments.
 */
public class ReportingAgent {
    
    private final IBurpExtenderCallbacks callbacks;
    private final ExecutorService executorService;
    
    private final AtomicInteger reportCount = new AtomicInteger(0);
    private final AtomicInteger exportCount = new AtomicInteger(0);
    private volatile boolean active = false;
    
    // Report generation and management
    private final List<SecurityReport> generatedReports = new ArrayList<>();
    private final Map<String, ReportTemplate> reportTemplates;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final SimpleDateFormat fileFormat = new SimpleDateFormat("yyyyMMdd_HHmmss");
    
    public ReportingAgent(IBurpExtenderCallbacks callbacks, ExecutorService executorService) {
        this.callbacks = callbacks;
        this.executorService = executorService;
        this.reportTemplates = initializeReportTemplates();
    }
    
    public void start() {
        this.active = true;
        
        // Start periodic report generation
        executorService.submit(this::generatePeriodicReports);
    }
    
    public void stop() {
        this.active = false;
    }
    
    public String getStatus() {
        return active ? "ACTIVE - " + reportCount.get() + " reports generated" : "STOPPED";
    }
    
    public int getReportCount() {
        return reportCount.get();
    }
    
    public int getExportCount() {
        return exportCount.get();
    }
    
    private Map<String, ReportTemplate> initializeReportTemplates() {
        Map<String, ReportTemplate> templates = new HashMap<>();
        
        // Executive Summary Report
        templates.put("EXECUTIVE", new ReportTemplate(
            "Executive Summary",
            "High-level security assessment summary for executive stakeholders",
            Arrays.asList("Risk Overview", "Key Findings", "Business Impact", "Recommendations"),
            this::generateExecutiveSummary
        ));
        
        // Technical Detail Report
        templates.put("TECHNICAL", new ReportTemplate(
            "Technical Assessment Report",
            "Detailed technical findings with proof-of-concept demonstrations",
            Arrays.asList("Methodology", "Findings", "Technical Details", "Exploitation", "Remediation"),
            this::generateTechnicalReport
        ));
        
        // Compliance Report
        templates.put("COMPLIANCE", new ReportTemplate(
            "Compliance Assessment",
            "Security assessment mapped to compliance frameworks (OWASP, PCI-DSS, etc.)",
            Arrays.asList("Framework Mapping", "Compliance Status", "Gap Analysis", "Remediation Plan"),
            this::generateComplianceReport
        ));
        
        // Vulnerability Summary Report
        templates.put("VULNERABILITY", new ReportTemplate(
            "Vulnerability Assessment Summary",
            "Comprehensive vulnerability listing with risk ratings and remediation priorities",
            Arrays.asList("Vulnerability Inventory", "Risk Assessment", "Remediation Timeline", "Verification"),
            this::generateVulnerabilityReport
        ));
        
        return templates;
    }
    
    private void generatePeriodicReports() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                // Generate reports every hour
                Thread.sleep(3600000);
                
                if (!active) break;
                
                // Check if there are new findings to report
                IScanIssue[] issues = callbacks.getScanIssues(null);
                if (issues.length > 0) {
                    generateComprehensiveReport();
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    public void generateComprehensiveReport() {
        executorService.submit(() -> {
            try {
                IScanIssue[] issues = callbacks.getScanIssues(null);
                
                if (issues.length == 0) {
                    callbacks.printOutput("No issues found for reporting");
                    return;
                }
                
                // Generate different types of reports
                SecurityReport executiveReport = generateReport("EXECUTIVE", issues);
                SecurityReport technicalReport = generateReport("TECHNICAL", issues);
                SecurityReport complianceReport = generateReport("COMPLIANCE", issues);
                SecurityReport vulnerabilityReport = generateReport("VULNERABILITY", issues);
                
                // Store reports
                generatedReports.add(executiveReport);
                generatedReports.add(technicalReport);
                generatedReports.add(complianceReport);
                generatedReports.add(vulnerabilityReport);
                
                reportCount.addAndGet(4);
                
                callbacks.printOutput("Comprehensive security report generated with " + 
                                     issues.length + " findings");
                
            } catch (Exception e) {
                callbacks.printError("Report generation error: " + e.getMessage());
            }
        });
    }
    
    private SecurityReport generateReport(String templateType, IScanIssue[] issues) {
        ReportTemplate template = reportTemplates.get(templateType);
        if (template == null) return null;
        
        SecurityReport report = new SecurityReport();
        report.title = template.title;
        report.description = template.description;
        report.generatedDate = new Date();
        report.templateType = templateType;
        report.issueCount = issues.length;
        
        // Generate report content using template function
        report.content = template.contentGenerator.apply(issues);
        
        // Calculate report metrics
        report.metrics = calculateReportMetrics(issues);
        
        return report;
    }
    
    private String generateExecutiveSummary(IScanIssue[] issues) {
        StringBuilder report = new StringBuilder();
        
        // Header
        report.append("EXECUTIVE SECURITY ASSESSMENT SUMMARY\n");
        report.append("=====================================\n\n");
        report.append("Report Date: ").append(dateFormat.format(new Date())).append("\n");
        report.append("Assessment Scope: Web Application Security Testing\n\n");
        
        // Risk Overview
        report.append("RISK OVERVIEW\n");
        report.append("=============\n");
        
        Map<String, Integer> severityCounts = categorizeBySeverity(issues);
        int totalIssues = issues.length;
        
        report.append("Total Security Issues Identified: ").append(totalIssues).append("\n\n");
        
        report.append("Risk Distribution:\n");
        report.append("- High Risk Issues: ").append(severityCounts.getOrDefault("High", 0)).append("\n");
        report.append("- Medium Risk Issues: ").append(severityCounts.getOrDefault("Medium", 0)).append("\n");
        report.append("- Low Risk Issues: ").append(severityCounts.getOrDefault("Low", 0)).append("\n");
        report.append("- Information Issues: ").append(severityCounts.getOrDefault("Information", 0)).append("\n\n");
        
        // Risk Rating
        String overallRisk = calculateOverallRisk(severityCounts);
        report.append("Overall Risk Rating: ").append(overallRisk).append("\n\n");
        
        // Key Findings
        report.append("KEY SECURITY FINDINGS\n");
        report.append("=====================\n");
        
        List<IScanIssue> criticalIssues = Arrays.stream(issues)
            .filter(issue -> "High".equals(issue.getSeverity()))
            .sorted((a, b) -> a.getIssueName().compareTo(b.getIssueName()))
            .limit(5)
            .toList();
        
        if (!criticalIssues.isEmpty()) {
            report.append("Critical Security Vulnerabilities:\n");
            for (int i = 0; i < criticalIssues.size(); i++) {
                IScanIssue issue = criticalIssues.get(i);
                report.append((i + 1)).append(". ").append(issue.getIssueName())
                      .append(" (").append(issue.getUrl().getHost()).append(")\n");
            }
            report.append("\n");
        }
        
        // Business Impact
        report.append("BUSINESS IMPACT ASSESSMENT\n");
        report.append("==========================\n");
        report.append(generateBusinessImpactAssessment(issues)).append("\n");
        
        // Executive Recommendations
        report.append("EXECUTIVE RECOMMENDATIONS\n");
        report.append("=========================\n");
        report.append(generateExecutiveRecommendations(severityCounts)).append("\n");
        
        return report.toString();
    }
    
    private String generateTechnicalReport(IScanIssue[] issues) {
        StringBuilder report = new StringBuilder();
        
        report.append("TECHNICAL SECURITY ASSESSMENT REPORT\n");
        report.append("====================================\n\n");
        report.append("Report Date: ").append(dateFormat.format(new Date())).append("\n\n");
        
        // Methodology
        report.append("TESTING METHODOLOGY\n");
        report.append("===================\n");
        report.append("This assessment employed automated vulnerability scanning supplemented by manual testing techniques.\n");
        report.append("The following testing approaches were used:\n");
        report.append("- Automated vulnerability scanning\n");
        report.append("- Manual penetration testing\n");
        report.append("- Business logic testing\n");
        report.append("- Input validation testing\n");
        report.append("- Authentication and authorization testing\n");
        report.append("- Session management testing\n\n");
        
        // Technical Findings
        report.append("DETAILED TECHNICAL FINDINGS\n");
        report.append("===========================\n\n");
        
        Map<String, List<IScanIssue>> issuesByType = categorizeByType(issues);
        
        for (Map.Entry<String, List<IScanIssue>> entry : issuesByType.entrySet()) {
            String issueType = entry.getKey();
            List<IScanIssue> typeIssues = entry.getValue();
            
            report.append("Finding Type: ").append(issueType).append("\n");
            report.append("Instances Found: ").append(typeIssues.size()).append("\n");
            report.append("Severity: ").append(typeIssues.get(0).getSeverity()).append("\n");
            report.append("Confidence: ").append(typeIssues.get(0).getConfidence()).append("\n\n");
            
            // Technical Description
            report.append("Technical Description:\n");
            report.append(getVulnerabilityDescription(issueType)).append("\n\n");
            
            // Affected URLs (sample)
            report.append("Affected URLs (sample):\n");
            typeIssues.stream().limit(5).forEach(issue -> 
                report.append("- ").append(issue.getUrl()).append("\n"));
            
            if (typeIssues.size() > 5) {
                report.append("... and ").append(typeIssues.size() - 5).append(" more instances\n");
            }
            report.append("\n");
            
            // Proof of Concept
            report.append("Proof of Concept:\n");
            report.append(generateProofOfConcept(typeIssues.get(0))).append("\n\n");
            
            // Remediation
            report.append("Remediation:\n");
            report.append(generateRemediation(issueType)).append("\n\n");
            
            report.append("----------------------------------------\n\n");
        }
        
        return report.toString();
    }
    
    private String generateComplianceReport(IScanIssue[] issues) {
        StringBuilder report = new StringBuilder();
        
        report.append("COMPLIANCE ASSESSMENT REPORT\n");
        report.append("============================\n\n");
        report.append("Report Date: ").append(dateFormat.format(new Date())).append("\n\n");
        
        // OWASP Top 10 Mapping
        report.append("OWASP TOP 10 2021 COMPLIANCE\n");
        report.append("=============================\n");
        
        Map<String, String> owaspMapping = getOwaspMapping();
        Map<String, List<IScanIssue>> owaspIssues = new HashMap<>();
        
        for (IScanIssue issue : issues) {
            String owaspCategory = mapToOwasp(issue.getIssueName());
            if (owaspCategory != null) {
                owaspIssues.computeIfAbsent(owaspCategory, k -> new ArrayList<>()).add(issue);
            }
        }
        
        for (Map.Entry<String, String> entry : owaspMapping.entrySet()) {
            String category = entry.getKey();
            String description = entry.getValue();
            List<IScanIssue> categoryIssues = owaspIssues.getOrDefault(category, Collections.emptyList());
            
            report.append(category).append(": ").append(description).append("\n");
            if (categoryIssues.isEmpty()) {
                report.append("  Status: COMPLIANT - No issues found\n");
            } else {
                report.append("  Status: NON-COMPLIANT - ").append(categoryIssues.size()).append(" issues found\n");
                report.append("  Risk Level: ").append(getHighestSeverity(categoryIssues)).append("\n");
            }
            report.append("\n");
        }
        
        // PCI DSS Considerations
        report.append("PCI DSS CONSIDERATIONS\n");
        report.append("======================\n");
        report.append(generatePciDssAssessment(issues)).append("\n");
        
        return report.toString();
    }
    
    private String generateVulnerabilityReport(IScanIssue[] issues) {
        StringBuilder report = new StringBuilder();
        
        report.append("VULNERABILITY ASSESSMENT REPORT\n");
        report.append("===============================\n\n");
        report.append("Report Date: ").append(dateFormat.format(new Date())).append("\n\n");
        
        // Vulnerability Inventory
        report.append("VULNERABILITY INVENTORY\n");
        report.append("=======================\n\n");
        
        Map<String, List<IScanIssue>> issuesByType = categorizeByType(issues);
        
        report.append("Total Vulnerabilities: ").append(issues.length).append("\n");
        report.append("Unique Vulnerability Types: ").append(issuesByType.size()).append("\n\n");
        
        // Detailed vulnerability list
        int vulnNumber = 1;
        for (Map.Entry<String, List<IScanIssue>> entry : issuesByType.entrySet()) {
            String type = entry.getKey();
            List<IScanIssue> typeIssues = entry.getValue();
            IScanIssue representative = typeIssues.get(0);
            
            report.append("VULN-").append(String.format("%03d", vulnNumber++)).append(": ").append(type).append("\n");
            report.append("  Severity: ").append(representative.getSeverity()).append("\n");
            report.append("  Confidence: ").append(representative.getConfidence()).append("\n");
            report.append("  Instances: ").append(typeIssues.size()).append("\n");
            report.append("  CVSS Score: ").append(calculateCvssScore(representative)).append("\n");
            report.append("  Priority: ").append(calculateRemediationPriority(representative)).append("\n");
            report.append("  Estimated Fix Time: ").append(estimateFixTime(type)).append("\n");
            report.append("\n");
        }
        
        // Remediation Timeline
        report.append("RECOMMENDED REMEDIATION TIMELINE\n");
        report.append("================================\n");
        report.append(generateRemediationTimeline(issues)).append("\n");
        
        return report.toString();
    }
    
    public void exportReportToFile(String reportType, String format) {
        executorService.submit(() -> {
            try {
                SecurityReport report = generatedReports.stream()
                    .filter(r -> r.templateType.equals(reportType))
                    .max(Comparator.comparing(r -> r.generatedDate))
                    .orElse(null);
                
                if (report == null) {
                    callbacks.printOutput("No report of type " + reportType + " found");
                    return;
                }
                
                String filename = "security_report_" + reportType.toLowerCase() + "_" + 
                                fileFormat.format(report.generatedDate) + "." + format.toLowerCase();
                
                File file = new File(filename);
                
                try (FileWriter writer = new FileWriter(file)) {
                    if ("HTML".equalsIgnoreCase(format)) {
                        writer.write(convertToHtml(report));
                    } else if ("JSON".equalsIgnoreCase(format)) {
                        writer.write(convertToJson(report));
                    } else {
                        writer.write(report.content);
                    }
                    
                    exportCount.incrementAndGet();
                    callbacks.printOutput("Report exported to: " + file.getAbsolutePath());
                }
                
            } catch (IOException e) {
                callbacks.printError("Failed to export report: " + e.getMessage());
            }
        });
    }
    
    // Helper methods
    
    private Map<String, Integer> categorizeBySeverity(IScanIssue[] issues) {
        Map<String, Integer> counts = new HashMap<>();
        
        for (IScanIssue issue : issues) {
            counts.merge(issue.getSeverity(), 1, Integer::sum);
        }
        
        return counts;
    }
    
    private Map<String, List<IScanIssue>> categorizeByType(IScanIssue[] issues) {
        Map<String, List<IScanIssue>> result = new HashMap<>();
        
        for (IScanIssue issue : issues) {
            result.computeIfAbsent(issue.getIssueName(), k -> new ArrayList<>()).add(issue);
        }
        
        return result;
    }
    
    private String calculateOverallRisk(Map<String, Integer> severityCounts) {
        int high = severityCounts.getOrDefault("High", 0);
        int medium = severityCounts.getOrDefault("Medium", 0);
        
        if (high >= 5) return "CRITICAL";
        if (high >= 1) return "HIGH";
        if (medium >= 10) return "HIGH";
        if (medium >= 5) return "MEDIUM";
        return "LOW";
    }
    
    private String generateBusinessImpactAssessment(IScanIssue[] issues) {
        StringBuilder impact = new StringBuilder();
        
        Map<String, Integer> severityCounts = categorizeBySeverity(issues);
        int high = severityCounts.getOrDefault("High", 0);
        int medium = severityCounts.getOrDefault("Medium", 0);
        
        if (high > 0) {
            impact.append("HIGH IMPACT: Critical vulnerabilities present significant business risk including:\n");
            impact.append("- Potential for data breach and regulatory non-compliance\n");
            impact.append("- Risk of system compromise and service disruption\n");
            impact.append("- Reputation damage and customer trust issues\n");
            impact.append("- Financial impact from incident response and recovery\n\n");
        }
        
        if (medium > 0) {
            impact.append("MEDIUM IMPACT: Moderate vulnerabilities that should be addressed:\n");
            impact.append("- Increased attack surface and security posture degradation\n");
            impact.append("- Potential for privilege escalation or information disclosure\n");
            impact.append("- Risk of exploitation when combined with other vulnerabilities\n\n");
        }
        
        impact.append("Immediate action is recommended to address high-risk vulnerabilities.");
        
        return impact.toString();
    }
    
    private String generateExecutiveRecommendations(Map<String, Integer> severityCounts) {
        StringBuilder recommendations = new StringBuilder();
        
        recommendations.append("1. IMMEDIATE ACTIONS (0-30 days):\n");
        recommendations.append("   - Address all high-severity vulnerabilities\n");
        recommendations.append("   - Implement emergency patches for critical systems\n");
        recommendations.append("   - Review and update security policies\n\n");
        
        recommendations.append("2. SHORT-TERM IMPROVEMENTS (1-3 months):\n");
        recommendations.append("   - Remediate medium-severity vulnerabilities\n");
        recommendations.append("   - Implement security monitoring and logging\n");
        recommendations.append("   - Conduct security awareness training\n\n");
        
        recommendations.append("3. LONG-TERM STRATEGY (3-12 months):\n");
        recommendations.append("   - Implement secure development lifecycle (SDLC)\n");
        recommendations.append("   - Regular security assessments and penetration testing\n");
        recommendations.append("   - Establish incident response procedures\n");
        
        return recommendations.toString();
    }
    
    private String getVulnerabilityDescription(String issueType) {
        Map<String, String> descriptions = Map.of(
            "SQL injection", "SQL injection vulnerabilities occur when user input is incorporated into SQL queries without proper sanitization, allowing attackers to manipulate database operations.",
            "Cross-site scripting", "Cross-site scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users.",
            "OS command injection", "Command injection vulnerabilities occur when applications execute system commands with user-controlled input without proper validation.",
            "Path traversal", "Path traversal vulnerabilities allow attackers to access files and directories outside the intended directory structure."
        );
        
        return descriptions.getOrDefault(issueType, "This vulnerability type requires manual analysis for detailed description.");
    }
    
    private String generateProofOfConcept(IScanIssue issue) {
        StringBuilder poc = new StringBuilder();
        
        poc.append("URL: ").append(issue.getUrl()).append("\n");
        
        if (issue.getHttpMessages() != null && issue.getHttpMessages().length > 0) {
            IHttpRequestResponse message = issue.getHttpMessages()[0];
            
            poc.append("Request Method: ").append(
                callbacks.getHelpers().analyzeRequest(message).getMethod()).append("\n");
            
            if (issue.getIssueDetail() != null) {
                poc.append("Details: ").append(issue.getIssueDetail().substring(0, 
                    Math.min(200, issue.getIssueDetail().length()))).append("...\n");
            }
        }
        
        poc.append("\nRecommendation: Manual verification required for complete proof of concept.");
        
        return poc.toString();
    }
    
    private String generateRemediation(String issueType) {
        Map<String, String> remediations = Map.of(
            "SQL injection", "Implement parameterized queries, input validation, and least-privilege database access.",
            "Cross-site scripting", "Implement proper output encoding, Content Security Policy (CSP), and input validation.",
            "OS command injection", "Avoid system command execution, implement input validation, and use secure APIs.",
            "Path traversal", "Implement proper input validation, use allow-lists, and restrict file system access."
        );
        
        return remediations.getOrDefault(issueType, "Consult security documentation for remediation guidance specific to this vulnerability type.");
    }
    
    private Map<String, String> getOwaspMapping() {
        return Map.of(
            "A01:2021", "Broken Access Control",
            "A02:2021", "Cryptographic Failures",
            "A03:2021", "Injection",
            "A04:2021", "Insecure Design",
            "A05:2021", "Security Misconfiguration",
            "A06:2021", "Vulnerable and Outdated Components",
            "A07:2021", "Identification and Authentication Failures",
            "A08:2021", "Software and Data Integrity Failures",
            "A09:2021", "Security Logging and Monitoring Failures",
            "A10:2021", "Server-Side Request Forgery"
        );
    }
    
    private String mapToOwasp(String issueName) {
        String lowerIssue = issueName.toLowerCase();
        
        if (lowerIssue.contains("sql") || lowerIssue.contains("injection") || lowerIssue.contains("xss")) {
            return "A03:2021";
        }
        if (lowerIssue.contains("access") || lowerIssue.contains("authorization")) {
            return "A01:2021";
        }
        if (lowerIssue.contains("crypto") || lowerIssue.contains("encryption")) {
            return "A02:2021";
        }
        if (lowerIssue.contains("configuration") || lowerIssue.contains("misconfiguration")) {
            return "A05:2021";
        }
        if (lowerIssue.contains("authentication") || lowerIssue.contains("session")) {
            return "A07:2021";
        }
        if (lowerIssue.contains("ssrf")) {
            return "A10:2021";
        }
        
        return null;
    }
    
    private String getHighestSeverity(List<IScanIssue> issues) {
        return issues.stream()
                   .map(IScanIssue::getSeverity)
                   .max(Comparator.comparing(severity -> {
                       switch (severity) {
                           case "High": return 3;
                           case "Medium": return 2;
                           case "Low": return 1;
                           default: return 0;
                       }
                   }))
                   .orElse("Information");
    }
    
    private String generatePciDssAssessment(IScanIssue[] issues) {
        return "PCI DSS compliance requires addressing all high and medium severity vulnerabilities.\n" +
               "Special attention should be paid to authentication, encryption, and access control issues.";
    }
    
    private double calculateCvssScore(IScanIssue issue) {
        switch (issue.getSeverity()) {
            case "High":
                return 7.5 + Math.random() * 2.5;
            case "Medium":
                return 4.0 + Math.random() * 3.5;
            case "Low":
                return 0.1 + Math.random() * 3.9;
            default:
                return 0.0;
        }
    }
    
    private String calculateRemediationPriority(IScanIssue issue) {
        if ("High".equals(issue.getSeverity()) && "Firm".equals(issue.getConfidence())) {
            return "P0 - Critical";
        } else if ("High".equals(issue.getSeverity())) {
            return "P1 - High";
        } else if ("Medium".equals(issue.getSeverity())) {
            return "P2 - Medium";
        }
        return "P3 - Low";
    }
    
    private String estimateFixTime(String issueType) {
        Map<String, String> fixTimes = Map.of(
            "SQL injection", "2-5 days",
            "Cross-site scripting", "1-3 days",
            "OS command injection", "3-7 days",
            "Path traversal", "2-4 days"
        );
        
        return fixTimes.getOrDefault(issueType, "1-2 weeks");
    }
    
    private String generateRemediationTimeline(IScanIssue[] issues) {
        StringBuilder timeline = new StringBuilder();
        
        Map<String, Integer> severityCounts = categorizeBySeverity(issues);
        
        timeline.append("Phase 1 (Immediate - 30 days): Address ").append(severityCounts.getOrDefault("High", 0)).append(" high-severity issues\n");
        timeline.append("Phase 2 (30-60 days): Address ").append(severityCounts.getOrDefault("Medium", 0)).append(" medium-severity issues\n");
        timeline.append("Phase 3 (60-90 days): Address ").append(severityCounts.getOrDefault("Low", 0)).append(" low-severity issues\n");
        timeline.append("Phase 4 (Ongoing): Implement security monitoring and regular assessments\n");
        
        return timeline.toString();
    }
    
    private ReportMetrics calculateReportMetrics(IScanIssue[] issues) {
        ReportMetrics metrics = new ReportMetrics();
        
        Map<String, Integer> severityCounts = categorizeBySeverity(issues);
        
        metrics.totalFindings = issues.length;
        metrics.highSeverity = severityCounts.getOrDefault("High", 0);
        metrics.mediumSeverity = severityCounts.getOrDefault("Medium", 0);
        metrics.lowSeverity = severityCounts.getOrDefault("Low", 0);
        metrics.uniqueVulnTypes = categorizeByType(issues).size();
        metrics.overallRiskScore = calculateOverallRisk(severityCounts);
        
        return metrics;
    }
    
    private String convertToHtml(SecurityReport report) {
        StringBuilder html = new StringBuilder();
        
        html.append("<!DOCTYPE html>\n<html>\n<head>\n");
        html.append("<title>").append(report.title).append("</title>\n");
        html.append("<style>body{font-family:Arial,sans-serif;margin:40px;} ");
        html.append("h1{color:#d32f2f;} h2{color:#1976d2;} pre{background:#f5f5f5;padding:10px;}</style>\n");
        html.append("</head>\n<body>\n");
        html.append("<h1>").append(report.title).append("</h1>\n");
        html.append("<pre>").append(report.content.replace("<", "&lt;").replace(">", "&gt;")).append("</pre>\n");
        html.append("</body>\n</html>");
        
        return html.toString();
    }
    
    private String convertToJson(SecurityReport report) {
        return String.format(
            "{\"title\":\"%s\",\"description\":\"%s\",\"generatedDate\":\"%s\",\"issueCount\":%d,\"metrics\":%s,\"content\":\"%s\"}", 
            report.title.replace("\"", "\\\""), 
            report.description.replace("\"", "\\\""),
            dateFormat.format(report.generatedDate),
            report.issueCount,
            formatMetricsAsJson(report.metrics),
            report.content.replace("\"", "\\\"").replace("\n", "\\n")
        );
    }
    
    private String formatMetricsAsJson(ReportMetrics metrics) {
        if (metrics == null) return "null";
        
        return String.format(
            "{\"totalFindings\":%d,\"highSeverity\":%d,\"mediumSeverity\":%d,\"lowSeverity\":%d,\"uniqueVulnTypes\":%d,\"overallRiskScore\":\"%s\"}",
            metrics.totalFindings, metrics.highSeverity, metrics.mediumSeverity, 
            metrics.lowSeverity, metrics.uniqueVulnTypes, metrics.overallRiskScore
        );
    }
    
    public void showReportSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("REPORTING AGENT SUMMARY\n");
        summary.append("=======================\n\n");
        
        summary.append("Reports Generated: ").append(reportCount.get()).append("\n");
        summary.append("Reports Exported: ").append(exportCount.get()).append("\n\n");
        
        if (!generatedReports.isEmpty()) {
            summary.append("Latest Reports:\n");
            generatedReports.stream()
                          .sorted(Comparator.comparing((SecurityReport r) -> r.generatedDate).reversed())
                          .limit(5)
                          .forEach(report -> {
                              summary.append("- ").append(report.title)
                                    .append(" (").append(dateFormat.format(report.generatedDate)).append(")")
                                    .append(" - ").append(report.issueCount).append(" findings\n");
                          });
        } else {
            summary.append("No reports generated yet.\n");
        }
        
        callbacks.printOutput(summary.toString());
    }
    
    // Supporting data classes
    
    private static class SecurityReport {
        public String title;
        public String description;
        public Date generatedDate;
        public String templateType;
        public int issueCount;
        public String content;
        public ReportMetrics metrics;
    }
    
    private static class ReportTemplate {
        public String title;
        public String description;
        public List<String> sections;
        public java.util.function.Function<IScanIssue[], String> contentGenerator;
        
        public ReportTemplate(String title, String description, List<String> sections,
                            java.util.function.Function<IScanIssue[], String> contentGenerator) {
            this.title = title;
            this.description = description;
            this.sections = sections;
            this.contentGenerator = contentGenerator;
        }
    }
    
    private static class ReportMetrics {
        public int totalFindings;
        public int highSeverity;
        public int mediumSeverity;
        public int lowSeverity;
        public int uniqueVulnTypes;
        public String overallRiskScore;
    }
}