package com.secure.ai.burp.integrations.nuclei;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.ai.burp.models.data.ApplicationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static com.secure.ai.burp.integrations.nuclei.NucleiDataClasses.*;

/**
 * Processes and analyzes Nuclei scan results
 */
class ScanResultProcessor {
    private static final Logger logger = LoggerFactory.getLogger(ScanResultProcessor.class);
    
    private final ObjectMapper objectMapper;
    
    // Severity mappings and weights
    private static final Map<String, Integer> SEVERITY_WEIGHTS = Map.of(
        "critical", 10,
        "high", 8,
        "medium", 6,
        "low", 4,
        "info", 2
    );
    
    // Vulnerability type mappings
    private static final Map<String, String> TYPE_MAPPINGS = Map.of(
        "xss", "Cross-Site Scripting",
        "sqli", "SQL Injection",
        "rce", "Remote Code Execution",
        "lfi", "Local File Inclusion",
        "rfi", "Remote File Inclusion",
        "xxe", "XML External Entity",
        "csrf", "Cross-Site Request Forgery",
        "ssti", "Server-Side Template Injection"
    );
    
    public ScanResultProcessor(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
    
    /**
     * Process raw Nuclei results into structured findings
     */
    public ProcessedResults processResults(List<NucleiResult> results, ApplicationContext context) {
        logger.info("Processing {} Nuclei results", results.size());
        
        try {
            // Deduplicate results
            List<NucleiResult> deduplicatedResults = deduplicateResults(results);
            
            // Convert to vulnerability findings
            List<VulnerabilityFinding> findings = convertToFindings(deduplicatedResults, context);
            
            // Enrich findings with context
            List<VulnerabilityFinding> enrichedFindings = enrichFindings(findings, context);
            
            // Calculate statistics
            ScanStatistics statistics = calculateStatistics(deduplicatedResults, enrichedFindings);
            
            logger.info("Processed results: {} findings from {} raw results", 
                       enrichedFindings.size(), results.size());
            
            return new ProcessedResults(deduplicatedResults, enrichedFindings, statistics);
            
        } catch (Exception e) {
            logger.error("Failed to process Nuclei results", e);
            
            // Return minimal result on error
            ScanStatistics fallbackStats = new ScanStatistics(
                0, 0, results.size(), Map.of(), Map.of(), 0, 0.0);
            return new ProcessedResults(results, List.of(), fallbackStats);
        }
    }
    
    private List<NucleiResult> deduplicateResults(List<NucleiResult> results) {
        // Use LinkedHashSet to preserve order while removing duplicates
        Set<NucleiResult> uniqueResults = new LinkedHashSet<>(results);
        
        // Additional deduplication based on template ID and matched location
        Map<String, NucleiResult> deduplicationMap = new HashMap<>();
        
        for (NucleiResult result : uniqueResults) {
            String key = result.getTemplateId() + "|" + result.getMatchedAt();
            
            // Keep the result with higher severity or more recent timestamp
            NucleiResult existing = deduplicationMap.get(key);
            if (existing == null || 
                getSeverityWeight(result.getSeverity()) > getSeverityWeight(existing.getSeverity()) ||
                (getSeverityWeight(result.getSeverity()) == getSeverityWeight(existing.getSeverity()) && 
                 result.getTimestamp() > existing.getTimestamp())) {
                deduplicationMap.put(key, result);
            }
        }
        
        return new ArrayList<>(deduplicationMap.values());
    }
    
    private List<VulnerabilityFinding> convertToFindings(List<NucleiResult> results, ApplicationContext context) {
        return results.stream()
            .map(result -> convertToFinding(result, context))
            .collect(Collectors.toList());
    }
    
    private VulnerabilityFinding convertToFinding(NucleiResult result, ApplicationContext context) {
        String vulnerabilityType = extractVulnerabilityType(result);
        String location = result.getMatchedAt();
        
        // Generate recommendation based on vulnerability type and context
        String recommendation = generateRecommendation(vulnerabilityType, result, context);
        
        // Extract references from tags or use default
        List<String> references = extractReferences(result);
        
        // Build metadata
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("template_id", result.getTemplateId());
        metadata.put("matcher_name", result.getMatcherName());
        metadata.put("type", result.getType());
        metadata.put("tags", result.getTags());
        metadata.put("extracted_results", result.getExtractedResults());
        metadata.put("timestamp", result.getTimestamp());
        metadata.put("nuclei_source", true);
        
        return new VulnerabilityFinding(
            result.getTemplateId(),
            result.getName(),
            vulnerabilityType,
            result.getSeverity(),
            result.getDescription(),
            location,
            recommendation,
            references,
            metadata
        );
    }
    
    private List<VulnerabilityFinding> enrichFindings(List<VulnerabilityFinding> findings, ApplicationContext context) {
        return findings.stream()
            .map(finding -> enrichFinding(finding, context))
            .collect(Collectors.toList());
    }
    
    private VulnerabilityFinding enrichFinding(VulnerabilityFinding finding, ApplicationContext context) {
        Map<String, Object> enrichedMetadata = new HashMap<>(finding.getMetadata());
        
        // Add context information
        enrichedMetadata.put("detected_technologies", context.getDetectedTechnologies());
        enrichedMetadata.put("application_context", context.getApplicationType());
        
        // Add risk assessment
        double riskScore = calculateRiskScore(finding, context);
        enrichedMetadata.put("risk_score", riskScore);
        
        // Add exploitability assessment
        String exploitability = assessExploitability(finding, context);
        enrichedMetadata.put("exploitability", exploitability);
        
        // Add business impact
        String businessImpact = assessBusinessImpact(finding, context);
        enrichedMetadata.put("business_impact", businessImpact);
        
        // Enhanced recommendation
        String enhancedRecommendation = enhanceRecommendation(finding, context);
        
        return new VulnerabilityFinding(
            finding.getId(),
            finding.getName(),
            finding.getType(),
            finding.getSeverity(),
            finding.getDescription(),
            finding.getLocation(),
            enhancedRecommendation,
            finding.getReferences(),
            enrichedMetadata
        );
    }
    
    private String extractVulnerabilityType(NucleiResult result) {
        String templateId = result.getTemplateId().toLowerCase();
        String tags = result.getTags().toLowerCase();
        String name = result.getName().toLowerCase();
        
        // Check template ID patterns
        for (Map.Entry<String, String> entry : TYPE_MAPPINGS.entrySet()) {
            String pattern = entry.getKey();
            if (templateId.contains(pattern) || tags.contains(pattern) || name.contains(pattern)) {
                return entry.getValue();
            }
        }
        
        // Check for common patterns in description
        String description = result.getDescription().toLowerCase();
        if (description.contains("cross-site scripting") || description.contains("xss")) {
            return "Cross-Site Scripting";
        }
        
        if (description.contains("sql injection") || description.contains("sqli")) {
            return "SQL Injection";
        }
        
        if (description.contains("remote code execution") || description.contains("rce")) {
            return "Remote Code Execution";
        }
        
        // Default to generic classification
        if (templateId.startsWith("cve-")) {
            return "Known Vulnerability (CVE)";
        }
        
        if (tags.contains("misconfiguration")) {
            return "Security Misconfiguration";
        }
        
        if (tags.contains("exposure")) {
            return "Information Disclosure";
        }
        
        return "Security Issue";
    }
    
    private String generateRecommendation(String vulnerabilityType, NucleiResult result, ApplicationContext context) {
        StringBuilder recommendation = new StringBuilder();
        
        switch (vulnerabilityType) {
            case "Cross-Site Scripting":
                recommendation.append("Implement proper input validation and output encoding. ");
                recommendation.append("Use Content Security Policy (CSP) headers to mitigate XSS attacks. ");
                if (context.getDetectedTechnologies().contains("React")) {
                    recommendation.append("Avoid using dangerouslySetInnerHTML and use React's built-in XSS protection.");
                }
                break;
                
            case "SQL Injection":
                recommendation.append("Use parameterized queries or prepared statements. ");
                recommendation.append("Implement proper input validation and sanitization. ");
                if (context.getDetectedTechnologies().stream().anyMatch(t -> t.contains("MySQL"))) {
                    recommendation.append("Configure MySQL with least-privilege principles and disable dangerous functions.");
                }
                break;
                
            case "Remote Code Execution":
                recommendation.append("URGENT: Patch the vulnerable component immediately. ");
                recommendation.append("Implement strong input validation and avoid dynamic code execution. ");
                recommendation.append("Use application sandboxing and principle of least privilege.");
                break;
                
            case "Security Misconfiguration":
                recommendation.append("Review and harden server configuration. ");
                recommendation.append("Disable unnecessary services and features. ");
                recommendation.append("Implement security headers and proper access controls.");
                break;
                
            case "Information Disclosure":
                recommendation.append("Restrict access to sensitive information. ");
                recommendation.append("Implement proper error handling to prevent information leakage. ");
                recommendation.append("Review directory permissions and web server configuration.");
                break;
                
            default:
                recommendation.append("Review the vulnerability details and implement appropriate security measures. ");
                recommendation.append("Consider the specific recommendations from the Nuclei template: ");
                recommendation.append(result.getTemplateId());
        }
        
        return recommendation.toString();
    }
    
    private List<String> extractReferences(NucleiResult result) {
        List<String> references = new ArrayList<>();
        
        // Add template-specific references
        String templateId = result.getTemplateId();
        if (templateId.startsWith("cve-")) {
            references.add("https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + templateId.toUpperCase());
        }
        
        // Add OWASP references based on vulnerability type
        String tags = result.getTags().toLowerCase();
        if (tags.contains("xss")) {
            references.add("https://owasp.org/www-community/attacks/xss/");
        }
        
        if (tags.contains("sqli") || tags.contains("sql")) {
            references.add("https://owasp.org/www-community/attacks/SQL_Injection");
        }
        
        if (tags.contains("rce")) {
            references.add("https://owasp.org/www-community/attacks/Code_Injection");
        }
        
        // Add general security references
        references.add("https://nuclei.projectdiscovery.io/templating-guide/");
        
        return references;
    }
    
    private double calculateRiskScore(VulnerabilityFinding finding, ApplicationContext context) {
        double score = 0.0;
        
        // Base score from severity
        score += getSeverityWeight(finding.getSeverity()) / 10.0;
        
        // Increase score based on exploitability
        String location = finding.getLocation();
        if (location.contains("admin") || location.contains("login")) {
            score += 0.2; // Admin/login endpoints are higher risk
        }
        
        if (location.contains("api")) {
            score += 0.1; // API endpoints have increased risk
        }
        
        // Technology-specific risk adjustments
        for (String tech : context.getDetectedTechnologies()) {
            if (tech.contains("WordPress") && finding.getType().contains("XSS")) {
                score += 0.15; // WordPress XSS vulnerabilities are commonly exploited
            }
            
            if (tech.contains("PHP") && finding.getType().contains("Code Execution")) {
                score += 0.2; // PHP RCE vulnerabilities are high risk
            }
        }
        
        // Cap the score at 1.0
        return Math.min(score, 1.0);
    }
    
    private String assessExploitability(VulnerabilityFinding finding, ApplicationContext context) {
        int score = 0;
        
        // Severity-based scoring
        switch (finding.getSeverity().toLowerCase()) {
            case "critical": score += 4; break;
            case "high": score += 3; break;
            case "medium": score += 2; break;
            case "low": score += 1; break;
        }
        
        // Type-based scoring
        switch (finding.getType()) {
            case "Remote Code Execution":
            case "SQL Injection":
                score += 2;
                break;
            case "Cross-Site Scripting":
                score += 1;
                break;
        }
        
        // Context-based scoring
        String location = finding.getLocation();
        if (location.contains("admin") || location.contains("/wp-admin/")) {
            score += 1;
        }
        
        // Return assessment
        if (score >= 6) return "Critical";
        if (score >= 4) return "High";
        if (score >= 2) return "Medium";
        return "Low";
    }
    
    private String assessBusinessImpact(VulnerabilityFinding finding, ApplicationContext context) {
        List<String> impacts = new ArrayList<>();
        
        switch (finding.getType()) {
            case "SQL Injection":
                impacts.add("Data breach and unauthorized database access");
                impacts.add("Customer data theft and privacy violations");
                impacts.add("Regulatory compliance violations (GDPR, CCPA)");
                break;
                
            case "Cross-Site Scripting":
                impacts.add("Session hijacking and account takeover");
                impacts.add("Defacement and reputation damage");
                impacts.add("Malware distribution to users");
                break;
                
            case "Remote Code Execution":
                impacts.add("Complete server compromise");
                impacts.add("Data theft and system manipulation");
                impacts.add("Service disruption and downtime");
                break;
                
            case "Information Disclosure":
                impacts.add("Sensitive data exposure");
                impacts.add("Reconnaissance for further attacks");
                impacts.add("Compliance and regulatory issues");
                break;
                
            default:
                impacts.add("Potential security compromise");
                impacts.add("Increased attack surface");
        }
        
        return String.join("; ", impacts);
    }
    
    private String enhanceRecommendation(VulnerabilityFinding finding, ApplicationContext context) {
        StringBuilder enhanced = new StringBuilder(finding.getRecommendation());
        
        // Add priority based on severity
        switch (finding.getSeverity().toLowerCase()) {
            case "critical":
                enhanced.insert(0, "🔴 CRITICAL - IMMEDIATE ACTION REQUIRED: ");
                break;
            case "high":
                enhanced.insert(0, "🟠 HIGH PRIORITY - Fix within 24 hours: ");
                break;
            case "medium":
                enhanced.insert(0, "🟡 MEDIUM PRIORITY - Fix within 1 week: ");
                break;
        }
        
        // Add context-specific recommendations
        if (context.getApplicationType().equals("e-commerce") && 
            finding.getType().equals("SQL Injection")) {
            enhanced.append(" Pay special attention to payment processing and customer data protection.");
        }
        
        if (context.getApplicationType().equals("admin-panel") &&
            finding.getType().equals("Cross-Site Scripting")) {
            enhanced.append(" Admin panel XSS vulnerabilities can lead to complete system compromise.");
        }
        
        return enhanced.toString();
    }
    
    private ScanStatistics calculateStatistics(List<NucleiResult> results, List<VulnerabilityFinding> findings) {
        Map<String, Integer> severityCounts = new HashMap<>();
        Map<String, Integer> typeCounts = new HashMap<>();
        
        for (VulnerabilityFinding finding : findings) {
            severityCounts.merge(finding.getSeverity(), 1, Integer::sum);
            typeCounts.merge(finding.getType(), 1, Integer::sum);
        }
        
        // Calculate timing statistics (simplified)
        long scanDuration = results.isEmpty() ? 0 : 
            results.get(results.size() - 1).getTimestamp() - results.get(0).getTimestamp();
        
        double averageResponseTime = 1000.0; // Default 1 second per template
        
        return new ScanStatistics(
            results.size(), // Total templates (simplified)
            results.size(), // Executed templates
            findings.size(),
            severityCounts,
            typeCounts,
            scanDuration,
            averageResponseTime
        );
    }
    
    private int getSeverityWeight(String severity) {
        return SEVERITY_WEIGHTS.getOrDefault(severity.toLowerCase(), 1);
    }
}