package com.secure.ai.burp.integrations.nuclei;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Data classes and supporting structures for Nuclei integration
 */

// Nuclei scan options configuration
static class NucleiScanOptions {
    private final int timeout;
    private final int concurrency;
    private final List<String> severityFilter;
    private final boolean verbose;
    private final boolean monitoringMode;
    private final Map<String, String> customHeaders;
    private final String proxy;
    private final int retries;
    
    private NucleiScanOptions(Builder builder) {
        this.timeout = builder.timeout;
        this.concurrency = builder.concurrency;
        this.severityFilter = builder.severityFilter;
        this.verbose = builder.verbose;
        this.monitoringMode = builder.monitoringMode;
        this.customHeaders = builder.customHeaders;
        this.proxy = builder.proxy;
        this.retries = builder.retries;
    }
    
    public int getTimeout() { return timeout; }
    public int getConcurrency() { return concurrency; }
    public List<String> getSeverityFilter() { return severityFilter; }
    public boolean isVerbose() { return verbose; }
    public boolean isMonitoringMode() { return monitoringMode; }
    public Map<String, String> getCustomHeaders() { return customHeaders; }
    public String getProxy() { return proxy; }
    public int getRetries() { return retries; }
    
    static class Builder {
        private int timeout = 60;
        private int concurrency = 10;
        private List<String> severityFilter = List.of();
        private boolean verbose = false;
        private boolean monitoringMode = false;
        private Map<String, String> customHeaders = Map.of();
        private String proxy = null;
        private int retries = 1;
        
        public Builder withTimeout(int timeout) {
            this.timeout = timeout;
            return this;
        }
        
        public Builder withConcurrency(int concurrency) {
            this.concurrency = concurrency;
            return this;
        }
        
        public Builder withSeverityFilter(List<String> severityFilter) {
            this.severityFilter = severityFilter;
            return this;
        }
        
        public Builder withVerbose(boolean verbose) {
            this.verbose = verbose;
            return this;
        }
        
        public Builder withMonitoringMode(boolean monitoringMode) {
            this.monitoringMode = monitoringMode;
            return this;
        }
        
        public Builder withCustomHeaders(Map<String, String> customHeaders) {
            this.customHeaders = customHeaders;
            return this;
        }
        
        public Builder withProxy(String proxy) {
            this.proxy = proxy;
            return this;
        }
        
        public Builder withRetries(int retries) {
            this.retries = retries;
            return this;
        }
        
        public NucleiScanOptions build() {
            return new NucleiScanOptions(this);
        }
    }
}

// Individual Nuclei scan result
static class NucleiResult {
    private final String templateId;
    private final String name;
    private final String severity;
    private final String description;
    private final String tags;
    private final String matchedAt;
    private final List<String> extractedResults;
    private final String matcherName;
    private final String type;
    private final String host;
    private final long timestamp;
    
    public NucleiResult(String templateId, String name, String severity, String description,
                       String tags, String matchedAt, List<String> extractedResults,
                       String matcherName, String type, String host, long timestamp) {
        this.templateId = templateId;
        this.name = name;
        this.severity = severity;
        this.description = description;
        this.tags = tags;
        this.matchedAt = matchedAt;
        this.extractedResults = extractedResults;
        this.matcherName = matcherName;
        this.type = type;
        this.host = host;
        this.timestamp = timestamp;
    }
    
    // Getters
    public String getTemplateId() { return templateId; }
    public String getName() { return name; }
    public String getSeverity() { return severity; }
    public String getDescription() { return description; }
    public String getTags() { return tags; }
    public String getMatchedAt() { return matchedAt; }
    public List<String> getExtractedResults() { return extractedResults; }
    public String getMatcherName() { return matcherName; }
    public String getType() { return type; }
    public String getHost() { return host; }
    public long getTimestamp() { return timestamp; }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof NucleiResult)) return false;
        NucleiResult other = (NucleiResult) obj;
        return templateId.equals(other.templateId) && 
               matchedAt.equals(other.matchedAt) &&
               host.equals(other.host);
    }
    
    @Override
    public int hashCode() {
        return (templateId + matchedAt + host).hashCode();
    }
}

// Scan session tracking
static class NucleiScanSession {
    private final String sessionId;
    private final String target;
    private final ApplicationContext context;
    private final NucleiScanOptions options;
    private final long startTime;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    
    private volatile String currentPhase = "initializing";
    private volatile List<String> selectedTemplates = List.of();
    
    public NucleiScanSession(String sessionId, String target, ApplicationContext context, 
                           NucleiScanOptions options) {
        this.sessionId = sessionId;
        this.target = target;
        this.context = context;
        this.options = options;
        this.startTime = System.currentTimeMillis();
    }
    
    public void updatePhase(String phase) {
        this.currentPhase = phase;
    }
    
    public void setSelectedTemplates(List<String> templates) {
        this.selectedTemplates = templates;
    }
    
    public void cancel() {
        cancelled.set(true);
    }
    
    public boolean isCancelled() {
        return cancelled.get();
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public String getTarget() { return target; }
    public ApplicationContext getContext() { return context; }
    public NucleiScanOptions getOptions() { return options; }
    public long getStartTime() { return startTime; }
    public String getCurrentPhase() { return currentPhase; }
    public List<String> getSelectedTemplates() { return selectedTemplates; }
}

// Intelligence gathering result
static class IntelligenceResult {
    private final String target;
    private final List<String> technologies;
    private final List<String> endpoints;
    private final Map<String, String> parameters;
    private final DomainInfo domainInfo;
    private final List<String> securityHeaders;
    private final AttackSurfaceAssessment attackSurface;
    
    public IntelligenceResult(String target, List<String> technologies, List<String> endpoints,
                            Map<String, String> parameters, DomainInfo domainInfo,
                            List<String> securityHeaders, AttackSurfaceAssessment attackSurface) {
        this.target = target;
        this.technologies = technologies;
        this.endpoints = endpoints;
        this.parameters = parameters;
        this.domainInfo = domainInfo;
        this.securityHeaders = securityHeaders;
        this.attackSurface = attackSurface;
    }
    
    // Getters
    public String getTarget() { return target; }
    public List<String> getTechnologies() { return technologies; }
    public List<String> getEndpoints() { return endpoints; }
    public Map<String, String> getParameters() { return parameters; }
    public DomainInfo getDomainInfo() { return domainInfo; }
    public List<String> getSecurityHeaders() { return securityHeaders; }
    public AttackSurfaceAssessment getAttackSurface() { return attackSurface; }
}

// Domain information
static class DomainInfo {
    private final String domain;
    private final List<String> subdomains;
    private final List<String> certificates;
    private final Map<String, String> dnsRecords;
    
    public DomainInfo(String domain, List<String> subdomains, List<String> certificates,
                     Map<String, String> dnsRecords) {
        this.domain = domain;
        this.subdomains = subdomains;
        this.certificates = certificates;
        this.dnsRecords = dnsRecords;
    }
    
    // Getters
    public String getDomain() { return domain; }
    public List<String> getSubdomains() { return subdomains; }
    public List<String> getCertificates() { return certificates; }
    public Map<String, String> getDnsRecords() { return dnsRecords; }
}

// Attack surface assessment
static class AttackSurfaceAssessment {
    private final int endpointCount;
    private final int parameterCount;
    private final int technologyCount;
    private final double riskScore;
    
    public AttackSurfaceAssessment(int endpointCount, int parameterCount, 
                                 int technologyCount, double riskScore) {
        this.endpointCount = endpointCount;
        this.parameterCount = parameterCount;
        this.technologyCount = technologyCount;
        this.riskScore = riskScore;
    }
    
    // Getters
    public int getEndpointCount() { return endpointCount; }
    public int getParameterCount() { return parameterCount; }
    public int getTechnologyCount() { return technologyCount; }
    public double getRiskScore() { return riskScore; }
}

// Processed scan results
static class ProcessedResults {
    private final List<NucleiResult> results;
    private final List<VulnerabilityFinding> findings;
    private final ScanStatistics statistics;
    
    public ProcessedResults(List<NucleiResult> results, List<VulnerabilityFinding> findings,
                          ScanStatistics statistics) {
        this.results = results;
        this.findings = findings;
        this.statistics = statistics;
    }
    
    // Getters
    public List<NucleiResult> getResults() { return results; }
    public List<VulnerabilityFinding> getFindings() { return findings; }
    public ScanStatistics getStatistics() { return statistics; }
}

// Vulnerability finding
static class VulnerabilityFinding {
    private final String id;
    private final String name;
    private final String type;
    private final String severity;
    private final String description;
    private final String location;
    private final String recommendation;
    private final List<String> references;
    private final Map<String, Object> metadata;
    
    public VulnerabilityFinding(String id, String name, String type, String severity,
                              String description, String location, String recommendation,
                              List<String> references, Map<String, Object> metadata) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.severity = severity;
        this.description = description;
        this.location = location;
        this.recommendation = recommendation;
        this.references = references;
        this.metadata = metadata;
    }
    
    // Getters
    public String getId() { return id; }
    public String getName() { return name; }
    public String getType() { return type; }
    public String getSeverity() { return severity; }
    public String getDescription() { return description; }
    public String getLocation() { return location; }
    public String getRecommendation() { return recommendation; }
    public List<String> getReferences() { return references; }
    public Map<String, Object> getMetadata() { return metadata; }
}

// Scan statistics
static class ScanStatistics {
    private final int totalTemplates;
    private final int executedTemplates;
    private final int totalFindings;
    private final Map<String, Integer> findingsBySeverity;
    private final Map<String, Integer> findingsByType;
    private final long scanDuration;
    private final double averageResponseTime;
    
    public ScanStatistics(int totalTemplates, int executedTemplates, int totalFindings,
                        Map<String, Integer> findingsBySeverity, Map<String, Integer> findingsByType,
                        long scanDuration, double averageResponseTime) {
        this.totalTemplates = totalTemplates;
        this.executedTemplates = executedTemplates;
        this.totalFindings = totalFindings;
        this.findingsBySeverity = findingsBySeverity;
        this.findingsByType = findingsByType;
        this.scanDuration = scanDuration;
        this.averageResponseTime = averageResponseTime;
    }
    
    // Getters
    public int getTotalTemplates() { return totalTemplates; }
    public int getExecutedTemplates() { return executedTemplates; }
    public int getTotalFindings() { return totalFindings; }
    public Map<String, Integer> getFindingsBySeverity() { return findingsBySeverity; }
    public Map<String, Integer> getFindingsByType() { return findingsByType; }
    public long getScanDuration() { return scanDuration; }
    public double getAverageResponseTime() { return averageResponseTime; }
}

// Gap analysis result
static class GapAnalysisResult {
    private final int aiOnlyFindings;
    private final int nucleiOnlyFindings;
    private final int overlappingFindings;
    private final double accuracy;
    private final List<String> missedByAI;
    private final List<String> missedByNuclei;
    private final List<String> recommendations;
    
    public GapAnalysisResult(int aiOnlyFindings, int nucleiOnlyFindings, int overlappingFindings,
                           double accuracy, List<String> missedByAI, List<String> missedByNuclei,
                           List<String> recommendations) {
        this.aiOnlyFindings = aiOnlyFindings;
        this.nucleiOnlyFindings = nucleiOnlyFindings;
        this.overlappingFindings = overlappingFindings;
        this.accuracy = accuracy;
        this.missedByAI = missedByAI;
        this.missedByNuclei = missedByNuclei;
        this.recommendations = recommendations;
    }
    
    // Getters
    public int getAiOnlyFindings() { return aiOnlyFindings; }
    public int getNucleiOnlyFindings() { return nucleiOnlyFindings; }
    public int getOverlappingFindings() { return overlappingFindings; }
    public double getAccuracy() { return accuracy; }
    public List<String> getMissedByAI() { return missedByAI; }
    public List<String> getMissedByNuclei() { return missedByNuclei; }
    public List<String> getRecommendations() { return recommendations; }
}

// Comprehensive result wrapper
static class ComprehensiveNucleiResult {
    private final String target;
    private final String sessionId;
    private final IntelligenceResult intelligence;
    private final List<String> selectedTemplates;
    private final List<NucleiResult> results;
    private final List<VulnerabilityFinding> findings;
    private final GapAnalysisResult gapAnalysis;
    private final long startTime;
    private final long endTime;
    private final ScanStatistics statistics;
    private final List<String> recommendations;
    
    public ComprehensiveNucleiResult(String target, String sessionId, IntelligenceResult intelligence,
                                   List<String> selectedTemplates, List<NucleiResult> results,
                                   List<VulnerabilityFinding> findings, GapAnalysisResult gapAnalysis,
                                   long startTime, long endTime, ScanStatistics statistics,
                                   List<String> recommendations) {
        this.target = target;
        this.sessionId = sessionId;
        this.intelligence = intelligence;
        this.selectedTemplates = selectedTemplates;
        this.results = results;
        this.findings = findings;
        this.gapAnalysis = gapAnalysis;
        this.startTime = startTime;
        this.endTime = endTime;
        this.statistics = statistics;
        this.recommendations = recommendations;
    }
    
    public int getTotalFindings() {
        return findings.size();
    }
    
    public Duration getScanDuration() {
        return Duration.ofMillis(endTime - startTime);
    }
    
    // Getters
    public String getTarget() { return target; }
    public String getSessionId() { return sessionId; }
    public IntelligenceResult getIntelligence() { return intelligence; }
    public List<String> getSelectedTemplates() { return selectedTemplates; }
    public List<NucleiResult> getResults() { return results; }
    public List<VulnerabilityFinding> getFindings() { return findings; }
    public GapAnalysisResult getGapAnalysis() { return gapAnalysis; }
    public long getStartTime() { return startTime; }
    public long getEndTime() { return endTime; }
    public ScanStatistics getStatistics() { return statistics; }
    public List<String> getRecommendations() { return recommendations; }
}