package com.secure.ai.burp.testing.poc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

// Main POC result containing all phase results and overall assessment
@JsonIgnoreProperties(ignoreUnknown = true)
class ComprehensivePOCResult {
    @JsonProperty("overall_status")
    private String overallStatus;
    
    @JsonProperty("success_rate")
    private double successRate;
    
    @JsonProperty("phase_results")
    private List<POCPhaseResult> phaseResults;
    
    @JsonProperty("all_test_results")
    private List<String> allTestResults;
    
    @JsonProperty("total_execution_time")
    private long totalExecutionTime;
    
    @JsonProperty("summary")
    private Map<String, Object> summary;
    
    @JsonProperty("performance_metrics")
    private Map<String, Object> performanceMetrics;
    
    @JsonProperty("completion_timestamp")
    private LocalDateTime completionTimestamp;
    
    public ComprehensivePOCResult() {}
    
    public ComprehensivePOCResult(String overallStatus, double successRate, List<POCPhaseResult> phaseResults,
                                 List<String> allTestResults, long totalExecutionTime, Map<String, Object> summary,
                                 Map<String, Object> performanceMetrics, LocalDateTime completionTimestamp) {
        this.overallStatus = overallStatus;
        this.successRate = successRate;
        this.phaseResults = phaseResults != null ? new ArrayList<>(phaseResults) : new ArrayList<>();
        this.allTestResults = allTestResults != null ? new ArrayList<>(allTestResults) : new ArrayList<>();
        this.totalExecutionTime = totalExecutionTime;
        this.summary = summary != null ? new HashMap<>(summary) : new HashMap<>();
        this.performanceMetrics = performanceMetrics != null ? new HashMap<>(performanceMetrics) : new HashMap<>();
        this.completionTimestamp = completionTimestamp;
    }
    
    // Getters and setters
    public String getOverallStatus() { return overallStatus; }
    public void setOverallStatus(String overallStatus) { this.overallStatus = overallStatus; }
    
    public double getSuccessRate() { return successRate; }
    public void setSuccessRate(double successRate) { this.successRate = successRate; }
    
    public List<POCPhaseResult> getPhaseResults() { return phaseResults; }
    public void setPhaseResults(List<POCPhaseResult> phaseResults) { this.phaseResults = phaseResults; }
    
    public List<String> getAllTestResults() { return allTestResults; }
    public void setAllTestResults(List<String> allTestResults) { this.allTestResults = allTestResults; }
    
    public long getTotalExecutionTime() { return totalExecutionTime; }
    public void setTotalExecutionTime(long totalExecutionTime) { this.totalExecutionTime = totalExecutionTime; }
    
    public Map<String, Object> getSummary() { return summary; }
    public void setSummary(Map<String, Object> summary) { this.summary = summary; }
    
    public Map<String, Object> getPerformanceMetrics() { return performanceMetrics; }
    public void setPerformanceMetrics(Map<String, Object> performanceMetrics) { this.performanceMetrics = performanceMetrics; }
    
    public LocalDateTime getCompletionTimestamp() { return completionTimestamp; }
    public void setCompletionTimestamp(LocalDateTime completionTimestamp) { this.completionTimestamp = completionTimestamp; }
}

// Individual POC phase result
@JsonIgnoreProperties(ignoreUnknown = true)
class POCPhaseResult {
    @JsonProperty("phase_name")
    private String phaseName;
    
    @JsonProperty("success")
    private boolean success;
    
    @JsonProperty("test_results")
    private List<String> testResults;
    
    @JsonProperty("execution_time")
    private long executionTime;
    
    @JsonProperty("phase_metrics")
    private Map<String, Object> phaseMetrics;
    
    @JsonProperty("error_details")
    private String errorDetails;
    
    public POCPhaseResult() {}
    
    public POCPhaseResult(String phaseName, boolean success, List<String> testResults, long executionTime) {
        this.phaseName = phaseName;
        this.success = success;
        this.testResults = testResults != null ? new ArrayList<>(testResults) : new ArrayList<>();
        this.executionTime = executionTime;
        this.phaseMetrics = new HashMap<>();
    }
    
    public POCPhaseResult(String phaseName, boolean success, List<String> testResults, long executionTime,
                         String errorDetails) {
        this(phaseName, success, testResults, executionTime);
        this.errorDetails = errorDetails;
    }
    
    // Getters and setters
    public String getPhaseName() { return phaseName; }
    public void setPhaseName(String phaseName) { this.phaseName = phaseName; }
    
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    
    public List<String> getTestResults() { return testResults; }
    public void setTestResults(List<String> testResults) { this.testResults = testResults; }
    
    public long getExecutionTime() { return executionTime; }
    public void setExecutionTime(long executionTime) { this.executionTime = executionTime; }
    
    public Map<String, Object> getPhaseMetrics() { return phaseMetrics; }
    public void setPhaseMetrics(Map<String, Object> phaseMetrics) { this.phaseMetrics = phaseMetrics; }
    
    public String getErrorDetails() { return errorDetails; }
    public void setErrorDetails(String errorDetails) { this.errorDetails = errorDetails; }
}

// POC test result for individual tests
class POCTestResult {
    private String testName;
    private boolean passed;
    private String description;
    private long executionTimeMs;
    private Map<String, Object> testData;
    private String errorMessage;
    private LocalDateTime timestamp;
    
    public POCTestResult(String testName, boolean passed, String description, long executionTimeMs) {
        this.testName = testName;
        this.passed = passed;
        this.description = description;
        this.executionTimeMs = executionTimeMs;
        this.testData = new HashMap<>();
        this.timestamp = LocalDateTime.now();
    }
    
    // Getters and setters
    public String getTestName() { return testName; }
    public void setTestName(String testName) { this.testName = testName; }
    
    public boolean isPassed() { return passed; }
    public void setPassed(boolean passed) { this.passed = passed; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public long getExecutionTimeMs() { return executionTimeMs; }
    public void setExecutionTimeMs(long executionTimeMs) { this.executionTimeMs = executionTimeMs; }
    
    public Map<String, Object> getTestData() { return testData; }
    public void setTestData(Map<String, Object> testData) { this.testData = testData; }
    
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}

// POC metrics collection
class POCMetrics {
    private final AtomicLong totalTests = new AtomicLong(0);
    private final AtomicLong passedTests = new AtomicLong(0);
    private final AtomicLong failedTests = new AtomicLong(0);
    private final AtomicLong totalExecutionTime = new AtomicLong(0);
    private final AtomicInteger concurrentRequests = new AtomicInteger(0);
    private final AtomicLong memoryUsed = new AtomicLong(0);
    
    private final Map<String, AtomicLong> phaseExecutionTimes = new HashMap<>();
    private final Map<String, AtomicInteger> errorCounts = new HashMap<>();
    private final List<Double> performanceSamples = Collections.synchronizedList(new ArrayList<>());
    
    public void recordTest(String testName, boolean passed, long executionTime) {
        totalTests.incrementAndGet();
        if (passed) {
            passedTests.incrementAndGet();
        } else {
            failedTests.incrementAndGet();
        }
        totalExecutionTime.addAndGet(executionTime);
        performanceSamples.add((double) executionTime);
    }
    
    public void recordPhaseExecution(String phaseName, long executionTime) {
        phaseExecutionTimes.computeIfAbsent(phaseName, k -> new AtomicLong(0)).addAndGet(executionTime);
    }
    
    public void recordError(String errorType) {
        errorCounts.computeIfAbsent(errorType, k -> new AtomicInteger(0)).incrementAndGet();
    }
    
    public void updateConcurrentRequests(int count) {
        concurrentRequests.set(count);
    }
    
    public void updateMemoryUsage(long bytes) {
        memoryUsed.set(bytes);
    }
    
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Basic metrics
        metrics.put("total_tests", totalTests.get());
        metrics.put("passed_tests", passedTests.get());
        metrics.put("failed_tests", failedTests.get());
        metrics.put("success_rate", totalTests.get() > 0 ? (double) passedTests.get() / totalTests.get() : 0.0);
        metrics.put("total_execution_time_ms", totalExecutionTime.get());
        metrics.put("average_execution_time_ms", totalTests.get() > 0 ? (double) totalExecutionTime.get() / totalTests.get() : 0.0);
        
        // Performance metrics
        if (!performanceSamples.isEmpty()) {
            metrics.put("min_execution_time_ms", performanceSamples.stream().mapToDouble(d -> d).min().orElse(0.0));
            metrics.put("max_execution_time_ms", performanceSamples.stream().mapToDouble(d -> d).max().orElse(0.0));
            metrics.put("median_execution_time_ms", calculateMedian(performanceSamples));
        }
        
        // System metrics
        metrics.put("concurrent_requests", concurrentRequests.get());
        metrics.put("memory_used_bytes", memoryUsed.get());
        metrics.put("memory_used_mb", memoryUsed.get() / (1024 * 1024));
        
        // Phase metrics
        Map<String, Long> phaseMetrics = new HashMap<>();
        phaseExecutionTimes.forEach((phase, time) -> phaseMetrics.put(phase, time.get()));
        metrics.put("phase_execution_times", phaseMetrics);
        
        // Error metrics
        Map<String, Integer> errorMetrics = new HashMap<>();
        errorCounts.forEach((error, count) -> errorMetrics.put(error, count.get()));
        metrics.put("error_counts", errorMetrics);
        
        return metrics;
    }
    
    private double calculateMedian(List<Double> values) {
        List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int size = sorted.size();
        if (size % 2 == 0) {
            return (sorted.get(size / 2 - 1) + sorted.get(size / 2)) / 2.0;
        } else {
            return sorted.get(size / 2);
        }
    }
    
    public void reset() {
        totalTests.set(0);
        passedTests.set(0);
        failedTests.set(0);
        totalExecutionTime.set(0);
        concurrentRequests.set(0);
        memoryUsed.set(0);
        phaseExecutionTimes.clear();
        errorCounts.clear();
        performanceSamples.clear();
    }
}

// POC Configuration
class POCConfiguration {
    private int pocThreads = 4;
    private long phaseTimeoutMs = 300000; // 5 minutes per phase
    private boolean enableDetailedLogging = true;
    private boolean enablePerformanceProfiling = true;
    private boolean enableMemoryMonitoring = true;
    private int maxConcurrentTests = 20;
    private int testRetryAttempts = 2;
    private long testTimeoutMs = 30000; // 30 seconds per test
    
    // Test configuration
    private boolean enableMLModelTests = true;
    private boolean enableAnomalyDetectionTests = true;
    private boolean enableNucleiIntegrationTests = true;
    private boolean enablePayloadGenerationTests = true;
    private boolean enableLearningSystemTests = true;
    private boolean enablePerformanceTests = true;
    private boolean enableIntegrationTests = true;
    
    // Performance test parameters
    private int performanceTestDuration = 60; // seconds
    private int maxRequestsPerSecond = 100;
    private int concurrentRequestCount = 20;
    private long memoryLimitMB = 512;
    
    // Getters and setters
    public int getPocThreads() { return pocThreads; }
    public void setPocThreads(int pocThreads) { this.pocThreads = pocThreads; }
    
    public long getPhaseTimeoutMs() { return phaseTimeoutMs; }
    public void setPhaseTimeoutMs(long phaseTimeoutMs) { this.phaseTimeoutMs = phaseTimeoutMs; }
    
    public boolean isEnableDetailedLogging() { return enableDetailedLogging; }
    public void setEnableDetailedLogging(boolean enableDetailedLogging) { this.enableDetailedLogging = enableDetailedLogging; }
    
    public boolean isEnablePerformanceProfiling() { return enablePerformanceProfiling; }
    public void setEnablePerformanceProfiling(boolean enablePerformanceProfiling) { this.enablePerformanceProfiling = enablePerformanceProfiling; }
    
    public boolean isEnableMemoryMonitoring() { return enableMemoryMonitoring; }
    public void setEnableMemoryMonitoring(boolean enableMemoryMonitoring) { this.enableMemoryMonitoring = enableMemoryMonitoring; }
    
    public int getMaxConcurrentTests() { return maxConcurrentTests; }
    public void setMaxConcurrentTests(int maxConcurrentTests) { this.maxConcurrentTests = maxConcurrentTests; }
    
    public int getTestRetryAttempts() { return testRetryAttempts; }
    public void setTestRetryAttempts(int testRetryAttempts) { this.testRetryAttempts = testRetryAttempts; }
    
    public long getTestTimeoutMs() { return testTimeoutMs; }
    public void setTestTimeoutMs(long testTimeoutMs) { this.testTimeoutMs = testTimeoutMs; }
    
    public boolean isEnableMLModelTests() { return enableMLModelTests; }
    public void setEnableMLModelTests(boolean enableMLModelTests) { this.enableMLModelTests = enableMLModelTests; }
    
    public boolean isEnableAnomalyDetectionTests() { return enableAnomalyDetectionTests; }
    public void setEnableAnomalyDetectionTests(boolean enableAnomalyDetectionTests) { this.enableAnomalyDetectionTests = enableAnomalyDetectionTests; }
    
    public boolean isEnableNucleiIntegrationTests() { return enableNucleiIntegrationTests; }
    public void setEnableNucleiIntegrationTests(boolean enableNucleiIntegrationTests) { this.enableNucleiIntegrationTests = enableNucleiIntegrationTests; }
    
    public boolean isEnablePayloadGenerationTests() { return enablePayloadGenerationTests; }
    public void setEnablePayloadGenerationTests(boolean enablePayloadGenerationTests) { this.enablePayloadGenerationTests = enablePayloadGenerationTests; }
    
    public boolean isEnableLearningSystemTests() { return enableLearningSystemTests; }
    public void setEnableLearningSystemTests(boolean enableLearningSystemTests) { this.enableLearningSystemTests = enableLearningSystemTests; }
    
    public boolean isEnablePerformanceTests() { return enablePerformanceTests; }
    public void setEnablePerformanceTests(boolean enablePerformanceTests) { this.enablePerformanceTests = enablePerformanceTests; }
    
    public boolean isEnableIntegrationTests() { return enableIntegrationTests; }
    public void setEnableIntegrationTests(boolean enableIntegrationTests) { this.enableIntegrationTests = enableIntegrationTests; }
    
    public int getPerformanceTestDuration() { return performanceTestDuration; }
    public void setPerformanceTestDuration(int performanceTestDuration) { this.performanceTestDuration = performanceTestDuration; }
    
    public int getMaxRequestsPerSecond() { return maxRequestsPerSecond; }
    public void setMaxRequestsPerSecond(int maxRequestsPerSecond) { this.maxRequestsPerSecond = maxRequestsPerSecond; }
    
    public int getConcurrentRequestCount() { return concurrentRequestCount; }
    public void setConcurrentRequestCount(int concurrentRequestCount) { this.concurrentRequestCount = concurrentRequestCount; }
    
    public long getMemoryLimitMB() { return memoryLimitMB; }
    public void setMemoryLimitMB(long memoryLimitMB) { this.memoryLimitMB = memoryLimitMB; }
}

// Comprehensive Security Report
@JsonIgnoreProperties(ignoreUnknown = true)
class ComprehensiveSecurityReport {
    @JsonProperty("report_id")
    private String reportId;
    
    @JsonProperty("generation_timestamp")
    private LocalDateTime generationTimestamp;
    
    @JsonProperty("executive_summary")
    private ExecutiveSummary executiveSummary;
    
    @JsonProperty("technical_findings")
    private List<TechnicalFinding> technicalFindings;
    
    @JsonProperty("security_recommendations")
    private List<SecurityRecommendation> securityRecommendations;
    
    @JsonProperty("risk_assessment")
    private RiskAssessmentReport riskAssessment;
    
    @JsonProperty("performance_analysis")
    private PerformanceAnalysis performanceAnalysis;
    
    @JsonProperty("compliance_assessment")
    private ComplianceAssessment complianceAssessment;
    
    @JsonProperty("section_count")
    private int sectionCount;
    
    @JsonProperty("recommendation_count")
    private int recommendationCount;
    
    @JsonProperty("risk_level")
    private String riskLevel;
    
    public ComprehensiveSecurityReport() {
        this.reportId = "SEC-RPT-" + System.currentTimeMillis();
        this.generationTimestamp = LocalDateTime.now();
        this.technicalFindings = new ArrayList<>();
        this.securityRecommendations = new ArrayList<>();
        calculateMetrics();
    }
    
    private void calculateMetrics() {
        this.sectionCount = 6; // Executive, Technical, Recommendations, Risk, Performance, Compliance
        this.recommendationCount = securityRecommendations.size();
        this.riskLevel = riskAssessment != null ? riskAssessment.getOverallRiskLevel() : "UNKNOWN";
    }
    
    // Getters and setters
    public String getReportId() { return reportId; }
    public void setReportId(String reportId) { this.reportId = reportId; }
    
    public LocalDateTime getGenerationTimestamp() { return generationTimestamp; }
    public void setGenerationTimestamp(LocalDateTime generationTimestamp) { this.generationTimestamp = generationTimestamp; }
    
    public ExecutiveSummary getExecutiveSummary() { return executiveSummary; }
    public void setExecutiveSummary(ExecutiveSummary executiveSummary) { this.executiveSummary = executiveSummary; }
    
    public List<TechnicalFinding> getTechnicalFindings() { return technicalFindings; }
    public void setTechnicalFindings(List<TechnicalFinding> technicalFindings) { this.technicalFindings = technicalFindings; }
    
    public List<SecurityRecommendation> getSecurityRecommendations() { return securityRecommendations; }
    public void setSecurityRecommendations(List<SecurityRecommendation> securityRecommendations) { 
        this.securityRecommendations = securityRecommendations;
        calculateMetrics();
    }
    
    public RiskAssessmentReport getRiskAssessment() { return riskAssessment; }
    public void setRiskAssessment(RiskAssessmentReport riskAssessment) { 
        this.riskAssessment = riskAssessment;
        calculateMetrics();
    }
    
    public PerformanceAnalysis getPerformanceAnalysis() { return performanceAnalysis; }
    public void setPerformanceAnalysis(PerformanceAnalysis performanceAnalysis) { this.performanceAnalysis = performanceAnalysis; }
    
    public ComplianceAssessment getComplianceAssessment() { return complianceAssessment; }
    public void setComplianceAssessment(ComplianceAssessment complianceAssessment) { this.complianceAssessment = complianceAssessment; }
    
    public int getSectionCount() { return sectionCount; }
    public int getRecommendationCount() { return recommendationCount; }
    public String getRiskLevel() { return riskLevel; }
}

// Executive Summary
@JsonIgnoreProperties(ignoreUnknown = true)
class ExecutiveSummary {
    @JsonProperty("key_findings")
    private List<String> keyFindings;
    
    @JsonProperty("business_impact")
    private String businessImpact;
    
    @JsonProperty("overall_security_posture")
    private String overallSecurityPosture;
    
    @JsonProperty("critical_issues_count")
    private int criticalIssuesCount;
    
    @JsonProperty("high_priority_recommendations")
    private List<String> highPriorityRecommendations;
    
    @JsonProperty("investment_recommendations")
    private List<String> investmentRecommendations;
    
    public ExecutiveSummary() {
        this.keyFindings = new ArrayList<>();
        this.highPriorityRecommendations = new ArrayList<>();
        this.investmentRecommendations = new ArrayList<>();
    }
    
    public int getKeyFindingsCount() { return keyFindings.size(); }
    
    // Getters and setters
    public List<String> getKeyFindings() { return keyFindings; }
    public void setKeyFindings(List<String> keyFindings) { this.keyFindings = keyFindings; }
    
    public String getBusinessImpact() { return businessImpact; }
    public void setBusinessImpact(String businessImpact) { this.businessImpact = businessImpact; }
    
    public String getOverallSecurityPosture() { return overallSecurityPosture; }
    public void setOverallSecurityPosture(String overallSecurityPosture) { this.overallSecurityPosture = overallSecurityPosture; }
    
    public int getCriticalIssuesCount() { return criticalIssuesCount; }
    public void setCriticalIssuesCount(int criticalIssuesCount) { this.criticalIssuesCount = criticalIssuesCount; }
    
    public List<String> getHighPriorityRecommendations() { return highPriorityRecommendations; }
    public void setHighPriorityRecommendations(List<String> highPriorityRecommendations) { this.highPriorityRecommendations = highPriorityRecommendations; }
    
    public List<String> getInvestmentRecommendations() { return investmentRecommendations; }
    public void setInvestmentRecommendations(List<String> investmentRecommendations) { this.investmentRecommendations = investmentRecommendations; }
}

// Technical Finding
@JsonIgnoreProperties(ignoreUnknown = true)
class TechnicalFinding {
    @JsonProperty("finding_id")
    private String findingId;
    
    @JsonProperty("title")
    private String title;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("severity")
    private String severity;
    
    @JsonProperty("confidence")
    private double confidence;
    
    @JsonProperty("affected_components")
    private List<String> affectedComponents;
    
    @JsonProperty("evidence")
    private Map<String, Object> evidence;
    
    @JsonProperty("remediation_steps")
    private List<String> remediationSteps;
    
    public TechnicalFinding() {
        this.findingId = "FIND-" + System.currentTimeMillis();
        this.affectedComponents = new ArrayList<>();
        this.evidence = new HashMap<>();
        this.remediationSteps = new ArrayList<>();
    }
    
    public TechnicalFinding(String title, String description, String severity, double confidence) {
        this();
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.confidence = confidence;
    }
    
    // Getters and setters
    public String getFindingId() { return findingId; }
    public void setFindingId(String findingId) { this.findingId = findingId; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public List<String> getAffectedComponents() { return affectedComponents; }
    public void setAffectedComponents(List<String> affectedComponents) { this.affectedComponents = affectedComponents; }
    
    public Map<String, Object> getEvidence() { return evidence; }
    public void setEvidence(Map<String, Object> evidence) { this.evidence = evidence; }
    
    public List<String> getRemediationSteps() { return remediationSteps; }
    public void setRemediationSteps(List<String> remediationSteps) { this.remediationSteps = remediationSteps; }
}

// Security Recommendation
@JsonIgnoreProperties(ignoreUnknown = true)
class SecurityRecommendation {
    @JsonProperty("recommendation_id")
    private String recommendationId;
    
    @JsonProperty("category")
    private String category;
    
    @JsonProperty("priority")
    private String priority;
    
    @JsonProperty("title")
    private String title;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("implementation_effort")
    private String implementationEffort;
    
    @JsonProperty("expected_impact")
    private String expectedImpact;
    
    @JsonProperty("implementation_steps")
    private List<String> implementationSteps;
    
    @JsonProperty("success_metrics")
    private List<String> successMetrics;
    
    public SecurityRecommendation() {
        this.recommendationId = "REC-" + System.currentTimeMillis();
        this.implementationSteps = new ArrayList<>();
        this.successMetrics = new ArrayList<>();
    }
    
    public SecurityRecommendation(String category, String priority, String title, String description) {
        this();
        this.category = category;
        this.priority = priority;
        this.title = title;
        this.description = description;
    }
    
    // Getters and setters
    public String getRecommendationId() { return recommendationId; }
    public void setRecommendationId(String recommendationId) { this.recommendationId = recommendationId; }
    
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getImplementationEffort() { return implementationEffort; }
    public void setImplementationEffort(String implementationEffort) { this.implementationEffort = implementationEffort; }
    
    public String getExpectedImpact() { return expectedImpact; }
    public void setExpectedImpact(String expectedImpact) { this.expectedImpact = expectedImpact; }
    
    public List<String> getImplementationSteps() { return implementationSteps; }
    public void setImplementationSteps(List<String> implementationSteps) { this.implementationSteps = implementationSteps; }
    
    public List<String> getSuccessMetrics() { return successMetrics; }
    public void setSuccessMetrics(List<String> successMetrics) { this.successMetrics = successMetrics; }
}

// Risk Assessment Report
@JsonIgnoreProperties(ignoreUnknown = true)
class RiskAssessmentReport {
    @JsonProperty("overall_risk_level")
    private String overallRiskLevel;
    
    @JsonProperty("risk_score")
    private double riskScore;
    
    @JsonProperty("risk_factors")
    private Map<String, String> riskFactors;
    
    @JsonProperty("vulnerability_distribution")
    private Map<String, Integer> vulnerabilityDistribution;
    
    @JsonProperty("threat_landscape")
    private Map<String, Object> threatLandscape;
    
    @JsonProperty("business_impact_analysis")
    private Map<String, String> businessImpactAnalysis;
    
    public RiskAssessmentReport() {
        this.riskFactors = new HashMap<>();
        this.vulnerabilityDistribution = new HashMap<>();
        this.threatLandscape = new HashMap<>();
        this.businessImpactAnalysis = new HashMap<>();
    }
    
    // Getters and setters
    public String getOverallRiskLevel() { return overallRiskLevel; }
    public void setOverallRiskLevel(String overallRiskLevel) { this.overallRiskLevel = overallRiskLevel; }
    
    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }
    
    public Map<String, String> getRiskFactors() { return riskFactors; }
    public void setRiskFactors(Map<String, String> riskFactors) { this.riskFactors = riskFactors; }
    
    public Map<String, Integer> getVulnerabilityDistribution() { return vulnerabilityDistribution; }
    public void setVulnerabilityDistribution(Map<String, Integer> vulnerabilityDistribution) { this.vulnerabilityDistribution = vulnerabilityDistribution; }
    
    public Map<String, Object> getThreatLandscape() { return threatLandscape; }
    public void setThreatLandscape(Map<String, Object> threatLandscape) { this.threatLandscape = threatLandscape; }
    
    public Map<String, String> getBusinessImpactAnalysis() { return businessImpactAnalysis; }
    public void setBusinessImpactAnalysis(Map<String, String> businessImpactAnalysis) { this.businessImpactAnalysis = businessImpactAnalysis; }
}

// Performance Analysis
@JsonIgnoreProperties(ignoreUnknown = true)
class PerformanceAnalysis {
    @JsonProperty("system_performance_metrics")
    private Map<String, Object> systemPerformanceMetrics;
    
    @JsonProperty("scalability_assessment")
    private Map<String, String> scalabilityAssessment;
    
    @JsonProperty("resource_utilization")
    private Map<String, Object> resourceUtilization;
    
    @JsonProperty("performance_recommendations")
    private List<String> performanceRecommendations;
    
    public PerformanceAnalysis() {
        this.systemPerformanceMetrics = new HashMap<>();
        this.scalabilityAssessment = new HashMap<>();
        this.resourceUtilization = new HashMap<>();
        this.performanceRecommendations = new ArrayList<>();
    }
    
    // Getters and setters
    public Map<String, Object> getSystemPerformanceMetrics() { return systemPerformanceMetrics; }
    public void setSystemPerformanceMetrics(Map<String, Object> systemPerformanceMetrics) { this.systemPerformanceMetrics = systemPerformanceMetrics; }
    
    public Map<String, String> getScalabilityAssessment() { return scalabilityAssessment; }
    public void setScalabilityAssessment(Map<String, String> scalabilityAssessment) { this.scalabilityAssessment = scalabilityAssessment; }
    
    public Map<String, Object> getResourceUtilization() { return resourceUtilization; }
    public void setResourceUtilization(Map<String, Object> resourceUtilization) { this.resourceUtilization = resourceUtilization; }
    
    public List<String> getPerformanceRecommendations() { return performanceRecommendations; }
    public void setPerformanceRecommendations(List<String> performanceRecommendations) { this.performanceRecommendations = performanceRecommendations; }
}

// Compliance Assessment
@JsonIgnoreProperties(ignoreUnknown = true)
class ComplianceAssessment {
    @JsonProperty("owasp_top_10_compliance")
    private Map<String, String> owaspTop10Compliance;
    
    @JsonProperty("security_frameworks")
    private Map<String, String> securityFrameworks;
    
    @JsonProperty("regulatory_compliance")
    private Map<String, String> regulatoryCompliance;
    
    @JsonProperty("compliance_gaps")
    private List<String> complianceGaps;
    
    @JsonProperty("remediation_roadmap")
    private List<String> remediationRoadmap;
    
    public ComplianceAssessment() {
        this.owaspTop10Compliance = new HashMap<>();
        this.securityFrameworks = new HashMap<>();
        this.regulatoryCompliance = new HashMap<>();
        this.complianceGaps = new ArrayList<>();
        this.remediationRoadmap = new ArrayList<>();
    }
    
    // Getters and setters
    public Map<String, String> getOwaspTop10Compliance() { return owaspTop10Compliance; }
    public void setOwaspTop10Compliance(Map<String, String> owaspTop10Compliance) { this.owaspTop10Compliance = owaspTop10Compliance; }
    
    public Map<String, String> getSecurityFrameworks() { return securityFrameworks; }
    public void setSecurityFrameworks(Map<String, String> securityFrameworks) { this.securityFrameworks = securityFrameworks; }
    
    public Map<String, String> getRegulatoryCompliance() { return regulatoryCompliance; }
    public void setRegulatoryCompliance(Map<String, String> regulatoryCompliance) { this.regulatoryCompliance = regulatoryCompliance; }
    
    public List<String> getComplianceGaps() { return complianceGaps; }
    public void setComplianceGaps(List<String> complianceGaps) { this.complianceGaps = complianceGaps; }
    
    public List<String> getRemediationRoadmap() { return remediationRoadmap; }
    public void setRemediationRoadmap(List<String> remediationRoadmap) { this.remediationRoadmap = remediationRoadmap; }
}