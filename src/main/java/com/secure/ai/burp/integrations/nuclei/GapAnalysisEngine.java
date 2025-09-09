package com.secure.ai.burp.integrations.nuclei;

import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.models.ml.AdvancedModelManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static com.secure.ai.burp.integrations.nuclei.NucleiDataClasses.*;

/**
 * Advanced gap analysis engine comparing AI predictions with Nuclei findings
 * Identifies missed vulnerabilities and improves detection accuracy
 */
class GapAnalysisEngine {
    private static final Logger logger = LoggerFactory.getLogger(GapAnalysisEngine.class);
    
    private final AdvancedModelManager modelManager;
    
    // Gap analysis configuration
    private static final double SIMILARITY_THRESHOLD = 0.75;
    private static final Map<String, String> VULNERABILITY_MAPPINGS = Map.of(
        "xss", "Cross-Site Scripting",
        "sqli", "SQL Injection", 
        "rce", "Remote Code Execution",
        "lfi", "Local File Inclusion",
        "xxe", "XML External Entity",
        "csrf", "Cross-Site Request Forgery"
    );
    
    public GapAnalysisEngine(AdvancedModelManager modelManager) {
        this.modelManager = modelManager;
    }
    
    /**
     * Perform comprehensive gap analysis between AI and Nuclei findings
     */
    public GapAnalysisResult performGapAnalysis(String target, ApplicationContext context, 
                                              ProcessedResults nucleiResults, 
                                              AdvancedModelManager modelManager) {
        try {
            logger.info("Performing gap analysis for: {}", target);
            
            // Generate AI predictions for the same target
            List<VulnerabilityPrediction> aiPredictions = generateAIPredictions(target, context, modelManager);
            
            // Extract Nuclei findings
            List<VulnerabilityFinding> nucleiFindings = nucleiResults.getFindings();
            
            // Perform matching analysis
            MatchingAnalysis matching = performMatchingAnalysis(aiPredictions, nucleiFindings);
            
            // Identify gaps
            List<VulnerabilityPrediction> missedByNuclei = identifyMissedByNuclei(
                aiPredictions, matching.getMatchedAI());
            
            List<VulnerabilityFinding> missedByAI = identifyMissedByAI(
                nucleiFindings, matching.getMatchedNuclei());
            
            // Calculate accuracy metrics
            AccuracyMetrics accuracy = calculateAccuracyMetrics(matching, aiPredictions, nucleiFindings);
            
            // Generate insights and recommendations
            List<String> recommendations = generateGapAnalysisRecommendations(
                missedByAI, missedByNuclei, accuracy);
            
            // Learn from the gaps
            learnFromGapAnalysis(missedByAI, missedByNuclei, context, modelManager);
            
            GapAnalysisResult result = new GapAnalysisResult(
                missedByNuclei.size(),
                missedByAI.size(),
                matching.getOverlappingCount(),
                accuracy.getOverallAccuracy(),
                missedByAI.stream().map(f -> f.getName()).collect(Collectors.toList()),
                missedByNuclei.stream().map(p -> p.getDescription()).collect(Collectors.toList()),
                recommendations
            );
            
            logger.info("Gap analysis complete - AI only: {}, Nuclei only: {}, Overlapping: {}, Accuracy: {:.2f}%",
                       result.getAiOnlyFindings(), result.getNucleiOnlyFindings(), 
                       result.getOverlappingFindings(), result.getAccuracy() * 100);
            
            return result;
            
        } catch (Exception e) {
            logger.error("Gap analysis failed", e);
            return new GapAnalysisResult(0, 0, 0, 0.0, List.of(), List.of(), 
                List.of("Gap analysis failed: " + e.getMessage()));
        }
    }
    
    private List<VulnerabilityPrediction> generateAIPredictions(String target, ApplicationContext context, 
                                                               AdvancedModelManager modelManager) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        
        try {
            // Generate predictions for common vulnerability types
            String[] vulnTypes = {"xss", "sqli", "rce", "lfi", "xxe", "csrf"};
            
            for (String vulnType : vulnTypes) {
                // Create context-aware test payloads
                List<String> testPayloads = generateTestPayloads(vulnType, context);
                
                for (String payload : testPayloads) {
                    // Get AI prediction
                    AdvancedModelManager.PredictionResult prediction = getPredictionForType(
                        vulnType, payload, context, modelManager);
                    
                    if (prediction.getScore() > 0.5) { // Threshold for positive prediction
                        predictions.add(new VulnerabilityPrediction(
                            vulnType,
                            VULNERABILITY_MAPPINGS.getOrDefault(vulnType, vulnType),
                            payload,
                            target,
                            prediction.getScore(),
                            prediction.getClassification(),
                            prediction.getDetails()
                        ));
                    }
                }
            }
            
            // Additional context-based predictions
            predictions.addAll(generateContextBasedPredictions(target, context, modelManager));
            
            logger.debug("Generated {} AI predictions", predictions.size());
            
        } catch (Exception e) {
            logger.error("Failed to generate AI predictions", e);
        }
        
        return predictions;
    }
    
    private List<String> generateTestPayloads(String vulnType, ApplicationContext context) {
        List<String> payloads = new ArrayList<>();
        
        switch (vulnType) {
            case "xss":
                payloads.add("<script>alert('test')</script>");
                payloads.add("'><script>alert(1)</script>");
                payloads.add("javascript:alert(1)");
                
                // Technology-specific payloads
                if (context.getDetectedTechnologies().contains("React")) {
                    payloads.add("{{constructor.constructor('alert(1)')()}}");
                }
                break;
                
            case "sqli":
                payloads.add("' OR '1'='1");
                payloads.add("1' UNION SELECT NULL--");
                payloads.add("'; DROP TABLE test--");
                
                // Database-specific payloads
                for (String tech : context.getDetectedTechnologies()) {
                    if (tech.contains("MySQL")) {
                        payloads.add("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--");
                    } else if (tech.contains("PostgreSQL")) {
                        payloads.add("1'; SELECT version()--");
                    }
                }
                break;
                
            case "rce":
                payloads.add("; cat /etc/passwd");
                payloads.add("$(whoami)");
                payloads.add("`id`");
                break;
                
            case "lfi":
                payloads.add("../../../etc/passwd");
                payloads.add("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts");
                break;
                
            case "xxe":
                payloads.add("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>");
                break;
                
            case "csrf":
                payloads.add("<form action='/admin/delete' method='post'><input type='submit'></form>");
                break;
        }
        
        return payloads;
    }
    
    private List<VulnerabilityPrediction> generateContextBasedPredictions(String target, ApplicationContext context, 
                                                                         AdvancedModelManager modelManager) {
        List<VulnerabilityPrediction> predictions = new ArrayList<>();
        
        try {
            // Analyze endpoints for potential vulnerabilities
            for (String endpoint : context.getDiscoveredEndpoints()) {
                // Admin panel vulnerabilities
                if (endpoint.toLowerCase().contains("admin")) {
                    predictions.add(new VulnerabilityPrediction(
                        "admin-access",
                        "Unauthorized Admin Access",
                        "Admin panel discovery",
                        target + endpoint,
                        0.7,
                        "medium",
                        Map.of("endpoint", endpoint, "context", "admin_panel")
                    ));
                }
                
                // API vulnerabilities
                if (endpoint.toLowerCase().contains("api")) {
                    predictions.add(new VulnerabilityPrediction(
                        "api-exposure",
                        "API Exposure",
                        "Potentially exposed API endpoint",
                        target + endpoint,
                        0.6,
                        "medium",
                        Map.of("endpoint", endpoint, "context", "api")
                    ));
                }
                
                // File upload endpoints
                if (endpoint.toLowerCase().contains("upload") || endpoint.toLowerCase().contains("file")) {
                    predictions.add(new VulnerabilityPrediction(
                        "file-upload",
                        "File Upload Vulnerability",
                        "Unrestricted file upload",
                        target + endpoint,
                        0.8,
                        "high",
                        Map.of("endpoint", endpoint, "context", "file_upload")
                    ));
                }
            }
            
            // Technology-specific predictions
            for (String tech : context.getDetectedTechnologies()) {
                if (tech.contains("WordPress")) {
                    predictions.add(new VulnerabilityPrediction(
                        "wordpress-vuln",
                        "WordPress Vulnerability",
                        "Common WordPress security issues",
                        target,
                        0.6,
                        "medium",
                        Map.of("technology", tech, "context", "cms")
                    ));
                }
                
                if (tech.contains("PHP") && tech.contains("5.")) {
                    predictions.add(new VulnerabilityPrediction(
                        "php-version",
                        "Outdated PHP Version",
                        "Using outdated PHP version with known vulnerabilities",
                        target,
                        0.8,
                        "high",
                        Map.of("technology", tech, "context", "outdated_software")
                    ));
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to generate context-based predictions", e);
        }
        
        return predictions;
    }
    
    private AdvancedModelManager.PredictionResult getPredictionForType(String vulnType, String payload, 
                                                                     ApplicationContext context, 
                                                                     AdvancedModelManager modelManager) {
        Map<String, Object> contextMap = new HashMap<>();
        contextMap.put("technologies", context.getDetectedTechnologies());
        contextMap.put("parameters", context.getParameters());
        contextMap.put("endpoints", context.getDiscoveredEndpoints());
        
        switch (vulnType) {
            case "xss":
                return modelManager.predictXSS(payload, contextMap);
            case "sqli":
                return modelManager.predictSQLi(payload, contextMap);
            default:
                // For other types, use a generic prediction with pattern matching
                return createGenericPrediction(vulnType, payload, context);
        }
    }
    
    private AdvancedModelManager.PredictionResult createGenericPrediction(String vulnType, String payload, 
                                                                        ApplicationContext context) {
        double score = 0.5; // Default moderate confidence
        String classification = "medium";
        Map<String, Object> details = new HashMap<>();
        
        // Simple pattern-based scoring
        if (vulnType.equals("rce") && (payload.contains(";") || payload.contains("$") || payload.contains("`"))) {
            score = 0.8;
            classification = "high";
        }
        
        if (vulnType.equals("lfi") && payload.contains("../")) {
            score = 0.7;
            classification = "medium";
        }
        
        if (vulnType.equals("xxe") && payload.contains("ENTITY")) {
            score = 0.7;
            classification = "medium";
        }
        
        details.put("pattern_based", true);
        details.put("payload", payload);
        
        return new AdvancedModelManager.PredictionResult(score, classification, details);
    }
    
    private MatchingAnalysis performMatchingAnalysis(List<VulnerabilityPrediction> aiPredictions, 
                                                   List<VulnerabilityFinding> nucleiFindings) {
        Set<VulnerabilityPrediction> matchedAI = new HashSet<>();
        Set<VulnerabilityFinding> matchedNuclei = new HashSet<>();
        List<Match> matches = new ArrayList<>();
        
        // Compare each AI prediction with each Nuclei finding
        for (VulnerabilityPrediction prediction : aiPredictions) {
            for (VulnerabilityFinding finding : nucleiFindings) {
                double similarity = calculateSimilarity(prediction, finding);
                
                if (similarity > SIMILARITY_THRESHOLD) {
                    matches.add(new Match(prediction, finding, similarity));
                    matchedAI.add(prediction);
                    matchedNuclei.add(finding);
                }
            }
        }
        
        return new MatchingAnalysis(matchedAI, matchedNuclei, matches);
    }
    
    private double calculateSimilarity(VulnerabilityPrediction prediction, VulnerabilityFinding finding) {
        double similarity = 0.0;
        
        // Type similarity
        if (prediction.getType().equalsIgnoreCase(finding.getType()) ||
            prediction.getVulnerabilityName().toLowerCase().contains(finding.getType().toLowerCase()) ||
            finding.getType().toLowerCase().contains(prediction.getType().toLowerCase())) {
            similarity += 0.4;
        }
        
        // Location similarity
        if (prediction.getLocation().contains(extractLocationFromFinding(finding))) {
            similarity += 0.3;
        }
        
        // Severity similarity
        if (prediction.getClassification().equalsIgnoreCase(finding.getSeverity())) {
            similarity += 0.2;
        }
        
        // Confidence boost for exact matches
        if (prediction.getType().equalsIgnoreCase(finding.getType()) && 
            prediction.getLocation().equals(finding.getLocation())) {
            similarity += 0.1;
        }
        
        return similarity;
    }
    
    private String extractLocationFromFinding(VulnerabilityFinding finding) {
        String location = finding.getLocation();
        
        // Extract base path from URL
        if (location.startsWith("http")) {
            try {
                java.net.URL url = new java.net.URL(location);
                return url.getPath();
            } catch (Exception e) {
                return location;
            }
        }
        
        return location;
    }
    
    private List<VulnerabilityPrediction> identifyMissedByNuclei(List<VulnerabilityPrediction> aiPredictions, 
                                                               Set<VulnerabilityPrediction> matchedAI) {
        return aiPredictions.stream()
            .filter(prediction -> !matchedAI.contains(prediction))
            .filter(prediction -> prediction.getConfidence() > 0.6) // High confidence only
            .collect(Collectors.toList());
    }
    
    private List<VulnerabilityFinding> identifyMissedByAI(List<VulnerabilityFinding> nucleiFindings, 
                                                        Set<VulnerabilityFinding> matchedNuclei) {
        return nucleiFindings.stream()
            .filter(finding -> !matchedNuclei.contains(finding))
            .collect(Collectors.toList());
    }
    
    private AccuracyMetrics calculateAccuracyMetrics(MatchingAnalysis matching, 
                                                   List<VulnerabilityPrediction> aiPredictions,
                                                   List<VulnerabilityFinding> nucleiFindings) {
        int truePositives = matching.getOverlappingCount();
        int falsePositives = aiPredictions.size() - truePositives;
        int falseNegatives = nucleiFindings.size() - truePositives;
        
        // Assume true negatives are much larger (common in security testing)
        int trueNegatives = Math.max(100, truePositives * 10); // Estimate
        
        double precision = truePositives > 0 ? (double) truePositives / (truePositives + falsePositives) : 0.0;
        double recall = truePositives > 0 ? (double) truePositives / (truePositives + falseNegatives) : 0.0;
        double f1Score = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;
        double accuracy = (double) (truePositives + trueNegatives) / 
                         (truePositives + falsePositives + falseNegatives + trueNegatives);
        
        return new AccuracyMetrics(precision, recall, f1Score, accuracy);
    }
    
    private List<String> generateGapAnalysisRecommendations(List<VulnerabilityFinding> missedByAI,
                                                          List<VulnerabilityPrediction> missedByNuclei,
                                                          AccuracyMetrics accuracy) {
        List<String> recommendations = new ArrayList<>();
        
        // AI model improvement recommendations
        if (!missedByAI.isEmpty()) {
            recommendations.add(String.format("Update AI models to detect %d vulnerability types missed by current models", 
                missedByAI.size()));
            
            Map<String, Long> missedTypes = missedByAI.stream()
                .collect(Collectors.groupingBy(VulnerabilityFinding::getType, Collectors.counting()));
            
            missedTypes.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(3)
                .forEach(entry -> recommendations.add(
                    String.format("Focus on improving %s detection (missed %d instances)", 
                        entry.getKey(), entry.getValue())));
        }
        
        // Nuclei template recommendations
        if (!missedByNuclei.isEmpty()) {
            recommendations.add(String.format("Consider adding custom Nuclei templates for %d AI-identified patterns", 
                missedByNuclei.size()));
            
            Map<String, Long> missedAITypes = missedByNuclei.stream()
                .collect(Collectors.groupingBy(VulnerabilityPrediction::getType, Collectors.counting()));
            
            missedAITypes.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(3)
                .forEach(entry -> recommendations.add(
                    String.format("Create Nuclei templates for %s patterns (AI found %d instances)", 
                        entry.getKey(), entry.getValue())));
        }
        
        // Accuracy improvement recommendations
        if (accuracy.getOverallAccuracy() < 0.8) {
            recommendations.add("Overall detection accuracy is below 80% - consider retraining AI models with recent data");
        }
        
        if (accuracy.getPrecision() < 0.7) {
            recommendations.add("High false positive rate detected - refine AI model thresholds");
        }
        
        if (accuracy.getRecall() < 0.7) {
            recommendations.add("Low recall indicates missed vulnerabilities - expand training dataset");
        }
        
        // Integration recommendations
        recommendations.add("Implement feedback loop to continuously improve detection accuracy");
        recommendations.add("Consider hybrid approach combining AI predictions with Nuclei scanning");
        
        return recommendations;
    }
    
    private void learnFromGapAnalysis(List<VulnerabilityFinding> missedByAI, 
                                    List<VulnerabilityPrediction> missedByNuclei,
                                    ApplicationContext context, 
                                    AdvancedModelManager modelManager) {
        try {
            // Learn from vulnerabilities missed by AI
            for (VulnerabilityFinding finding : missedByAI) {
                // Create learning pattern from Nuclei finding
                String pattern = finding.getLocation() + " | " + finding.getType() + " | " + finding.getDescription();
                modelManager.learnFromAttackPattern(pattern, finding.getType(), 0.8);
            }
            
            // Learn from false positives (AI predictions not confirmed by Nuclei)
            for (VulnerabilityPrediction prediction : missedByNuclei) {
                // Reduce confidence in this type of prediction
                String pattern = prediction.getLocation() + " | " + prediction.getType();
                modelManager.learnFromAttackPattern(pattern, prediction.getType(), 0.3);
            }
            
            logger.info("Gap analysis learning completed: {} missed by AI, {} missed by Nuclei", 
                       missedByAI.size(), missedByNuclei.size());
            
        } catch (Exception e) {
            logger.error("Failed to learn from gap analysis", e);
        }
    }
    
    // Supporting classes
    private static class VulnerabilityPrediction {
        private final String type;
        private final String vulnerabilityName;
        private final String description;
        private final String location;
        private final double confidence;
        private final String classification;
        private final Map<String, Object> details;
        
        public VulnerabilityPrediction(String type, String vulnerabilityName, String description,
                                     String location, double confidence, String classification,
                                     Map<String, Object> details) {
            this.type = type;
            this.vulnerabilityName = vulnerabilityName;
            this.description = description;
            this.location = location;
            this.confidence = confidence;
            this.classification = classification;
            this.details = details;
        }
        
        // Getters
        public String getType() { return type; }
        public String getVulnerabilityName() { return vulnerabilityName; }
        public String getDescription() { return description; }
        public String getLocation() { return location; }
        public double getConfidence() { return confidence; }
        public String getClassification() { return classification; }
        public Map<String, Object> getDetails() { return details; }
    }
    
    private static class MatchingAnalysis {
        private final Set<VulnerabilityPrediction> matchedAI;
        private final Set<VulnerabilityFinding> matchedNuclei;
        private final List<Match> matches;
        
        public MatchingAnalysis(Set<VulnerabilityPrediction> matchedAI, 
                              Set<VulnerabilityFinding> matchedNuclei,
                              List<Match> matches) {
            this.matchedAI = matchedAI;
            this.matchedNuclei = matchedNuclei;
            this.matches = matches;
        }
        
        public Set<VulnerabilityPrediction> getMatchedAI() { return matchedAI; }
        public Set<VulnerabilityFinding> getMatchedNuclei() { return matchedNuclei; }
        public List<Match> getMatches() { return matches; }
        public int getOverlappingCount() { return matches.size(); }
    }
    
    private static class Match {
        private final VulnerabilityPrediction prediction;
        private final VulnerabilityFinding finding;
        private final double similarity;
        
        public Match(VulnerabilityPrediction prediction, VulnerabilityFinding finding, double similarity) {
            this.prediction = prediction;
            this.finding = finding;
            this.similarity = similarity;
        }
        
        public VulnerabilityPrediction getPrediction() { return prediction; }
        public VulnerabilityFinding getFinding() { return finding; }
        public double getSimilarity() { return similarity; }
    }
    
    private static class AccuracyMetrics {
        private final double precision;
        private final double recall;
        private final double f1Score;
        private final double overallAccuracy;
        
        public AccuracyMetrics(double precision, double recall, double f1Score, double overallAccuracy) {
            this.precision = precision;
            this.recall = recall;
            this.f1Score = f1Score;
            this.overallAccuracy = overallAccuracy;
        }
        
        public double getPrecision() { return precision; }
        public double getRecall() { return recall; }
        public double getF1Score() { return f1Score; }
        public double getOverallAccuracy() { return overallAccuracy; }
    }
}