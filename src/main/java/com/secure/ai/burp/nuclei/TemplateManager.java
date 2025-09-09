package com.secure.ai.burp.nuclei;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.secure.ai.burp.core.ApplicationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Advanced template management for Nuclei integration
 * Handles template discovery, categorization, and context-aware selection
 */
public class TemplateManager {
    private static final Logger logger = LoggerFactory.getLogger(TemplateManager.class);
    
    private final Path templatesPath;
    private final ObjectMapper yamlMapper;
    
    // Template categorization
    private final Map<String, List<String>> templatesByCategory = new HashMap<>();
    private final Map<String, List<String>> templatesByTechnology = new HashMap<>();
    private final Map<String, List<String>> templatesBySeverity = new HashMap<>();
    private final Map<String, TemplateMetadata> templateMetadata = new HashMap<>();
    
    // Technology mappings
    private static final Map<String, List<String>> TECHNOLOGY_MAPPINGS = Map.of(
        "WordPress", List.of("wordpress", "wp-"),
        "Joomla", List.of("joomla"),
        "Drupal", List.of("drupal"),
        "PHP", List.of("php"),
        "Apache", List.of("apache"),
        "Nginx", List.of("nginx"),
        "MySQL", List.of("mysql"),
        "PostgreSQL", List.of("postgresql", "postgres"),
        "MongoDB", List.of("mongodb", "mongo"),
        "Jenkins", List.of("jenkins"),
        "Docker", List.of("docker"),
        "Kubernetes", List.of("kubernetes", "k8s")
    );
    
    public TemplateManager(Path templatesPath) {
        this.templatesPath = templatesPath;
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
    }
    
    public void initialize() throws IOException {
        logger.info("Initializing template manager...");
        
        if (!Files.exists(templatesPath)) {
            throw new IOException("Templates directory not found: " + templatesPath);
        }
        
        // Discover and categorize templates
        discoverTemplates();
        
        logger.info("Template manager initialized: {} templates in {} categories", 
                   templateMetadata.size(), templatesByCategory.size());
    }
    
    /**
     * Select templates based on application context and intelligence
     */
    public List<String> selectContextAwareTemplates(ApplicationContext context, IntelligenceResult intelligence) {
        Set<String> selectedTemplates = new LinkedHashSet<>();
        
        // Add base security templates (always include)
        selectedTemplates.addAll(getBaseSecurityTemplates());
        
        // Add technology-specific templates
        for (String technology : context.getDetectedTechnologies()) {
            selectedTemplates.addAll(getTemplatesForTechnology(technology));
        }
        
        // Add templates based on endpoints
        selectedTemplates.addAll(selectTemplatesForEndpoints(context.getDiscoveredEndpoints()));
        
        // Add templates based on parameters
        selectedTemplates.addAll(selectTemplatesForParameters(context.getParameters()));
        
        // Add templates based on intelligence
        selectedTemplates.addAll(selectTemplatesForIntelligence(intelligence));
        
        // Filter by priority and relevance
        List<String> filteredTemplates = filterAndPrioritizeTemplates(
            new ArrayList<>(selectedTemplates), context, intelligence);
        
        logger.info("Selected {} templates for context-aware scan", filteredTemplates.size());
        return filteredTemplates;
    }
    
    /**
     * Get templates for specific vulnerability type
     */
    public List<String> getTemplatesForVulnerability(String vulnerabilityType) {
        return templatesByCategory.getOrDefault(vulnerabilityType.toLowerCase(), List.of());
    }
    
    /**
     * Get templates for specific technology
     */
    public List<String> getTemplatesForTechnology(String technology) {
        List<String> templates = new ArrayList<>();
        
        // Direct match
        templates.addAll(templatesByTechnology.getOrDefault(technology.toLowerCase(), List.of()));
        
        // Pattern matching
        List<String> patterns = TECHNOLOGY_MAPPINGS.getOrDefault(technology, List.of());
        for (String pattern : patterns) {
            templatesByTechnology.forEach((tech, techTemplates) -> {
                if (tech.contains(pattern)) {
                    templates.addAll(techTemplates);
                }
            });
        }
        
        return templates.stream().distinct().collect(Collectors.toList());
    }
    
    /**
     * Get templates by severity level
     */
    public List<String> getTemplatesBySeverity(List<String> severities) {
        return severities.stream()
            .flatMap(severity -> templatesBySeverity.getOrDefault(severity.toLowerCase(), List.of()).stream())
            .distinct()
            .collect(Collectors.toList());
    }
    
    /**
     * Get recommended templates based on attack surface
     */
    public List<String> getRecommendedTemplates(AttackSurfaceAssessment assessment) {
        List<String> recommended = new ArrayList<>();
        
        // High-risk applications get more comprehensive scanning
        if (assessment.getRiskScore() > 0.7) {
            recommended.addAll(getTemplatesBySeverity(List.of("critical", "high", "medium")));
        } else if (assessment.getRiskScore() > 0.4) {
            recommended.addAll(getTemplatesBySeverity(List.of("high", "medium")));
        } else {
            recommended.addAll(getTemplatesBySeverity(List.of("high")));
        }
        
        return recommended.stream().distinct().collect(Collectors.toList());
    }
    
    private void discoverTemplates() throws IOException {
        try (Stream<Path> paths = Files.walk(templatesPath)) {
            paths.filter(path -> path.toString().endsWith(".yaml"))
                .forEach(this::analyzeTemplate);
        }
    }
    
    private void analyzeTemplate(Path templatePath) {
        try {
            String relativePath = templatesPath.relativize(templatePath).toString();
            JsonNode template = yamlMapper.readTree(templatePath.toFile());
            
            TemplateMetadata metadata = extractTemplateMetadata(template, relativePath);
            templateMetadata.put(relativePath, metadata);
            
            // Categorize template
            categorizeTemplate(relativePath, metadata);
            
        } catch (Exception e) {
            logger.debug("Failed to analyze template: {}", templatePath, e);
        }
    }
    
    private TemplateMetadata extractTemplateMetadata(JsonNode template, String path) {
        JsonNode info = template.path("info");
        
        String id = template.path("id").asText(path);
        String name = info.path("name").asText("");
        String severity = info.path("severity").asText("info");
        String description = info.path("description").asText("");
        List<String> tags = extractTags(info.path("tags"));
        String author = info.path("author").asText("");
        List<String> references = extractReferences(info.path("reference"));
        
        return new TemplateMetadata(id, name, severity, description, tags, author, references, path);
    }
    
    private List<String> extractTags(JsonNode tagsNode) {
        List<String> tags = new ArrayList<>();
        if (tagsNode.isArray()) {
            tagsNode.forEach(tag -> tags.add(tag.asText()));
        } else if (tagsNode.isTextual()) {
            String tagsText = tagsNode.asText();
            if (tagsText.contains(",")) {
                Collections.addAll(tags, tagsText.split(","));
            } else {
                tags.add(tagsText);
            }
        }
        return tags.stream().map(String::trim).collect(Collectors.toList());
    }
    
    private List<String> extractReferences(JsonNode refNode) {
        List<String> references = new ArrayList<>();
        if (refNode.isArray()) {
            refNode.forEach(ref -> references.add(ref.asText()));
        } else if (refNode.isTextual()) {
            references.add(refNode.asText());
        }
        return references;
    }
    
    private void categorizeTemplate(String path, TemplateMetadata metadata) {
        // Categorize by directory structure
        String[] pathParts = path.split("/");
        if (pathParts.length > 0) {
            String category = pathParts[0];
            templatesByCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(path);
        }
        
        // Categorize by tags
        for (String tag : metadata.getTags()) {
            String lowerTag = tag.toLowerCase();
            templatesByCategory.computeIfAbsent(lowerTag, k -> new ArrayList<>()).add(path);
            
            // Technology categorization
            if (isTechnologyTag(lowerTag)) {
                templatesByTechnology.computeIfAbsent(lowerTag, k -> new ArrayList<>()).add(path);
            }
        }
        
        // Categorize by severity
        String severity = metadata.getSeverity().toLowerCase();
        templatesBySeverity.computeIfAbsent(severity, k -> new ArrayList<>()).add(path);
        
        // Special categorizations
        String name = metadata.getName().toLowerCase();
        String desc = metadata.getDescription().toLowerCase();
        
        if (name.contains("xss") || desc.contains("cross-site scripting")) {
            templatesByCategory.computeIfAbsent("xss", k -> new ArrayList<>()).add(path);
        }
        
        if (name.contains("sql") || desc.contains("sql injection")) {
            templatesByCategory.computeIfAbsent("sqli", k -> new ArrayList<>()).add(path);
        }
        
        if (name.contains("rce") || name.contains("command") || desc.contains("remote code execution")) {
            templatesByCategory.computeIfAbsent("rce", k -> new ArrayList<>()).add(path);
        }
    }
    
    private boolean isTechnologyTag(String tag) {
        return TECHNOLOGY_MAPPINGS.keySet().stream()
            .anyMatch(tech -> tech.toLowerCase().contains(tag) || tag.contains(tech.toLowerCase()));
    }
    
    private List<String> getBaseSecurityTemplates() {
        List<String> base = new ArrayList<>();
        
        // Essential security checks
        base.addAll(templatesByCategory.getOrDefault("misconfiguration", List.of()));
        base.addAll(templatesByCategory.getOrDefault("exposure", List.of()));
        base.addAll(templatesByCategory.getOrDefault("default-logins", List.of()));
        
        // Limit to most critical
        return base.stream().limit(20).collect(Collectors.toList());
    }
    
    private List<String> selectTemplatesForEndpoints(List<String> endpoints) {
        Set<String> templates = new HashSet<>();
        
        for (String endpoint : endpoints) {
            String lowerEndpoint = endpoint.toLowerCase();
            
            // Admin endpoints
            if (lowerEndpoint.contains("admin") || lowerEndpoint.contains("wp-admin")) {
                templates.addAll(templatesByCategory.getOrDefault("admin-panel", List.of()));
            }
            
            // API endpoints
            if (lowerEndpoint.contains("api") || lowerEndpoint.contains("/v1/") || lowerEndpoint.contains("/v2/")) {
                templates.addAll(templatesByCategory.getOrDefault("api", List.of()));
            }
            
            // Login endpoints
            if (lowerEndpoint.contains("login") || lowerEndpoint.contains("auth")) {
                templates.addAll(templatesByCategory.getOrDefault("auth-bypass", List.of()));
            }
            
            // Upload endpoints
            if (lowerEndpoint.contains("upload") || lowerEndpoint.contains("file")) {
                templates.addAll(templatesByCategory.getOrDefault("file-upload", List.of()));
            }
        }
        
        return new ArrayList<>(templates);
    }
    
    private List<String> selectTemplatesForParameters(Map<String, String> parameters) {
        Set<String> templates = new HashSet<>();
        
        for (Map.Entry<String, String> param : parameters.entrySet()) {
            String paramName = param.getKey().toLowerCase();
            String paramType = param.getValue().toLowerCase();
            
            // SQL injection candidates
            if (paramType.equals("integer") || paramType.equals("string")) {
                templates.addAll(templatesByCategory.getOrDefault("sqli", List.of()));
            }
            
            // XSS candidates
            if (paramType.equals("string") || paramType.equals("text")) {
                templates.addAll(templatesByCategory.getOrDefault("xss", List.of()));
            }
            
            // File-related parameters
            if (paramName.contains("file") || paramName.contains("upload") || paramName.contains("path")) {
                templates.addAll(templatesByCategory.getOrDefault("lfi", List.of()));
                templates.addAll(templatesByCategory.getOrDefault("path-traversal", List.of()));
            }
            
            // Command injection candidates
            if (paramName.contains("cmd") || paramName.contains("exec") || paramName.contains("system")) {
                templates.addAll(templatesByCategory.getOrDefault("cmdi", List.of()));
            }
        }
        
        return new ArrayList<>(templates);
    }
    
    private List<String> selectTemplatesForIntelligence(IntelligenceResult intelligence) {
        Set<String> templates = new HashSet<>();
        
        // Security headers analysis
        List<String> securityHeaders = intelligence.getSecurityHeaders();
        if (securityHeaders.isEmpty()) {
            templates.addAll(templatesByCategory.getOrDefault("misconfiguration", List.of()));
        }
        
        // Attack surface analysis
        AttackSurfaceAssessment assessment = intelligence.getAttackSurface();
        if (assessment.getRiskScore() > 0.5) {
            templates.addAll(getRecommendedTemplates(assessment));
        }
        
        return new ArrayList<>(templates);
    }
    
    private List<String> filterAndPrioritizeTemplates(List<String> templates, 
                                                    ApplicationContext context, 
                                                    IntelligenceResult intelligence) {
        
        // Score templates by relevance
        Map<String, Double> templateScores = new HashMap<>();
        
        for (String template : templates) {
            TemplateMetadata metadata = templateMetadata.get(template);
            if (metadata != null) {
                double score = calculateTemplateRelevance(metadata, context, intelligence);
                templateScores.put(template, score);
            }
        }
        
        // Sort by score and return top templates
        return templateScores.entrySet().stream()
            .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
            .limit(200) // Reasonable limit for scan performance
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }
    
    private double calculateTemplateRelevance(TemplateMetadata metadata, 
                                            ApplicationContext context, 
                                            IntelligenceResult intelligence) {
        double score = 0.0;
        
        // Severity weight
        switch (metadata.getSeverity().toLowerCase()) {
            case "critical": score += 1.0; break;
            case "high": score += 0.8; break;
            case "medium": score += 0.6; break;
            case "low": score += 0.4; break;
            case "info": score += 0.2; break;
        }
        
        // Technology match
        for (String tech : context.getDetectedTechnologies()) {
            if (metadata.getTags().stream().anyMatch(tag -> 
                tag.toLowerCase().contains(tech.toLowerCase()) || 
                tech.toLowerCase().contains(tag.toLowerCase()))) {
                score += 0.5;
            }
        }
        
        // Risk assessment boost
        double riskScore = intelligence.getAttackSurface().getRiskScore();
        score *= (1.0 + riskScore);
        
        return score;
    }
    
    public Map<String, List<String>> getTemplatesByCategory() {
        return new HashMap<>(templatesByCategory);
    }
    
    public Map<String, TemplateMetadata> getTemplateMetadata() {
        return new HashMap<>(templateMetadata);
    }
    
    public int getTotalTemplates() {
        return templateMetadata.size();
    }
    
    public static class TemplateMetadata {
        private final String id;
        private final String name;
        private final String severity;
        private final String description;
        private final List<String> tags;
        private final String author;
        private final List<String> references;
        private final String path;
        
        public TemplateMetadata(String id, String name, String severity, String description,
                              List<String> tags, String author, List<String> references, String path) {
            this.id = id;
            this.name = name;
            this.severity = severity;
            this.description = description;
            this.tags = tags;
            this.author = author;
            this.references = references;
            this.path = path;
        }
        
        // Getters
        public String getId() { return id; }
        public String getName() { return name; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public List<String> getTags() { return tags; }
        public String getAuthor() { return author; }
        public List<String> getReferences() { return references; }
        public String getPath() { return path; }
    }
}