package com.secure.ai.burp.integrations.nuclei;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.models.ml.AdvancedModelManager;
import org.apache.commons.exec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Comprehensive Nuclei integration with auto-installation, template management,
 * context-aware scanning, and AI-powered gap analysis
 */
class ComprehensiveNucleiIntegration {
    private static final Logger logger = LoggerFactory.getLogger(ComprehensiveNucleiIntegration.class);
    
    // Nuclei configuration
    private static final String NUCLEI_VERSION = "v3.0.4";
    private static final String NUCLEI_DOWNLOAD_BASE = "https://github.com/projectdiscovery/nuclei/releases/download/";
    private static final String TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip";
    
    // File paths
    private final Path nucleiPath;
    private final Path templatesPath;
    private final Path configPath;
    private final Path outputPath;
    
    // Components
    private final ObjectMapper objectMapper;
    private final ExecutorService scanExecutor;
    private final AdvancedModelManager modelManager;
    private final TemplateManager templateManager;
    private final ScanResultProcessor resultProcessor;
    private final GapAnalysisEngine gapAnalysisEngine;
    
    // State tracking
    private boolean nucleiAvailable = false;
    private boolean templatesDownloaded = false;
    private final Map<String, NucleiScanSession> activeSessions = new ConcurrentHashMap<>();
    private final Map<String, List<NucleiResult>> scanHistory = new ConcurrentHashMap<>();
    
    public ComprehensiveNucleiIntegration(AdvancedModelManager modelManager) {
        this.modelManager = modelManager;
        this.objectMapper = new ObjectMapper();
        this.scanExecutor = Executors.newFixedThreadPool(4);
        
        // Initialize paths
        String homeDir = System.getProperty("user.home");
        Path nucleiDir = Paths.get(homeDir, ".nuclei");
        this.nucleiPath = nucleiDir.resolve("nuclei");
        this.templatesPath = nucleiDir.resolve("templates");
        this.configPath = nucleiDir.resolve("config");
        this.outputPath = nucleiDir.resolve("output");
        
        // Initialize components
        this.templateManager = new TemplateManager(templatesPath);
        this.resultProcessor = new ScanResultProcessor(objectMapper);
        this.gapAnalysisEngine = new GapAnalysisEngine(modelManager);
        
        // Initialize Nuclei
        initializeNuclei();
    }
    
    /**
     * Perform comprehensive context-aware Nuclei scan
     */
    public CompletableFuture<ComprehensiveNucleiResult> performComprehensiveScan(
            String target, ApplicationContext context, NucleiScanOptions options) {
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.info("Starting comprehensive Nuclei scan for: {}", target);
                
                // Create scan session
                String sessionId = generateSessionId();
                NucleiScanSession session = new NucleiScanSession(sessionId, target, context, options);
                activeSessions.put(sessionId, session);
                
                // Phase 1: Intelligence gathering
                session.updatePhase("intelligence_gathering");
                IntelligenceResult intelligence = gatherIntelligence(target, context);
                
                // Phase 2: Template selection
                session.updatePhase("template_selection");
                List<String> selectedTemplates = templateManager.selectContextAwareTemplates(context, intelligence);
                session.setSelectedTemplates(selectedTemplates);
                
                // Phase 3: Parallel scanning
                session.updatePhase("scanning");
                List<NucleiResult> scanResults = performParallelScanning(target, selectedTemplates, options);
                
                // Phase 4: Result processing
                session.updatePhase("processing");
                ProcessedResults processed = resultProcessor.processResults(scanResults, context);
                
                // Phase 5: Gap analysis
                session.updatePhase("gap_analysis");
                GapAnalysisResult gapAnalysis = gapAnalysisEngine.performGapAnalysis(
                    target, context, processed, modelManager);
                
                // Phase 6: Report generation
                session.updatePhase("reporting");
                ComprehensiveNucleiResult finalResult = generateComprehensiveResult(
                    session, intelligence, processed, gapAnalysis);
                
                // Store results
                scanHistory.computeIfAbsent(target, k -> new ArrayList<>()).addAll(scanResults);
                session.updatePhase("completed");
                
                logger.info("Comprehensive Nuclei scan completed for: {} ({} findings)", 
                           target, finalResult.getTotalFindings());
                
                return finalResult;
                
            } catch (Exception e) {
                logger.error("Comprehensive Nuclei scan failed for: {}", target, e);
                throw new RuntimeException("Nuclei scan failed: " + e.getMessage(), e);
            } finally {
                activeSessions.remove(target);
            }
        }, scanExecutor);
    }
    
    /**
     * Perform targeted vulnerability-specific scan
     */
    public CompletableFuture<List<NucleiResult>> performTargetedScan(
            String target, String vulnerabilityType, ApplicationContext context) {
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                List<String> templates = templateManager.getTemplatesForVulnerability(vulnerabilityType);
                NucleiScanOptions options = new NucleiScanOptions.Builder()
                    .withTimeout(30)
                    .withConcurrency(10)
                    .withSeverityFilter(List.of("low", "medium", "high", "critical"))
                    .build();
                
                return performParallelScanning(target, templates, options);
                
            } catch (Exception e) {
                logger.error("Targeted Nuclei scan failed", e);
                return List.of();
            }
        }, scanExecutor);
    }
    
    /**
     * Continuous monitoring scan
     */
    public CompletableFuture<Void> startContinuousMonitoring(
            List<String> targets, ApplicationContext context, Duration interval) {
        
        return CompletableFuture.runAsync(() -> {
            logger.info("Starting continuous monitoring for {} targets", targets.size());
            
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    for (String target : targets) {
                        NucleiScanOptions options = new NucleiScanOptions.Builder()
                            .withTimeout(60)
                            .withConcurrency(5)
                            .withMonitoringMode(true)
                            .build();
                            
                        performComprehensiveScan(target, context, options)
                            .whenComplete((result, throwable) -> {
                                if (throwable != null) {
                                    logger.warn("Monitoring scan failed for {}: {}", target, throwable.getMessage());
                                } else {
                                    processMonitoringResults(target, result);
                                }
                            });
                    }
                    
                    Thread.sleep(interval.toMillis());
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in continuous monitoring", e);
                }
            }
            
            logger.info("Continuous monitoring stopped");
        }, scanExecutor);
    }
    
    private void initializeNuclei() {
        try {
            // Create directories
            Files.createDirectories(nucleiPath.getParent());
            Files.createDirectories(templatesPath);
            Files.createDirectories(configPath);
            Files.createDirectories(outputPath);
            
            // Check if Nuclei is already installed
            if (isNucleiInstalled()) {
                nucleiAvailable = true;
                logger.info("Nuclei found at: {}", nucleiPath);
            } else {
                logger.info("Nuclei not found, attempting installation...");
                installNuclei();
            }
            
            // Download/update templates
            if (!templatesDownloaded || shouldUpdateTemplates()) {
                downloadTemplates();
            }
            
            // Initialize template manager
            templateManager.initialize();
            
            logger.info("Nuclei integration initialized successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize Nuclei integration", e);
            nucleiAvailable = false;
        }
    }
    
    private boolean isNucleiInstalled() {
        try {
            if (!Files.exists(nucleiPath)) return false;
            
            ProcessBuilder pb = new ProcessBuilder(nucleiPath.toString(), "-version");
            Process process = pb.start();
            int exitCode = process.waitFor(10, TimeUnit.SECONDS) ? process.exitValue() : -1;
            
            return exitCode == 0;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    private void installNuclei() throws Exception {
        logger.info("Installing Nuclei {}...", NUCLEI_VERSION);
        
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        
        String platform = determinePlatform(os, arch);
        String downloadUrl = NUCLEI_DOWNLOAD_BASE + NUCLEI_VERSION + "/nuclei_" + NUCLEI_VERSION.substring(1) + "_" + platform + ".zip";
        
        logger.info("Downloading Nuclei from: {}", downloadUrl);
        
        // Download Nuclei
        Path tempFile = downloadFile(downloadUrl);
        
        // Extract Nuclei
        extractNuclei(tempFile, nucleiPath.getParent());
        
        // Make executable on Unix-like systems
        if (!os.contains("windows")) {
            Files.setPosixFilePermissions(nucleiPath, 
                Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                       java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                       java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
        }
        
        // Verify installation
        if (isNucleiInstalled()) {
            nucleiAvailable = true;
            logger.info("Nuclei installed successfully");
        } else {
            throw new RuntimeException("Nuclei installation verification failed");
        }
        
        // Clean up
        Files.deleteIfExists(tempFile);
    }
    
    private void downloadTemplates() throws Exception {
        logger.info("Downloading Nuclei templates...");
        
        // Download templates archive
        Path tempFile = downloadFile(TEMPLATES_REPO);
        
        // Extract templates
        extractTemplates(tempFile, templatesPath);
        
        templatesDownloaded = true;
        logger.info("Nuclei templates downloaded successfully");
        
        // Clean up
        Files.deleteIfExists(tempFile);
    }
    
    private String determinePlatform(String os, String arch) {
        String platform = "";
        
        if (os.contains("windows")) {
            platform = "windows";
        } else if (os.contains("mac") || os.contains("darwin")) {
            platform = "macOS";
        } else if (os.contains("linux")) {
            platform = "linux";
        } else {
            platform = "linux"; // Default fallback
        }
        
        if (arch.contains("amd64") || arch.contains("x86_64")) {
            platform += "_amd64";
        } else if (arch.contains("arm64") || arch.contains("aarch64")) {
            platform += "_arm64";
        } else {
            platform += "_386"; // Default fallback
        }
        
        return platform;
    }
    
    private Path downloadFile(String url) throws Exception {
        Path tempFile = Files.createTempFile("nuclei_download", ".zip");
        
        try (InputStream in = new URL(url).openStream()) {
            Files.copy(in, tempFile, StandardCopyOption.REPLACE_EXISTING);
        }
        
        return tempFile;
    }
    
    private void extractNuclei(Path zipFile, Path destDir) throws Exception {
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals("nuclei") || entry.getName().equals("nuclei.exe")) {
                    Path nucleiFile = destDir.resolve("nuclei" + (entry.getName().endsWith(".exe") ? ".exe" : ""));
                    Files.copy(zis, nucleiFile, StandardCopyOption.REPLACE_EXISTING);
                    break;
                }
                zis.closeEntry();
            }
        }
    }
    
    private void extractTemplates(Path zipFile, Path destDir) throws Exception {
        // Clear existing templates
        if (Files.exists(destDir)) {
            Files.walk(destDir)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
        }
        Files.createDirectories(destDir);
        
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.isDirectory() && entry.getName().endsWith(".yaml")) {
                    // Remove the top-level directory from the path
                    String[] pathParts = entry.getName().split("/");
                    if (pathParts.length > 1) {
                        String relativePath = String.join("/", Arrays.copyOfRange(pathParts, 1, pathParts.length));
                        Path templateFile = destDir.resolve(relativePath);
                        
                        Files.createDirectories(templateFile.getParent());
                        Files.copy(zis, templateFile, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
                zis.closeEntry();
            }
        }
    }
    
    private boolean shouldUpdateTemplates() {
        try {
            Path lastUpdateFile = templatesPath.resolve(".last_update");
            if (!Files.exists(lastUpdateFile)) return true;
            
            long lastUpdate = Long.parseLong(Files.readString(lastUpdateFile).trim());
            long daysSinceUpdate = (System.currentTimeMillis() - lastUpdate) / (24 * 60 * 60 * 1000);
            
            return daysSinceUpdate > 7; // Update weekly
            
        } catch (Exception e) {
            return true; // Update on error
        }
    }
    
    private IntelligenceResult gatherIntelligence(String target, ApplicationContext context) {
        logger.debug("Gathering intelligence for: {}", target);
        
        return new IntelligenceResult(
            target,
            context.getDetectedTechnologies(),
            context.getDiscoveredEndpoints(),
            context.getParameters(),
            extractDomainInfo(target),
            identifySecurityHeaders(context),
            assessAttackSurface(context)
        );
    }
    
    private List<NucleiResult> performParallelScanning(String target, List<String> templates, NucleiScanOptions options) {
        if (!nucleiAvailable) {
            logger.warn("Nuclei not available, skipping scan");
            return List.of();
        }
        
        List<NucleiResult> allResults = new ArrayList<>();
        
        // Group templates by category for parallel execution
        Map<String, List<String>> templateGroups = groupTemplatesByCategory(templates);
        
        List<CompletableFuture<List<NucleiResult>>> futures = templateGroups.entrySet().stream()
            .map(entry -> CompletableFuture.supplyAsync(() -> {
                try {
                    return executeNucleiScan(target, entry.getValue(), options);
                } catch (Exception e) {
                    logger.error("Scan failed for template group: {}", entry.getKey(), e);
                    return List.of();
                }
            }, scanExecutor))
            .collect(Collectors.toList());
        
        // Wait for all scans to complete
        for (CompletableFuture<List<NucleiResult>> future : futures) {
            try {
                allResults.addAll(future.get(options.getTimeout() + 30, TimeUnit.SECONDS));
            } catch (Exception e) {
                logger.error("Failed to get scan results", e);
            }
        }
        
        return allResults;
    }
    
    private List<NucleiResult> executeNucleiScan(String target, List<String> templates, NucleiScanOptions options) throws Exception {
        // Create temporary template list file
        Path tempTemplateFile = Files.createTempFile("nuclei_templates", ".txt");
        Files.write(tempTemplateFile, templates.stream()
            .map(t -> templatesPath.resolve(t).toString())
            .collect(Collectors.toList()));
        
        // Create output file
        Path outputFile = outputPath.resolve("scan_" + System.currentTimeMillis() + ".json");
        
        try {
            // Build Nuclei command
            List<String> command = new ArrayList<>();
            command.add(nucleiPath.toString());
            command.add("-target");
            command.add(target);
            command.add("-list");
            command.add(tempTemplateFile.toString());
            command.add("-json");
            command.add("-output");
            command.add(outputFile.toString());
            command.add("-timeout");
            command.add(String.valueOf(options.getTimeout()));
            command.add("-concurrency");
            command.add(String.valueOf(options.getConcurrency()));
            
            if (!options.getSeverityFilter().isEmpty()) {
                command.add("-severity");
                command.add(String.join(",", options.getSeverityFilter()));
            }
            
            if (options.isVerbose()) {
                command.add("-verbose");
            }
            
            // Execute command
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.environment().put("HOME", System.getProperty("user.home"));
            
            Process process = pb.start();
            
            // Capture output
            String stdout = captureOutput(process.getInputStream());
            String stderr = captureOutput(process.getErrorStream());
            
            boolean finished = process.waitFor(options.getTimeout() + 10, TimeUnit.SECONDS);
            
            if (!finished) {
                process.destroyForcibly();
                throw new RuntimeException("Nuclei scan timed out");
            }
            
            int exitCode = process.exitValue();
            if (exitCode != 0 && !stderr.isEmpty()) {
                logger.warn("Nuclei scan completed with warnings: {}", stderr);
            }
            
            // Parse results
            List<NucleiResult> results = parseNucleiResults(outputFile);
            
            logger.debug("Nuclei scan completed: {} results", results.size());
            
            return results;
            
        } finally {
            // Cleanup temporary files
            Files.deleteIfExists(tempTemplateFile);
        }
    }
    
    private List<NucleiResult> parseNucleiResults(Path outputFile) throws Exception {
        List<NucleiResult> results = new ArrayList<>();
        
        if (!Files.exists(outputFile)) {
            return results;
        }
        
        try (BufferedReader reader = Files.newBufferedReader(outputFile)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                
                try {
                    JsonNode json = objectMapper.readTree(line);
                    NucleiResult result = parseNucleiResult(json);
                    results.add(result);
                } catch (Exception e) {
                    logger.warn("Failed to parse Nuclei result line: {}", line, e);
                }
            }
        }
        
        return results;
    }
    
    private NucleiResult parseNucleiResult(JsonNode json) {
        return new NucleiResult(
            json.path("template-id").asText(),
            json.path("info").path("name").asText(),
            json.path("info").path("severity").asText(),
            json.path("info").path("description").asText(),
            json.path("info").path("tags").asText(),
            json.path("matched-at").asText(),
            json.path("extracted-results").isArray() ? 
                extractArrayAsStrings(json.path("extracted-results")) : List.of(),
            json.path("matcher-name").asText(),
            json.path("type").asText(),
            json.path("host").asText(),
            System.currentTimeMillis()
        );
    }
    
    private List<String> extractArrayAsStrings(JsonNode arrayNode) {
        List<String> result = new ArrayList<>();
        if (arrayNode.isArray()) {
            arrayNode.forEach(node -> result.add(node.asText()));
        }
        return result;
    }
    
    private Map<String, List<String>> groupTemplatesByCategory(List<String> templates) {
        Map<String, List<String>> groups = new HashMap<>();
        
        for (String template : templates) {
            String category = extractCategory(template);
            groups.computeIfAbsent(category, k -> new ArrayList<>()).add(template);
        }
        
        return groups;
    }
    
    private String extractCategory(String template) {
        // Extract category from template path
        String[] parts = template.split("/");
        return parts.length > 1 ? parts[0] : "miscellaneous";
    }
    
    private String captureOutput(InputStream inputStream) throws IOException {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        return output.toString();
    }
    
    private ComprehensiveNucleiResult generateComprehensiveResult(
            NucleiScanSession session, IntelligenceResult intelligence, 
            ProcessedResults processed, GapAnalysisResult gapAnalysis) {
        
        return new ComprehensiveNucleiResult(
            session.getTarget(),
            session.getSessionId(),
            intelligence,
            session.getSelectedTemplates(),
            processed.getResults(),
            processed.getFindings(),
            gapAnalysis,
            session.getStartTime(),
            System.currentTimeMillis(),
            processed.getStatistics(),
            generateRecommendations(processed, gapAnalysis)
        );
    }
    
    private String generateSessionId() {
        return "nuclei_" + System.currentTimeMillis() + "_" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    private DomainInfo extractDomainInfo(String target) {
        // Simplified domain information extraction
        return new DomainInfo(target, List.of(), List.of(), Map.of());
    }
    
    private List<String> identifySecurityHeaders(ApplicationContext context) {
        // Extract security headers from context
        return List.of("Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection");
    }
    
    private AttackSurfaceAssessment assessAttackSurface(ApplicationContext context) {
        return new AttackSurfaceAssessment(
            context.getDiscoveredEndpoints().size(),
            context.getParameters().size(),
            context.getDetectedTechnologies().size(),
            calculateRiskScore(context)
        );
    }
    
    private double calculateRiskScore(ApplicationContext context) {
        double score = 0.0;
        
        // Technology-based risk
        for (String tech : context.getDetectedTechnologies()) {
            if (tech.contains("WordPress") || tech.contains("Joomla")) score += 0.3;
            if (tech.contains("PHP") && tech.contains("5.")) score += 0.2;
            if (tech.contains("Apache") && tech.contains("2.2")) score += 0.2;
        }
        
        // Endpoint-based risk
        score += Math.min(context.getDiscoveredEndpoints().size() * 0.05, 0.3);
        
        // Parameter-based risk
        score += Math.min(context.getParameters().size() * 0.03, 0.2);
        
        return Math.min(score, 1.0);
    }
    
    private List<String> generateRecommendations(ProcessedResults processed, GapAnalysisResult gapAnalysis) {
        List<String> recommendations = new ArrayList<>();
        
        // Add recommendations based on findings
        processed.getFindings().forEach(finding -> {
            switch (finding.getSeverity().toLowerCase()) {
                case "critical":
                    recommendations.add("URGENT: Address critical " + finding.getType() + " vulnerability immediately");
                    break;
                case "high":
                    recommendations.add("HIGH PRIORITY: Fix " + finding.getType() + " vulnerability within 24 hours");
                    break;
                case "medium":
                    recommendations.add("Schedule remediation for " + finding.getType() + " vulnerability within 1 week");
                    break;
            }
        });
        
        // Add gap analysis recommendations
        if (gapAnalysis.getAiOnlyFindings() > 0) {
            recommendations.add("Review AI-identified vulnerabilities that Nuclei missed");
        }
        
        if (gapAnalysis.getNucleiOnlyFindings() > 0) {
            recommendations.add("Update AI models to detect vulnerabilities found by Nuclei");
        }
        
        return recommendations;
    }
    
    private void processMonitoringResults(String target, ComprehensiveNucleiResult result) {
        // Process continuous monitoring results
        logger.info("Monitoring result for {}: {} findings", target, result.getTotalFindings());
        
        // Check for new vulnerabilities
        List<NucleiResult> previousResults = scanHistory.get(target);
        if (previousResults != null) {
            List<NucleiResult> newFindings = result.getResults().stream()
                .filter(r -> !previousResults.contains(r))
                .collect(Collectors.toList());
                
            if (!newFindings.isEmpty()) {
                logger.warn("NEW VULNERABILITIES DETECTED for {}: {}", target, newFindings.size());
                // Here you could trigger alerts, notifications, etc.
            }
        }
    }
    
    public boolean isNucleiAvailable() {
        return nucleiAvailable;
    }
    
    public Map<String, NucleiScanSession> getActiveSessions() {
        return new HashMap<>(activeSessions);
    }
    
    public void shutdown() {
        logger.info("Shutting down Nuclei integration...");
        
        // Cancel active scans
        activeSessions.values().forEach(session -> session.cancel());
        activeSessions.clear();
        
        // Shutdown executor
        scanExecutor.shutdown();
        try {
            if (!scanExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                scanExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            scanExecutor.shutdownNow();
        }
        
        logger.info("Nuclei integration shutdown complete");
    }
}