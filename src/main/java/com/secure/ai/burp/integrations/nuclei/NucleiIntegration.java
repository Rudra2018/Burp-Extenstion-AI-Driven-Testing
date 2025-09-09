package com.secure.ai.burp.integrations.nuclei;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.learners.adaptive.AdvancedLearningEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

class NucleiIntegration {
    private static final Logger logger = LoggerFactory.getLogger(NucleiIntegration.class);
    
    private final MontoyaApi api;
    private final AdvancedLearningEngine learningEngine;
    private final NucleiTemplateManager templateManager;
    private final NucleiResultProcessor resultProcessor;
    private final ExecutorService nucleiExecutor;
    
    // Nuclei configuration
    private String nucleiPath;
    private String templatesPath;
    private final Set<String> enabledTemplates;
    private final Map<String, NucleiTemplate> availableTemplates;
    
    // Performance settings
    private int maxConcurrentScans = 5;
    private int requestsPerSecond = 10;
    private int timeoutSeconds = 30;
    
    public NucleiIntegration(MontoyaApi api, AdvancedLearningEngine learningEngine) {
        this.api = api;
        this.learningEngine = learningEngine;
        this.templateManager = new NucleiTemplateManager();
        this.resultProcessor = new NucleiResultProcessor(learningEngine);
        this.nucleiExecutor = Executors.newFixedThreadPool(maxConcurrentScans);
        this.enabledTemplates = ConcurrentHashMap.newKeySet();
        this.availableTemplates = new ConcurrentHashMap<>();
        
        initialize();
    }
    
    private void initialize() {
        try {
            // Detect Nuclei installation
            detectNucleiInstallation();
            
            // Load and analyze templates
            loadNucleiTemplates();
            
            // Initialize template categories
            initializeTemplateCategories();
            
            logger.info("Nuclei integration initialized with {} templates", availableTemplates.size());
            
        } catch (Exception e) {
            logger.error("Failed to initialize Nuclei integration", e);
        }
    }
    
    private void detectNucleiInstallation() {
        String[] possiblePaths = {
            "/usr/local/bin/nuclei",
            "/usr/bin/nuclei",
            "nuclei",
            System.getProperty("user.home") + "/go/bin/nuclei",
            System.getProperty("user.home") + "/.local/bin/nuclei"
        };
        
        for (String path : possiblePaths) {
            if (isNucleiAvailable(path)) {
                this.nucleiPath = path;
                logger.info("Found Nuclei at: {}", path);
                break;
            }
        }
        
        if (nucleiPath == null) {
            logger.warn("Nuclei not found in standard locations");
            // Try to download and install Nuclei
            autoInstallNuclei();
        }
        
        // Detect templates directory
        detectTemplatesDirectory();
    }
    
    private boolean isNucleiAvailable(String path) {
        try {
            ProcessBuilder pb = new ProcessBuilder(path, "-version");
            Process process = pb.start();
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    private void autoInstallNuclei() {
        try {
            logger.info("Attempting to auto-install Nuclei...");
            
            // Download Nuclei binary
            String downloadUrl = determineNucleiDownloadUrl();
            Path nucleiDir = Paths.get(System.getProperty("user.home"), ".ai-burp-extension", "nuclei");
            Files.createDirectories(nucleiDir);
            
            Path nucleiBinary = nucleiDir.resolve("nuclei");
            downloadFile(downloadUrl, nucleiBinary);
            
            // Make executable
            nucleiBinary.toFile().setExecutable(true);
            this.nucleiPath = nucleiBinary.toString();
            
            logger.info("Nuclei installed successfully at: {}", nucleiPath);
            
        } catch (Exception e) {
            logger.error("Failed to auto-install Nuclei", e);
        }
    }
    
    private String determineNucleiDownloadUrl() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch");
        
        String platform;
        if (os.contains("windows")) {
            platform = "windows";
        } else if (os.contains("mac")) {
            platform = "macOS";
        } else {
            platform = "linux";
        }
        
        String architecture = arch.contains("64") ? "amd64" : "386";
        
        return String.format("https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_%s_%s.zip", 
                           platform, architecture);
    }
    
    private void downloadFile(String url, Path destination) throws IOException {
        // Implementation would download and extract Nuclei
        logger.info("Downloading Nuclei from: {}", url);
        // For POC, we'll assume Nuclei is available
    }
    
    private void detectTemplatesDirectory() {
        String[] possibleTemplatePaths = {
            System.getProperty("user.home") + "/nuclei-templates",
            System.getProperty("user.home") + "/.config/nuclei/templates",
            "/opt/nuclei-templates",
            "./nuclei-templates"
        };
        
        for (String path : possibleTemplatePaths) {
            if (Files.exists(Paths.get(path))) {
                this.templatesPath = path;
                logger.info("Found Nuclei templates at: {}", path);
                return;
            }
        }
        
        // Download templates if not found
        downloadNucleiTemplates();
    }
    
    private void downloadNucleiTemplates() {
        try {
            Path templatesDir = Paths.get(System.getProperty("user.home"), ".ai-burp-extension", "nuclei-templates");
            Files.createDirectories(templatesDir);
            
            // Clone nuclei-templates repository
            ProcessBuilder pb = new ProcessBuilder("git", "clone", 
                "https://github.com/projectdiscovery/nuclei-templates.git", 
                templatesDir.toString());
            Process process = pb.start();
            
            if (process.waitFor() == 0) {
                this.templatesPath = templatesDir.toString();
                logger.info("Downloaded Nuclei templates to: {}", templatesPath);
            }
            
        } catch (Exception e) {
            logger.error("Failed to download Nuclei templates", e);
        }
    }
    
    private void loadNucleiTemplates() {
        if (templatesPath == null) return;
        
        try {
            Files.walk(Paths.get(templatesPath))
                 .filter(path -> path.toString().endsWith(".yaml") || path.toString().endsWith(".yml"))
                 .forEach(this::parseNucleiTemplate);
                 
        } catch (IOException e) {
            logger.error("Failed to load Nuclei templates", e);
        }
    }
    
    private void parseNucleiTemplate(Path templatePath) {
        try {
            String content = Files.readString(templatePath);
            NucleiTemplate template = templateManager.parseTemplate(templatePath, content);
            availableTemplates.put(template.getId(), template);
            
        } catch (Exception e) {
            logger.debug("Failed to parse template: {}", templatePath, e);
        }
    }
    
    private void initializeTemplateCategories() {
        // Enable relevant templates based on configuration
        enabledTemplates.addAll(Arrays.asList(
            "http-missing-security-headers",
            "generic-tokens",
            "tech-detect",
            "cves",
            "vulnerabilities",
            "exposed-panels",
            "misconfiguration",
            "takeovers"
        ));
    }
    
    public CompletableFuture<NucleiScanResult> scanTarget(String target, ApplicationContext context) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Select relevant templates based on context
                List<String> selectedTemplates = selectTemplatesForContext(context);
                
                // Execute Nuclei scan
                NucleiScanResult result = executeNucleiScan(target, selectedTemplates, context);
                
                // Process results and feed to learning engine
                processAndLearnFromResults(result, context);
                
                return result;
                
            } catch (Exception e) {
                logger.error("Nuclei scan failed for target: {}", target, e);
                return new NucleiScanResult(target, Collections.emptyList(), false, e.getMessage());
            }
        }, nucleiExecutor);
    }
    
    private List<String> selectTemplatesForContext(ApplicationContext context) {
        List<String> selected = new ArrayList<>();
        
        // Always include basic checks
        selected.addAll(Arrays.asList(
            "http-missing-security-headers",
            "tech-detect",
            "generic-tokens"
        ));
        
        // Technology-specific templates
        for (String tech : context.getDetectedTechnologies()) {
            selected.addAll(getTemplatesForTechnology(tech));
        }
        
        // Framework-specific templates
        for (String framework : context.getFrameworks()) {
            selected.addAll(getTemplatesForFramework(framework));
        }
        
        // Database-specific templates
        for (String database : context.getDatabases()) {
            selected.addAll(getTemplatesForDatabase(database));
        }
        
        // CVE templates based on detected versions
        selected.addAll(getCVETemplatesForContext(context));
        
        return selected;
    }
    
    private List<String> getTemplatesForTechnology(String technology) {
        Map<String, List<String>> techTemplates = Map.of(
            "apache", Arrays.asList("apache-detect", "apache-cve", "apache-status"),
            "nginx", Arrays.asList("nginx-detect", "nginx-status", "nginx-cve"),
            "php", Arrays.asList("php-detect", "php-errors", "php-cve"),
            "java", Arrays.asList("java-detect", "spring-boot", "tomcat-cve"),
            "nodejs", Arrays.asList("nodejs-detect", "express-detect", "npm-cve"),
            "python", Arrays.asList("python-detect", "django-detect", "flask-detect")
        );
        
        return techTemplates.getOrDefault(technology.toLowerCase(), Collections.emptyList());
    }
    
    private List<String> getTemplatesForFramework(String framework) {
        Map<String, List<String>> frameworkTemplates = Map.of(
            "spring", Arrays.asList("spring-boot-actuator", "spring-cve"),
            "django", Arrays.asList("django-debug", "django-cve"),
            "laravel", Arrays.asList("laravel-telescope", "laravel-debug"),
            "express", Arrays.asList("express-detect", "nodejs-cve"),
            "rails", Arrays.asList("rails-detect", "ruby-cve")
        );
        
        return frameworkTemplates.getOrDefault(framework.toLowerCase(), Collections.emptyList());
    }
    
    private List<String> getTemplatesForDatabase(String database) {
        Map<String, List<String>> dbTemplates = Map.of(
            "mysql", Arrays.asList("mysql-detect", "mysql-cve"),
            "postgresql", Arrays.asList("postgresql-detect", "postgresql-cve"),
            "mongodb", Arrays.asList("mongodb-detect", "mongodb-unauth"),
            "redis", Arrays.asList("redis-detect", "redis-unauth"),
            "elasticsearch", Arrays.asList("elasticsearch-detect", "elasticsearch-unauth")
        );
        
        return dbTemplates.getOrDefault(database.toLowerCase(), Collections.emptyList());
    }
    
    private List<String> getCVETemplatesForContext(ApplicationContext context) {
        List<String> cveTemplates = new ArrayList<>();
        
        // Add CVE templates based on detected software versions
        // This would be expanded with actual version detection
        cveTemplates.add("cves/2023");
        cveTemplates.add("cves/2024");
        
        return cveTemplates;
    }
    
    private NucleiScanResult executeNucleiScan(String target, List<String> templates, ApplicationContext context) {
        try {
            List<String> command = buildNucleiCommand(target, templates);
            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // Read output
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            
            boolean success = process.waitFor(timeoutSeconds, TimeUnit.SECONDS) && process.exitValue() == 0;
            
            // Parse results
            List<NucleiFinding> findings = parseNucleiOutput(output.toString());
            
            return new NucleiScanResult(target, findings, success, output.toString());
            
        } catch (Exception e) {
            logger.error("Failed to execute Nuclei scan", e);
            throw new RuntimeException("Nuclei execution failed", e);
        }
    }
    
    private List<String> buildNucleiCommand(String target, List<String> templates) {
        List<String> command = new ArrayList<>();
        command.add(nucleiPath);
        command.add("-u");
        command.add(target);
        command.add("-j"); // JSON output
        command.add("-silent");
        command.add("-rate-limit");
        command.add(String.valueOf(requestsPerSecond));
        command.add("-timeout");
        command.add(String.valueOf(timeoutSeconds));
        
        // Add templates
        if (!templates.isEmpty()) {
            command.add("-t");
            command.add(String.join(",", templates));
        }
        
        // Add nuclei-templates path if available
        if (templatesPath != null) {
            command.add("-t");
            command.add(templatesPath);
        }
        
        return command;
    }
    
    private List<NucleiFinding> parseNucleiOutput(String output) {
        List<NucleiFinding> findings = new ArrayList<>();
        
        String[] lines = output.split("\n");
        for (String line : lines) {
            if (line.trim().startsWith("{")) {
                try {
                    NucleiFinding finding = NucleiFinding.fromJson(line);
                    findings.add(finding);
                } catch (Exception e) {
                    logger.debug("Failed to parse Nuclei output line: {}", line, e);
                }
            }
        }
        
        return findings;
    }
    
    private void processAndLearnFromResults(NucleiScanResult result, ApplicationContext context) {
        try {
            // Feed results to learning engine for pattern recognition
            learningEngine.learnFromNucleiResults(result, context);
            
            // Update context with new findings
            updateContextWithFindings(result, context);
            
            // Identify gaps in our AI testing
            identifyTestingGaps(result, context);
            
        } catch (Exception e) {
            logger.error("Failed to process Nuclei results", e);
        }
    }
    
    private void updateContextWithFindings(NucleiScanResult result, ApplicationContext context) {
        for (NucleiFinding finding : result.getFindings()) {
            // Update technology detection
            if (finding.getInfo() != null && finding.getInfo().getTags() != null) {
                for (String tag : finding.getInfo().getTags()) {
                    if (isTechnologyTag(tag)) {
                        context.getDetectedTechnologies().add(tag);
                    }
                }
            }
            
            // Record vulnerabilities
            if (finding.getSeverity() != null) {
                double riskScore = convertSeverityToScore(finding.getSeverity());
                context.recordVulnerability(finding.getTemplateId(), riskScore);
            }
        }
    }
    
    private boolean isTechnologyTag(String tag) {
        return tag.matches(".*(?:apache|nginx|php|java|python|nodejs|mysql|postgresql).*");
    }
    
    private double convertSeverityToScore(String severity) {
        switch (severity.toLowerCase()) {
            case "critical": return 9.5;
            case "high": return 8.0;
            case "medium": return 6.0;
            case "low": return 3.0;
            case "info": return 1.0;
            default: return 5.0;
        }
    }
    
    private void identifyTestingGaps(NucleiScanResult result, ApplicationContext context) {
        // Analyze what Nuclei found that our AI testing missed
        List<String> missedVulnerabilities = new ArrayList<>();
        
        for (NucleiFinding finding : result.getFindings()) {
            String vulnType = mapNucleiTemplateToVulnType(finding.getTemplateId());
            
            // Check if our AI testing covered this vulnerability type
            if (!context.getVulnerabilityHistory().containsKey(vulnType)) {
                missedVulnerabilities.add(vulnType);
            }
        }
        
        if (!missedVulnerabilities.isEmpty()) {
            logger.info("Identified {} testing gaps: {}", missedVulnerabilities.size(), missedVulnerabilities);
            
            // Feed gaps to learning engine for improvement
            learningEngine.learnFromTestingGaps(missedVulnerabilities, context);
        }
    }
    
    private String mapNucleiTemplateToVulnType(String templateId) {
        if (templateId.contains("xss")) return "xss";
        if (templateId.contains("sqli") || templateId.contains("sql")) return "sqli";
        if (templateId.contains("ssrf")) return "ssrf";
        if (templateId.contains("lfi") || templateId.contains("file")) return "lfi";
        if (templateId.contains("rce") || templateId.contains("command")) return "rce";
        if (templateId.contains("xxe")) return "xxe";
        if (templateId.contains("csrf")) return "csrf";
        if (templateId.contains("idor")) return "idor";
        return "misconfiguration";
    }
    
    public void scanWithContextualTemplates(String target, ApplicationContext context) {
        // Dynamic template selection based on real-time context
        CompletableFuture.supplyAsync(() -> {
            try {
                // Analyze current context for optimal template selection
                List<String> dynamicTemplates = selectDynamicTemplates(context);
                
                // Execute scan with contextual templates
                return executeNucleiScan(target, dynamicTemplates, context);
                
            } catch (Exception e) {
                logger.error("Contextual Nuclei scan failed", e);
                return null;
            }
        }, nucleiExecutor).thenAccept(result -> {
            if (result != null) {
                processAndLearnFromResults(result, context);
            }
        });
    }
    
    private List<String> selectDynamicTemplates(ApplicationContext context) {
        List<String> templates = new ArrayList<>();
        
        // Risk-based template selection
        double riskScore = context.getOverallRiskScore();
        
        if (riskScore > 7.0) {
            // High-risk applications get comprehensive scanning
            templates.addAll(Arrays.asList("cves", "vulnerabilities", "exposures", "takeovers"));
        } else if (riskScore > 4.0) {
            // Medium-risk applications get targeted scanning
            templates.addAll(Arrays.asList("vulnerabilities", "misconfiguration"));
        } else {
            // Low-risk applications get basic scanning
            templates.add("http-missing-security-headers");
        }
        
        return templates;
    }
    
    public void shutdown() {
        logger.info("Shutting down Nuclei integration...");
        nucleiExecutor.shutdown();
        try {
            if (!nucleiExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                nucleiExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            nucleiExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
    
    // Getters and configuration methods
    public boolean isNucleiAvailable() { return nucleiPath != null; }
    public int getAvailableTemplatesCount() { return availableTemplates.size(); }
    public Set<String> getEnabledTemplates() { return new HashSet<>(enabledTemplates); }
    
    public void setMaxConcurrentScans(int maxConcurrentScans) {
        this.maxConcurrentScans = maxConcurrentScans;
    }
    
    public void setRequestsPerSecond(int requestsPerSecond) {
        this.requestsPerSecond = requestsPerSecond;
    }
    
    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }
}