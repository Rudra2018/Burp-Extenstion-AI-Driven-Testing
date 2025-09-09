package com.secure.ai.burp.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.*;
import burp.api.montoya.http.handler.*;
import com.secure.ai.burp.models.ml.ModelManager;
import com.secure.ai.burp.analyzers.traffic.TrafficAnalyzer;
import com.secure.ai.burp.analyzers.traffic.ContextExtractor;
import com.secure.ai.burp.generators.payload.PayloadGenerator;
import com.secure.ai.burp.detectors.vulnerability.VulnerabilityScanner;
import com.secure.ai.burp.learners.adaptive.AdaptiveLearningEngine;
import com.secure.ai.burp.utilities.reporting.SecurityReporter;
import com.secure.ai.burp.models.data.ApplicationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class AISecurityEngine implements HttpHandler {
    private static final Logger logger = LoggerFactory.getLogger(AISecurityEngine.class);
    
    private final MontoyaApi api;
    private final ModelManager modelManager;
    private final TrafficAnalyzer trafficAnalyzer;
    private final ContextExtractor contextExtractor;
    private final PayloadGenerator payloadGenerator;
    private final VulnerabilityScanner vulnerabilityScanner;
    private final AdaptiveLearningEngine learningEngine;
    private final SecurityReporter reporter;
    private final ExecutorService analysisExecutor;
    
    private final Map<String, ApplicationContext> applicationContexts;
    private volatile boolean isActive;
    
    public AISecurityEngine(MontoyaApi api) {
        this.api = api;
        this.modelManager = new ModelManager();
        this.trafficAnalyzer = new TrafficAnalyzer(api);
        this.contextExtractor = new ContextExtractor();
        this.payloadGenerator = new PayloadGenerator(modelManager);
        this.vulnerabilityScanner = new VulnerabilityScanner(modelManager, api);
        this.learningEngine = new AdaptiveLearningEngine(modelManager);
        this.reporter = new SecurityReporter(api);
        this.analysisExecutor = Executors.newFixedThreadPool(10);
        this.applicationContexts = new ConcurrentHashMap<>();
        this.isActive = false;
        
        initialize();
    }
    
    private void initialize() {
        try {
            logger.info("Initializing AI Security Engine...");
            
            // Load ML models
            modelManager.initialize();
            
            // Register HTTP handler
            api.http().registerHttpHandler(this);
            
            // Initialize components
            trafficAnalyzer.initialize();
            learningEngine.initialize();
            
            this.isActive = true;
            logger.info("AI Security Engine initialized successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize AI Security Engine", e);
            throw new RuntimeException("AI Security Engine initialization failed", e);
        }
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!isActive) return RequestToBeSentAction.continueWith(requestToBeSent);
        
        try {
            // Extract application context
            String host = requestToBeSent.httpService().host();
            ApplicationContext context = getOrCreateApplicationContext(host);
            
            // Analyze request in background
            analysisExecutor.submit(() -> analyzeRequest(requestToBeSent, context));
            
            return RequestToBeSentAction.continueWith(requestToBeSent);
            
        } catch (Exception e) {
            logger.warn("Error handling HTTP request", e);
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!isActive) return ResponseReceivedAction.continueWith(responseReceived);
        
        try {
            String host = responseReceived.initiatingRequest().httpService().host();
            ApplicationContext context = getOrCreateApplicationContext(host);
            
            // Analyze response and trigger security testing
            analysisExecutor.submit(() -> {
                analyzeResponse(responseReceived, context);
                performSecurityTesting(responseReceived, context);
            });
            
            return ResponseReceivedAction.continueWith(responseReceived);
            
        } catch (Exception e) {
            logger.warn("Error handling HTTP response", e);
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
    
    private ApplicationContext getOrCreateApplicationContext(String host) {
        return applicationContexts.computeIfAbsent(host, k -> new ApplicationContext(k));
    }
    
    private void analyzeRequest(HttpRequestToBeSent request, ApplicationContext context) {
        try {
            // Extract context from request
            context.updateFromRequest(contextExtractor.extractContext(request));
            
            // Analyze traffic patterns
            trafficAnalyzer.analyzeRequest(request, context);
            
        } catch (Exception e) {
            logger.warn("Error analyzing request", e);
        }
    }
    
    private void analyzeResponse(HttpResponseReceived response, ApplicationContext context) {
        try {
            // Extract context from response
            context.updateFromResponse(contextExtractor.extractContext(response));
            
            // Analyze traffic patterns
            trafficAnalyzer.analyzeResponse(response, context);
            
        } catch (Exception e) {
            logger.warn("Error analyzing response", e);
        }
    }
    
    private void performSecurityTesting(HttpResponseReceived response, ApplicationContext context) {
        try {
            // Generate context-aware payloads
            var payloads = payloadGenerator.generatePayloads(response.initiatingRequest(), context);
            
            // Perform vulnerability scanning
            var results = vulnerabilityScanner.scanWithPayloads(response.initiatingRequest(), payloads, context);
            
            // Learn from results
            learningEngine.learnFromResults(results, context);
            
            // Report findings
            reporter.reportFindings(results);
            
        } catch (Exception e) {
            logger.warn("Error performing security testing", e);
        }
    }
    
    public void shutdown() {
        logger.info("Shutting down AI Security Engine...");
        this.isActive = false;
        
        if (analysisExecutor != null && !analysisExecutor.isShutdown()) {
            analysisExecutor.shutdown();
        }
        
        if (modelManager != null) {
            modelManager.shutdown();
        }
        
        logger.info("AI Security Engine shut down");
    }
    
    public Map<String, ApplicationContext> getApplicationContexts() {
        return new ConcurrentHashMap<>(applicationContexts);
    }
    
    public boolean isActive() {
        return isActive;
    }
    
    public ModelManager getModelManager() {
        return modelManager;
    }
}