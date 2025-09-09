package com.secure.ai.burp.ml;

import ai.onnxruntime.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.Arrays;

public class ModelManager {
    private static final Logger logger = LoggerFactory.getLogger(ModelManager.class);
    
    private OrtEnvironment environment;
    private final Map<String, OrtSession> loadedModels;
    private final Map<String, String> modelPaths;
    
    public ModelManager() {
        this.loadedModels = new ConcurrentHashMap<>();
        this.modelPaths = new ConcurrentHashMap<>();
        initializeModelPaths();
    }
    
    private void initializeModelPaths() {
        // Define model paths for different vulnerability types
        modelPaths.put("anomaly_detection", "models/anomaly.onnx");
        modelPaths.put("xss_detection", "models/xss_detector.onnx");
        modelPaths.put("sqli_detection", "models/sqli_detector.onnx");
        modelPaths.put("ssrf_detection", "models/ssrf_detector.onnx");
        modelPaths.put("auth_bypass", "models/auth_bypass_detector.onnx");
        modelPaths.put("payload_generator", "models/payload_generator.onnx");
        modelPaths.put("context_analyzer", "models/context_analyzer.onnx");
        modelPaths.put("tech_stack_detector", "models/tech_stack_detector.onnx");
        modelPaths.put("vulnerability_classifier", "models/vuln_classifier.onnx");
        modelPaths.put("risk_assessor", "models/risk_assessor.onnx");
    }
    
    public void initialize() {
        try {
            logger.info("Initializing ONNX Runtime environment...");
            environment = OrtEnvironment.getEnvironment();
            
            // Load core models
            loadCoreModels();
            
            logger.info("Model Manager initialized successfully with {} models", loadedModels.size());
            
        } catch (Exception e) {
            logger.error("Failed to initialize Model Manager", e);
            throw new RuntimeException("Model Manager initialization failed", e);
        }
    }
    
    private void loadCoreModels() {
        // Load only existing models, create placeholder for others
        for (Map.Entry<String, String> entry : modelPaths.entrySet()) {
            String modelName = entry.getKey();
            String modelPath = entry.getKey();
            
            try {
                Path path = Paths.get(modelPath);
                if (path.toFile().exists()) {
                    loadModel(modelName, modelPath);
                } else {
                    logger.warn("Model file not found: {} - will use fallback methods", modelPath);
                    // Create a placeholder or use fallback detection methods
                    createFallbackModel(modelName);
                }
            } catch (Exception e) {
                logger.warn("Failed to load model: {} - {}", modelName, e.getMessage());
                createFallbackModel(modelName);
            }
        }
    }
    
    private void loadModel(String modelName, String modelPath) {
        try {
            OrtSession.SessionOptions options = new OrtSession.SessionOptions();
            OrtSession session = environment.createSession(modelPath, options);
            loadedModels.put(modelName, session);
            logger.info("Successfully loaded model: {}", modelName);
        } catch (OrtException e) {
            logger.error("Failed to load model: {} from path: {}", modelName, modelPath, e);
            throw new RuntimeException("Failed to load model: " + modelName, e);
        }
    }
    
    private void createFallbackModel(String modelName) {
        // For models that don't exist, we'll use rule-based fallbacks
        // This is handled in the respective detection classes
        logger.info("Using fallback detection for: {}", modelName);
    }
    
    public boolean isModelLoaded(String modelName) {
        return loadedModels.containsKey(modelName);
    }
    
    public MLPrediction predict(String modelName, float[] inputData) {
        if (!isModelLoaded(modelName)) {
            return getFallbackPrediction(modelName, inputData);
        }
        
        try {
            OrtSession session = loadedModels.get(modelName);
            
            // Create input tensor
            long[] shape = {1, inputData.length};
            OnnxTensor inputTensor = OnnxTensor.createTensor(environment, 
                new float[][]{inputData}, shape);
            
            // Run inference
            Map<String, OnnxTensor> inputs = Map.of("input", inputTensor);
            OrtSession.Result result = session.run(inputs);
            
            // Extract output
            OnnxTensor outputTensor = (OnnxTensor) result.get(0);
            float[][] output = (float[][]) outputTensor.getValue();
            
            // Clean up
            inputTensor.close();
            result.close();
            
            return new MLPrediction(modelName, output[0], true);
            
        } catch (OrtException e) {
            logger.warn("Model prediction failed for {}: {}", modelName, e.getMessage());
            return getFallbackPrediction(modelName, inputData);
        }
    }
    
    public MLPrediction predictText(String modelName, String inputText) {
        // Convert text to features based on model type
        float[] features = extractTextFeatures(modelName, inputText);
        return predict(modelName, features);
    }
    
    private float[] extractTextFeatures(String modelName, String inputText) {
        switch (modelName) {
            case "xss_detection":
                return extractXSSFeatures(inputText);
            case "sqli_detection":
                return extractSQLiFeatures(inputText);
            case "ssrf_detection":
                return extractSSRFFeatures(inputText);
            case "context_analyzer":
                return extractContextFeatures(inputText);
            default:
                return extractGenericFeatures(inputText);
        }
    }
    
    private float[] extractXSSFeatures(String input) {
        float[] features = new float[50]; // Feature vector size
        
        // Basic XSS indicators
        features[0] = input.contains("<script") ? 1.0f : 0.0f;
        features[1] = input.contains("javascript:") ? 1.0f : 0.0f;
        features[2] = input.contains("onerror") ? 1.0f : 0.0f;
        features[3] = input.contains("onload") ? 1.0f : 0.0f;
        features[4] = input.contains("alert(") ? 1.0f : 0.0f;
        features[5] = input.contains("document.") ? 1.0f : 0.0f;
        features[6] = input.contains("eval(") ? 1.0f : 0.0f;
        features[7] = input.contains("innerHTML") ? 1.0f : 0.0f;
        features[8] = (float) input.length() / 1000.0f; // Normalized length
        features[9] = countChar(input, '<') / 10.0f; // Normalized tag count
        
        // Additional features based on common XSS patterns
        features[10] = input.contains("src=") ? 1.0f : 0.0f;
        features[11] = input.contains("href=") ? 1.0f : 0.0f;
        features[12] = input.contains("style=") ? 1.0f : 0.0f;
        features[13] = input.matches(".*['\"][^'\"]*javascript:[^'\"]*['\"].*") ? 1.0f : 0.0f;
        features[14] = input.contains("data:") ? 1.0f : 0.0f;
        
        return features;
    }
    
    private float[] extractSQLiFeatures(String input) {
        float[] features = new float[50];
        
        String lowerInput = input.toLowerCase();
        
        // SQL injection indicators
        features[0] = lowerInput.contains("union") ? 1.0f : 0.0f;
        features[1] = lowerInput.contains("select") ? 1.0f : 0.0f;
        features[2] = lowerInput.contains("insert") ? 1.0f : 0.0f;
        features[3] = lowerInput.contains("delete") ? 1.0f : 0.0f;
        features[4] = lowerInput.contains("update") ? 1.0f : 0.0f;
        features[5] = lowerInput.contains("drop") ? 1.0f : 0.0f;
        features[6] = lowerInput.contains("'") ? 1.0f : 0.0f;
        features[7] = lowerInput.contains("\"") ? 1.0f : 0.0f;
        features[8] = lowerInput.contains("--") ? 1.0f : 0.0f;
        features[9] = lowerInput.contains("/*") ? 1.0f : 0.0f;
        features[10] = lowerInput.contains("or ") ? 1.0f : 0.0f;
        features[11] = lowerInput.contains("and ") ? 1.0f : 0.0f;
        features[12] = lowerInput.contains("where") ? 1.0f : 0.0f;
        features[13] = lowerInput.contains("from") ? 1.0f : 0.0f;
        features[14] = lowerInput.contains("having") ? 1.0f : 0.0f;
        features[15] = lowerInput.contains("group by") ? 1.0f : 0.0f;
        features[16] = lowerInput.contains("order by") ? 1.0f : 0.0f;
        features[17] = lowerInput.contains("limit") ? 1.0f : 0.0f;
        features[18] = lowerInput.contains("information_schema") ? 1.0f : 0.0f;
        features[19] = lowerInput.contains("database()") ? 1.0f : 0.0f;
        
        return features;
    }
    
    private float[] extractSSRFFeatures(String input) {
        float[] features = new float[30];
        
        String lowerInput = input.toLowerCase();
        
        // SSRF indicators
        features[0] = lowerInput.contains("http://") ? 1.0f : 0.0f;
        features[1] = lowerInput.contains("https://") ? 1.0f : 0.0f;
        features[2] = lowerInput.contains("file://") ? 1.0f : 0.0f;
        features[3] = lowerInput.contains("ftp://") ? 1.0f : 0.0f;
        features[4] = lowerInput.contains("localhost") ? 1.0f : 0.0f;
        features[5] = lowerInput.contains("127.0.0.1") ? 1.0f : 0.0f;
        features[6] = lowerInput.contains("0.0.0.0") ? 1.0f : 0.0f;
        features[7] = lowerInput.contains("169.254") ? 1.0f : 0.0f; // AWS metadata
        features[8] = lowerInput.contains("192.168") ? 1.0f : 0.0f;
        features[9] = lowerInput.contains("10.") ? 1.0f : 0.0f;
        features[10] = lowerInput.contains("172.") ? 1.0f : 0.0f;
        features[11] = lowerInput.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*") ? 1.0f : 0.0f;
        features[12] = lowerInput.contains("gopher://") ? 1.0f : 0.0f;
        features[13] = lowerInput.contains("dict://") ? 1.0f : 0.0f;
        features[14] = lowerInput.contains("ldap://") ? 1.0f : 0.0f;
        
        return features;
    }
    
    private float[] extractContextFeatures(String input) {
        float[] features = new float[100];
        
        // Technology indicators
        features[0] = input.contains("php") ? 1.0f : 0.0f;
        features[1] = input.contains("asp") ? 1.0f : 0.0f;
        features[2] = input.contains("jsp") ? 1.0f : 0.0f;
        features[3] = input.contains("node") ? 1.0f : 0.0f;
        features[4] = input.contains("python") ? 1.0f : 0.0f;
        features[5] = input.contains("ruby") ? 1.0f : 0.0f;
        features[6] = input.contains("java") ? 1.0f : 0.0f;
        
        // Framework indicators
        features[10] = input.contains("spring") ? 1.0f : 0.0f;
        features[11] = input.contains("django") ? 1.0f : 0.0f;
        features[12] = input.contains("rails") ? 1.0f : 0.0f;
        features[13] = input.contains("express") ? 1.0f : 0.0f;
        features[14] = input.contains("flask") ? 1.0f : 0.0f;
        features[15] = input.contains("laravel") ? 1.0f : 0.0f;
        
        return features;
    }
    
    private float[] extractGenericFeatures(String input) {
        float[] features = new float[20];
        
        features[0] = (float) input.length() / 1000.0f;
        features[1] = countChar(input, '&') / 10.0f;
        features[2] = countChar(input, '=') / 10.0f;
        features[3] = countChar(input, '%') / 10.0f;
        features[4] = input.matches(".*[0-9].*") ? 1.0f : 0.0f;
        features[5] = input.matches(".*[a-zA-Z].*") ? 1.0f : 0.0f;
        features[6] = input.matches(".*[^a-zA-Z0-9].*") ? 1.0f : 0.0f;
        
        return features;
    }
    
    private int countChar(String str, char ch) {
        return (int) str.chars().filter(c -> c == ch).count();
    }
    
    private MLPrediction getFallbackPrediction(String modelName, float[] inputData) {
        // Rule-based fallback predictions
        switch (modelName) {
            case "xss_detection":
                return getFallbackXSSPrediction(inputData);
            case "sqli_detection":
                return getFallbackSQLiPrediction(inputData);
            default:
                return new MLPrediction(modelName, new float[]{0.5f}, false);
        }
    }
    
    private MLPrediction getFallbackXSSPrediction(float[] features) {
        float score = 0.0f;
        
        // Simple rule-based XSS detection
        if (features.length > 10) {
            score += features[0] * 0.3f; // <script
            score += features[1] * 0.2f; // javascript:
            score += features[2] * 0.1f; // onerror
            score += features[3] * 0.1f; // onload
            score += features[4] * 0.2f; // alert(
            score += features[5] * 0.1f; // document.
        }
        
        return new MLPrediction("xss_detection", new float[]{Math.min(score, 1.0f)}, false);
    }
    
    private MLPrediction getFallbackSQLiPrediction(float[] features) {
        float score = 0.0f;
        
        // Simple rule-based SQLi detection
        if (features.length > 15) {
            score += features[0] * 0.2f; // union
            score += features[1] * 0.1f; // select
            score += features[6] * 0.1f; // '
            score += features[8] * 0.2f; // --
            score += features[10] * 0.1f; // or
            score += features[11] * 0.1f; // and
        }
        
        return new MLPrediction("sqli_detection", new float[]{Math.min(score, 1.0f)}, false);
    }
    
    public void shutdown() {
        logger.info("Shutting down Model Manager...");
        
        // Close all loaded models
        for (Map.Entry<String, OrtSession> entry : loadedModels.entrySet()) {
            try {
                entry.getValue().close();
                logger.debug("Closed model: {}", entry.getKey());
            } catch (OrtException e) {
                logger.warn("Error closing model {}: {}", entry.getKey(), e.getMessage());
            }
        }
        
        loadedModels.clear();
        
        // Close environment
        if (environment != null) {
            try {
                environment.close();
            } catch (OrtException e) {
                logger.warn("Error closing ONNX environment: {}", e.getMessage());
            }
        }
        
        logger.info("Model Manager shut down");
    }
}