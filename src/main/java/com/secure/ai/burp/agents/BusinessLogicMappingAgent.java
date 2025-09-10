package com.secure.ai.burp.agents;

import burp.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Tier 2: Business Logic Mapping & Testing Agent
 * 
 * Understands and tests for flaws in multi-step application workflows.
 * Maps user flows and identifies business logic vulnerabilities.
 */
public class BusinessLogicMappingAgent {
    
    private final IBurpExtenderCallbacks callbacks;
    private final ExecutorService executorService;
    
    private final AtomicInteger workflowCount = new AtomicInteger(0);
    private final AtomicInteger testedFlows = new AtomicInteger(0);
    private volatile boolean active = false;
    
    // Workflow tracking and analysis
    private final Map<String, UserWorkflow> identifiedWorkflows = new ConcurrentHashMap<>();
    private final Map<String, List<IHttpRequestResponse>> sessionFlows = new ConcurrentHashMap<>();
    private final Set<String> businessLogicTests = Collections.synchronizedSet(new HashSet<>());
    
    // Business logic vulnerability patterns
    private final List<BusinessLogicTest> logicTests;
    
    public BusinessLogicMappingAgent(IBurpExtenderCallbacks callbacks, ExecutorService executorService) {
        this.callbacks = callbacks;
        this.executorService = executorService;
        this.logicTests = initializeBusinessLogicTests();
    }
    
    public void start() {
        this.active = true;
        
        // Start workflow mapping from traffic
        executorService.submit(this::mapUserWorkflows);
        
        // Start business logic testing
        executorService.submit(this::testBusinessLogic);
        
        // Start session analysis
        executorService.submit(this::analyzeUserSessions);
    }
    
    public void stop() {
        this.active = false;
    }
    
    public String getStatus() {
        return active ? "MAPPING - " + workflowCount.get() + " workflows identified" : "STOPPED";
    }
    
    public int getWorkflowCount() {
        return workflowCount.get();
    }
    
    public int getTestedFlows() {
        return testedFlows.get();
    }
    
    private List<BusinessLogicTest> initializeBusinessLogicTests() {
        List<BusinessLogicTest> tests = new ArrayList<>();
        
        // Authentication bypass tests
        tests.add(new BusinessLogicTest(
            "AUTH_BYPASS", 
            "Direct object access without authentication",
            this::testAuthenticationBypass
        ));
        
        // Authorization bypass tests
        tests.add(new BusinessLogicTest(
            "AUTHZ_BYPASS", 
            "Access to resources without proper authorization",
            this::testAuthorizationBypass
        ));
        
        // Price manipulation tests
        tests.add(new BusinessLogicTest(
            "PRICE_MANIPULATION", 
            "Manipulation of prices or quantities in commerce flows",
            this::testPriceManipulation
        ));
        
        // Workflow bypass tests
        tests.add(new BusinessLogicTest(
            "WORKFLOW_BYPASS", 
            "Bypassing mandatory steps in business processes",
            this::testWorkflowBypass
        ));
        
        // Race condition tests
        tests.add(new BusinessLogicTest(
            "RACE_CONDITION", 
            "Race conditions in multi-step processes",
            this::testRaceConditions
        ));
        
        // State manipulation tests
        tests.add(new BusinessLogicTest(
            "STATE_MANIPULATION", 
            "Improper state transitions in workflows",
            this::testStateManipulation
        ));
        
        // Privilege escalation tests
        tests.add(new BusinessLogicTest(
            "PRIVILEGE_ESCALATION", 
            "Unauthorized privilege elevation",
            this::testPrivilegeEscalation
        ));
        
        return tests;
    }
    
    private void mapUserWorkflows() {
        Map<String, List<IHttpRequestResponse>> userSessions = new HashMap<>();
        
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                IHttpRequestResponse[] history = callbacks.getProxyHistory();
                
                // Group requests by session/user
                for (IHttpRequestResponse item : history) {
                    String sessionId = extractSessionIdentifier(item);
                    if (sessionId != null) {
                        userSessions.computeIfAbsent(sessionId, k -> new ArrayList<>()).add(item);
                    }
                }
                
                // Analyze each user session for workflows
                for (Map.Entry<String, List<IHttpRequestResponse>> entry : userSessions.entrySet()) {
                    analyzeSessionForWorkflows(entry.getKey(), entry.getValue());
                }
                
                Thread.sleep(60000); // Analyze every minute
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void analyzeSessionForWorkflows(String sessionId, List<IHttpRequestResponse> requests) {
        // Sort requests by timestamp (if available) or order
        requests.sort((a, b) -> {
            // Simple ordering - in real implementation, use actual timestamps
            return Integer.compare(System.identityHashCode(a), System.identityHashCode(b));
        });
        
        // Identify common workflow patterns
        UserWorkflow workflow = identifyWorkflowPattern(requests);
        if (workflow != null) {
            String workflowKey = workflow.name + "_" + sessionId;
            if (!identifiedWorkflows.containsKey(workflowKey)) {
                identifiedWorkflows.put(workflowKey, workflow);
                workflowCount.incrementAndGet();
                
                callbacks.printOutput("Identified workflow: " + workflow.name + 
                                     " (" + workflow.steps.size() + " steps)");
            }
        }
        
        sessionFlows.put(sessionId, new ArrayList<>(requests));
    }
    
    private UserWorkflow identifyWorkflowPattern(List<IHttpRequestResponse> requests) {
        if (requests.size() < 2) return null;
        
        UserWorkflow workflow = new UserWorkflow();
        List<WorkflowStep> steps = new ArrayList<>();
        
        for (IHttpRequestResponse request : requests) {
            try {
                IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(request);
                String path = reqInfo.getUrl().getPath();
                String method = reqInfo.getMethod();
                
                WorkflowStep step = new WorkflowStep();
                step.url = reqInfo.getUrl().toString();
                step.method = method;
                step.path = path;
                step.parameters = reqInfo.getParameters();
                
                // Identify step type based on patterns
                step.stepType = classifyStepType(path, method, reqInfo.getParameters());
                steps.add(step);
                
            } catch (Exception e) {
                // Continue with next request
            }
        }
        
        // Only consider it a workflow if it has meaningful business steps
        if (hasBusinessLogicSteps(steps)) {
            workflow.steps = steps;
            workflow.name = generateWorkflowName(steps);
            workflow.type = classifyWorkflowType(steps);
            return workflow;
        }
        
        return null;
    }
    
    private String classifyStepType(String path, String method, List<IParameter> parameters) {
        String lowerPath = path.toLowerCase();
        
        // Authentication steps
        if (lowerPath.contains("login") || lowerPath.contains("signin") || 
            lowerPath.contains("authenticate")) {
            return "AUTHENTICATION";
        }
        
        // Registration steps
        if (lowerPath.contains("register") || lowerPath.contains("signup") || 
            lowerPath.contains("create") && lowerPath.contains("account")) {
            return "REGISTRATION";
        }
        
        // Payment steps
        if (lowerPath.contains("payment") || lowerPath.contains("checkout") || 
            lowerPath.contains("billing") || lowerPath.contains("purchase")) {
            return "PAYMENT";
        }
        
        // Profile/Account management
        if (lowerPath.contains("profile") || lowerPath.contains("account") || 
            lowerPath.contains("settings")) {
            return "ACCOUNT_MANAGEMENT";
        }
        
        // Administrative actions
        if (lowerPath.contains("admin") || lowerPath.contains("manage") || 
            lowerPath.contains("delete") && "POST".equals(method)) {
            return "ADMINISTRATIVE";
        }
        
        // Data modification
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            return "DATA_MODIFICATION";
        }
        
        // Data retrieval
        if ("GET".equals(method)) {
            return "DATA_RETRIEVAL";
        }
        
        return "GENERIC";
    }
    
    private boolean hasBusinessLogicSteps(List<WorkflowStep> steps) {
        Set<String> businessStepTypes = Set.of(
            "AUTHENTICATION", "REGISTRATION", "PAYMENT", 
            "ACCOUNT_MANAGEMENT", "ADMINISTRATIVE"
        );
        
        return steps.stream()
                   .anyMatch(step -> businessStepTypes.contains(step.stepType));
    }
    
    private String generateWorkflowName(List<WorkflowStep> steps) {
        Map<String, Integer> stepTypeCounts = new HashMap<>();
        
        for (WorkflowStep step : steps) {
            stepTypeCounts.merge(step.stepType, 1, Integer::sum);
        }
        
        // Generate name based on predominant step types
        String primaryType = stepTypeCounts.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("GENERIC");
        
        return primaryType + "_WORKFLOW";
    }
    
    private String classifyWorkflowType(List<WorkflowStep> steps) {
        boolean hasAuth = steps.stream().anyMatch(s -> s.stepType.equals("AUTHENTICATION"));
        boolean hasPayment = steps.stream().anyMatch(s -> s.stepType.equals("PAYMENT"));
        boolean hasAdmin = steps.stream().anyMatch(s -> s.stepType.equals("ADMINISTRATIVE"));
        
        if (hasPayment) return "ECOMMERCE";
        if (hasAdmin) return "ADMINISTRATIVE";
        if (hasAuth) return "USER_MANAGEMENT";
        
        return "GENERAL";
    }
    
    private void testBusinessLogic() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                Thread.sleep(120000); // Wait 2 minutes before starting tests
                
                for (UserWorkflow workflow : identifiedWorkflows.values()) {
                    if (!active) break;
                    
                    testWorkflowForLogicFlaws(workflow);
                    testedFlows.incrementAndGet();
                }
                
                Thread.sleep(300000); // Test every 5 minutes
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void testWorkflowForLogicFlaws(UserWorkflow workflow) {
        for (BusinessLogicTest test : logicTests) {
            if (!active) break;
            
            try {
                boolean result = test.testFunction.apply(workflow);
                String testKey = workflow.name + "_" + test.testType;
                
                if (result && !businessLogicTests.contains(testKey)) {
                    businessLogicTests.add(testKey);
                    reportBusinessLogicFlaw(workflow, test);
                }
                
            } catch (Exception e) {
                callbacks.printError("Business logic test error: " + e.getMessage());
            }
        }
    }
    
    private void analyzeUserSessions() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                // Analyze session flows for anomalies
                for (Map.Entry<String, List<IHttpRequestResponse>> entry : sessionFlows.entrySet()) {
                    analyzeSessionAnomalities(entry.getKey(), entry.getValue());
                }
                
                Thread.sleep(180000); // Analyze every 3 minutes
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void analyzeSessionAnomalities(String sessionId, List<IHttpRequestResponse> requests) {
        // Look for suspicious patterns in user behavior
        detectPrivilegeEscalation(sessionId, requests);
        detectUnusualAccess(sessionId, requests);
        detectWorkflowAnomalies(sessionId, requests);
    }
    
    private void detectPrivilegeEscalation(String sessionId, List<IHttpRequestResponse> requests) {
        boolean hasUserActions = false;
        boolean hasAdminActions = false;
        
        for (IHttpRequestResponse request : requests) {
            try {
                String path = callbacks.getHelpers().analyzeRequest(request).getUrl().getPath().toLowerCase();
                
                if (path.contains("user") || path.contains("profile")) {
                    hasUserActions = true;
                }
                
                if (path.contains("admin") || path.contains("manage")) {
                    hasAdminActions = true;
                }
                
            } catch (Exception e) {
                // Continue
            }
        }
        
        if (hasUserActions && hasAdminActions) {
            callbacks.printOutput("POTENTIAL PRIVILEGE ESCALATION detected in session: " + sessionId);
        }
    }
    
    private void detectUnusualAccess(String sessionId, List<IHttpRequestResponse> requests) {
        Set<String> accessedResources = new HashSet<>();
        
        for (IHttpRequestResponse request : requests) {
            try {
                String path = callbacks.getHelpers().analyzeRequest(request).getUrl().getPath();
                accessedResources.add(path);
            } catch (Exception e) {
                // Continue
            }
        }
        
        // If session accessed many different resources, it might be suspicious
        if (accessedResources.size() > 20) {
            callbacks.printOutput("UNUSUAL ACCESS PATTERN detected in session: " + sessionId + 
                                 " (accessed " + accessedResources.size() + " resources)");
        }
    }
    
    private void detectWorkflowAnomalies(String sessionId, List<IHttpRequestResponse> requests) {
        // Look for steps executed out of order or skipped steps
        Map<String, Integer> stepTypeOrder = new HashMap<>();
        int order = 0;
        
        for (IHttpRequestResponse request : requests) {
            try {
                IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(request);
                String stepType = classifyStepType(reqInfo.getUrl().getPath(), 
                                                 reqInfo.getMethod(), 
                                                 reqInfo.getParameters());
                
                stepTypeOrder.put(stepType, order++);
                
            } catch (Exception e) {
                // Continue
            }
        }
        
        // Check for payment before authentication (suspicious)
        if (stepTypeOrder.containsKey("PAYMENT") && stepTypeOrder.containsKey("AUTHENTICATION")) {
            if (stepTypeOrder.get("PAYMENT") < stepTypeOrder.get("AUTHENTICATION")) {
                callbacks.printOutput("WORKFLOW ANOMALY: Payment before authentication in session: " + sessionId);
            }
        }
    }
    
    // Business Logic Test Functions
    
    private boolean testAuthenticationBypass(UserWorkflow workflow) {
        // Test if authenticated resources can be accessed without authentication
        for (WorkflowStep step : workflow.steps) {
            if (step.stepType.equals("AUTHENTICATION")) {
                // Try to access subsequent steps without authentication
                return testDirectAccess(step);
            }
        }
        return false;
    }
    
    private boolean testAuthorizationBypass(UserWorkflow workflow) {
        // Test if user can access resources meant for other users
        for (WorkflowStep step : workflow.steps) {
            if (step.stepType.equals("ACCOUNT_MANAGEMENT") || step.stepType.equals("ADMINISTRATIVE")) {
                return testParameterManipulation(step);
            }
        }
        return false;
    }
    
    private boolean testPriceManipulation(UserWorkflow workflow) {
        // Test if prices or quantities can be manipulated
        for (WorkflowStep step : workflow.steps) {
            if (step.stepType.equals("PAYMENT")) {
                return testPriceParameterManipulation(step);
            }
        }
        return false;
    }
    
    private boolean testWorkflowBypass(UserWorkflow workflow) {
        // Test if steps can be skipped
        if (workflow.steps.size() > 2) {
            WorkflowStep firstStep = workflow.steps.get(0);
            WorkflowStep lastStep = workflow.steps.get(workflow.steps.size() - 1);
            
            return testSkipToFinalStep(firstStep, lastStep);
        }
        return false;
    }
    
    private boolean testRaceConditions(UserWorkflow workflow) {
        // Test for race conditions in workflows
        for (WorkflowStep step : workflow.steps) {
            if (step.method.equals("POST") || step.method.equals("PUT")) {
                return testConcurrentRequests(step);
            }
        }
        return false;
    }
    
    private boolean testStateManipulation(UserWorkflow workflow) {
        // Test improper state transitions
        return workflow.steps.stream()
                           .anyMatch(this::testStateTransition);
    }
    
    private boolean testPrivilegeEscalation(UserWorkflow workflow) {
        // Test for privilege escalation opportunities
        return workflow.steps.stream()
                           .anyMatch(step -> testPrivilegeEscalationInStep(step));
    }
    
    // Helper test methods (simplified implementations)
    
    private boolean testDirectAccess(WorkflowStep step) {
        // Implementation would test accessing protected resources directly
        return false; // Placeholder
    }
    
    private boolean testParameterManipulation(WorkflowStep step) {
        // Implementation would test changing user IDs or role parameters
        return false; // Placeholder
    }
    
    private boolean testPriceParameterManipulation(WorkflowStep step) {
        // Implementation would test modifying price/quantity parameters
        return false; // Placeholder
    }
    
    private boolean testSkipToFinalStep(WorkflowStep firstStep, WorkflowStep lastStep) {
        // Implementation would test accessing final step directly
        return false; // Placeholder
    }
    
    private boolean testConcurrentRequests(WorkflowStep step) {
        // Implementation would test sending multiple concurrent requests
        return false; // Placeholder
    }
    
    private boolean testStateTransition(WorkflowStep step) {
        // Implementation would test invalid state transitions
        return false; // Placeholder
    }
    
    private boolean testPrivilegeEscalationInStep(WorkflowStep step) {
        // Implementation would test privilege escalation in step
        return false; // Placeholder
    }
    
    private String extractSessionIdentifier(IHttpRequestResponse item) {
        try {
            IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(item);
            
            // Look for session ID in cookies
            for (IParameter param : reqInfo.getParameters()) {
                if (param.getType() == IParameter.PARAM_COOKIE) {
                    String name = param.getName().toLowerCase();
                    if (name.contains("session") || name.contains("jsession") || 
                        name.contains("phpsess") || name.contains("aspnet")) {
                        return param.getValue();
                    }
                }
            }
            
            // Fallback to client IP
            return reqInfo.getUrl().getHost();
            
        } catch (Exception e) {
            return null;
        }
    }
    
    private void reportBusinessLogicFlaw(UserWorkflow workflow, BusinessLogicTest test) {
        callbacks.printOutput(String.format(
            "BUSINESS LOGIC FLAW DETECTED: %s in workflow '%s' - %s", 
            test.testType, workflow.name, test.description
        ));
    }
    
    public void showWorkflowMap() {
        StringBuilder report = new StringBuilder();
        report.append("BUSINESS WORKFLOW MAP\n");
        report.append("=====================\n\n");
        
        Map<String, List<UserWorkflow>> workflowsByType = new HashMap<>();
        
        for (UserWorkflow workflow : identifiedWorkflows.values()) {
            workflowsByType.computeIfAbsent(workflow.type, k -> new ArrayList<>()).add(workflow);
        }
        
        for (Map.Entry<String, List<UserWorkflow>> entry : workflowsByType.entrySet()) {
            report.append(entry.getKey()).append(" WORKFLOWS:\n");
            
            for (UserWorkflow workflow : entry.getValue()) {
                report.append("  - ").append(workflow.name).append(" (")
                      .append(workflow.steps.size()).append(" steps)\n");
                
                for (int i = 0; i < workflow.steps.size() && i < 5; i++) {
                    WorkflowStep step = workflow.steps.get(i);
                    report.append("    ").append(i + 1).append(". ")
                          .append(step.stepType).append(" - ")
                          .append(step.method).append(" ").append(step.path).append("\n");
                }
                
                if (workflow.steps.size() > 5) {
                    report.append("    ... (").append(workflow.steps.size() - 5)
                          .append(" more steps)\n");
                }
                report.append("\n");
            }
            report.append("\n");
        }
        
        if (identifiedWorkflows.isEmpty()) {
            report.append("No workflows mapped yet. Monitor user traffic to identify business logic flows.\n");
        } else {
            report.append("Total workflows identified: ").append(workflowCount.get()).append("\n");
            report.append("Business logic tests performed: ").append(testedFlows.get()).append("\n");
            report.append("Logic flaws detected: ").append(businessLogicTests.size()).append("\n");
        }
        
        callbacks.printOutput(report.toString());
    }
    
    // Supporting data classes
    
    private static class UserWorkflow {
        public String name;
        public String type;
        public List<WorkflowStep> steps;
    }
    
    private static class WorkflowStep {
        public String url;
        public String path;
        public String method;
        public String stepType;
        public List<IParameter> parameters;
    }
    
    private static class BusinessLogicTest {
        public String testType;
        public String description;
        public java.util.function.Function<UserWorkflow, Boolean> testFunction;
        
        public BusinessLogicTest(String testType, String description, 
                                java.util.function.Function<UserWorkflow, Boolean> testFunction) {
            this.testType = testType;
            this.description = description;
            this.testFunction = testFunction;
        }
    }
}