package com.secure.ai.burp;

import burp.*;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Simplified AI Security Extension for Burp Suite
 * Demonstrates core functionality without complex dependencies
 */
public class SimpleBurpAIExtension implements IBurpExtender, ITab, IProxyListener {
    
    private static final String EXTENSION_NAME = "AI Security Extension";
    private static final String VERSION = "2.0.0";
    
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // UI Components
    private JPanel mainPanel;
    private JTextArea logArea;
    private JLabel statsLabel;
    private JButton startStopButton;
    
    // Statistics
    private final AtomicInteger requestsProcessed = new AtomicInteger(0);
    private final AtomicInteger responsesProcessed = new AtomicInteger(0);
    private final AtomicInteger anomaliesDetected = new AtomicInteger(0);
    private volatile boolean isActive = true;
    
    // Simple anomaly detection
    private final ConcurrentHashMap<String, Integer> suspiciousPatterns = new ConcurrentHashMap<>();
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        // Set up output streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME + " v" + VERSION);
        
        // Initialize suspicious patterns for simple ML-like detection
        initializeSuspiciousPatterns();
        
        // Create UI
        initializeUI();
        
        // Register as proxy listener
        callbacks.registerProxyListener(this);
        
        // Register this as a suite tab
        callbacks.addSuiteTab(this);
        
        // Print success message
        stdout.println(String.format(
            "%s v%s initialized successfully!\n" +
            "Features enabled:\n" +
            "  ✓ Real-time traffic analysis\n" +
            "  ✓ Pattern-based anomaly detection\n" +
            "  ✓ Suspicious payload identification\n" +
            "  ✓ Live monitoring dashboard\n" +
            "\nCheck the 'AI Security' tab for the dashboard.",
            EXTENSION_NAME, VERSION
        ));
        
        logMessage("AI Security Extension started successfully!");
    }
    
    private void initializeSuspiciousPatterns() {
        // SQL Injection patterns
        suspiciousPatterns.put("' OR '1'='1", 10);
        suspiciousPatterns.put("UNION SELECT", 10);
        suspiciousPatterns.put("'; DROP TABLE", 10);
        suspiciousPatterns.put("' AND 1=1", 8);
        suspiciousPatterns.put("' UNION ALL", 9);
        
        // XSS patterns
        suspiciousPatterns.put("<script>", 10);
        suspiciousPatterns.put("javascript:", 8);
        suspiciousPatterns.put("onerror=", 7);
        suspiciousPatterns.put("onload=", 7);
        suspiciousPatterns.put("alert(", 6);
        
        // Command Injection patterns
        suspiciousPatterns.put("; cat /etc/passwd", 10);
        suspiciousPatterns.put("| whoami", 8);
        suspiciousPatterns.put("&& dir", 7);
        suspiciousPatterns.put("`id`", 8);
        
        // Path Traversal patterns
        suspiciousPatterns.put("../../../", 9);
        suspiciousPatterns.put("..\\\\..\\\\", 9);
        suspiciousPatterns.put("%2e%2e%2f", 8);
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        
        // Top panel with controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startStopButton = new JButton("Stop Monitoring");
        startStopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                toggleMonitoring();
            }
        });
        controlPanel.add(startStopButton);
        
        JButton clearLogButton = new JButton("Clear Log");
        clearLogButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logArea.setText("");
            }
        });
        controlPanel.add(clearLogButton);
        
        mainPanel.add(controlPanel, BorderLayout.NORTH);
        
        // Statistics panel
        JPanel statsPanel = new JPanel(new GridLayout(1, 3));
        statsPanel.setBorder(new TitledBorder("Live Statistics"));
        
        statsLabel = new JLabel("Requests: 0 | Responses: 0 | Anomalies: 0");
        statsLabel.setHorizontalAlignment(SwingConstants.CENTER);
        statsPanel.add(statsLabel);
        
        mainPanel.add(statsPanel, BorderLayout.CENTER);
        
        // Log area
        logArea = new JTextArea(15, 60);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(new TitledBorder("Security Analysis Log"));
        mainPanel.add(scrollPane, BorderLayout.SOUTH);
        
        // Start stats update timer
        Timer statsTimer = new Timer(1000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateStatsDisplay();
            }
        });
        statsTimer.start();
    }
    
    private void toggleMonitoring() {
        isActive = !isActive;
        startStopButton.setText(isActive ? "Stop Monitoring" : "Start Monitoring");
        logMessage(isActive ? "Monitoring resumed" : "Monitoring paused");
    }
    
    private void updateStatsDisplay() {
        SwingUtilities.invokeLater(() -> {
            statsLabel.setText(String.format(
                "Requests: %d | Responses: %d | Anomalies: %d",
                requestsProcessed.get(),
                responsesProcessed.get(),
                anomaliesDetected.get()
            ));
        });
    }
    
    private void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = java.time.LocalTime.now().toString().substring(0, 8);
            logArea.append("[" + timestamp + "] " + message + "\\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!isActive) return;
        
        try {
            if (messageIsRequest) {
                processRequest(message);
            } else {
                processResponse(message);
            }
        } catch (Exception e) {
            stderr.println("Error processing proxy message: " + e.getMessage());
        }
    }
    
    private void processRequest(IInterceptedProxyMessage message) {
        requestsProcessed.incrementAndGet();
        
        IHttpRequestResponse requestResponse = message.getMessageInfo();
        if (requestResponse == null || requestResponse.getRequest() == null) return;
        
        String request = new String(requestResponse.getRequest());
        
        // Simple anomaly detection
        int suspiciousScore = 0;
        StringBuilder detectedPatterns = new StringBuilder();
        
        for (String pattern : suspiciousPatterns.keySet()) {
            if (request.toLowerCase().contains(pattern.toLowerCase())) {
                suspiciousScore += suspiciousPatterns.get(pattern);
                if (detectedPatterns.length() > 0) detectedPatterns.append(", ");
                detectedPatterns.append(pattern);
            }
        }
        
        if (suspiciousScore > 5) { // Threshold for anomaly
            anomaliesDetected.incrementAndGet();
            String host = requestResponse.getHttpService() != null ? 
                requestResponse.getHttpService().getHost() : "unknown";
            
            logMessage(String.format(
                "🚨 ANOMALY DETECTED: %s (Score: %d) - Patterns: [%s]",
                host, suspiciousScore, detectedPatterns.toString()
            ));
        } else if (suspiciousScore > 0) {
            String host = requestResponse.getHttpService() != null ? 
                requestResponse.getHttpService().getHost() : "unknown";
            logMessage(String.format(
                "⚠️ Suspicious activity: %s (Score: %d) - Patterns: [%s]",
                host, suspiciousScore, detectedPatterns.toString()
            ));
        }
    }
    
    private void processResponse(IInterceptedProxyMessage message) {
        responsesProcessed.incrementAndGet();
        
        IHttpRequestResponse requestResponse = message.getMessageInfo();
        if (requestResponse == null || requestResponse.getResponse() == null) return;
        
        String response = new String(requestResponse.getResponse());
        
        // Check for common error patterns that might indicate successful attacks
        if (response.contains("SQL syntax error") || 
            response.contains("mysql_fetch") ||
            response.contains("ORA-") ||
            response.contains("Microsoft JET Database")) {
            
            anomaliesDetected.incrementAndGet();
            String host = requestResponse.getHttpService() != null ? 
                requestResponse.getHttpService().getHost() : "unknown";
            logMessage(String.format(
                "🔥 SQL ERROR DETECTED: %s - Possible SQL injection vulnerability!",
                host
            ));
        }
        
        // Check for XSS reflection
        if (response.contains("<script>") || response.contains("javascript:")) {
            anomaliesDetected.incrementAndGet();
            String host = requestResponse.getHttpService() != null ? 
                requestResponse.getHttpService().getHost() : "unknown";
            logMessage(String.format(
                "⚡ XSS REFLECTION: %s - Possible XSS vulnerability!",
                host
            ));
        }
    }
    
    @Override
    public String getTabCaption() {
        return "AI Security";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}