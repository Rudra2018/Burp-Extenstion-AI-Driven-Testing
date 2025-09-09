# 📦 Installation Guide - AI-Driven Security Extension v2.0.0

## 🚀 Quick Installation (5 minutes)

### **Step 1: Download the Extension**
```bash
# Download the latest release JAR file
wget https://github.com/your-repo/ai-burp-extension/releases/download/v2.0.0/ai-security-extension-2.0.0.jar

# Or download directly from GitHub Releases page
```

### **Step 2: Install in Burp Suite**

1. **Open Burp Suite** (Professional or Community Edition)
2. **Navigate to Extensions**:
   - Go to `Extensions` → `Installed`
3. **Add Extension**:
   - Click `Add`
   - Select `Java` as extension type
   - Browse and select: `ai-security-extension-2.0.0.jar`
   - Click `Next` → `Close`

### **Step 3: Verify Installation**
- Look for **"AI-Driven Security Tester"** tab in Burp Suite
- Status should show: **🟢 AI Security System: Active**
- Check extension output for initialization messages

## 🔧 System Requirements

### **Minimum Requirements**
- **Java**: 11+ (Java 17+ recommended)
- **Burp Suite**: Professional or Community Edition (latest version)
- **RAM**: 4GB+ available memory
- **CPU**: Multi-core processor
- **Storage**: 1GB+ free space
- **Network**: Internet connection (initial setup only)

### **Recommended Configuration**
- **Java**: OpenJDK 17+
- **RAM**: 8GB+ system memory
- **CPU**: 4+ cores, 2.5GHz+
- **Storage**: SSD with 2GB+ free space
- **Network**: Stable internet connection

## 🛠️ Detailed Installation Process

### **Pre-Installation Checklist**

1. **Verify Java Version**:
   ```bash
   java -version
   # Should show Java 11+ (OpenJDK recommended)
   ```

2. **Check Burp Suite Version**:
   - Ensure you're running a recent version of Burp Suite
   - Update to latest version if needed

3. **System Resources**:
   ```bash
   # Check available RAM
   free -h  # Linux
   vm_stat  # macOS
   
   # Check disk space
   df -h
   ```

### **Installation Steps**

#### **Method 1: Direct Installation (Recommended)**

1. **Download Extension JAR**:
   ```bash
   # Using wget
   wget -O ai-security-extension-2.0.0.jar \
     "https://github.com/your-repo/ai-burp-extension/releases/download/v2.0.0/ai-security-extension-2.0.0.jar"
   
   # Using curl
   curl -L -o ai-security-extension-2.0.0.jar \
     "https://github.com/your-repo/ai-burp-extension/releases/download/v2.0.0/ai-security-extension-2.0.0.jar"
   ```

2. **Verify Download**:
   ```bash
   # Check file size (should be ~50-100MB)
   ls -lh ai-security-extension-2.0.0.jar
   
   # Verify it's a valid JAR
   file ai-security-extension-2.0.0.jar
   ```

3. **Install in Burp Suite**:
   - Launch Burp Suite
   - Go to `Extensions` → `Installed`
   - Click `Add` button
   - Select `Java` as extension type
   - Browse to downloaded JAR file
   - Click `Next` → `Close`

#### **Method 2: Build from Source**

1. **Clone Repository**:
   ```bash
   git clone https://github.com/your-repo/ai-burp-extension.git
   cd Burp-Extenstion-AI-Driven-Testing
   ```

2. **Build Extension**:
   ```bash
   # Ensure Java 11+ and Gradle are installed
   ./gradlew clean shadowJar
   
   # JAR will be created at: build/libs/ai-security-extension-2.0.0.jar
   ```

3. **Install Built JAR**:
   - Follow installation steps from Method 1
   - Use the JAR from `build/libs/` directory

### **Post-Installation Setup**

#### **First Launch Configuration**

1. **Navigate to AI Extension Tab**:
   - Look for **"AI-Driven Security Tester"** in Burp Suite tabs
   - Click to open the extension interface

2. **Initial System Check**:
   - **Dashboard**: Should show "🟢 AI Security System: Active"
   - **ML Models**: May show "🟡 Models: Loading..." initially
   - **Nuclei Integration**: "Installing Nuclei..." on first run

3. **Wait for Initialization** (2-5 minutes):
   - ML models download and initialize
   - Nuclei binary downloads and installs
   - Template database updates
   - System performs self-checks

4. **Verify Components**:
   - **Dashboard**: All green status indicators
   - **ML Models**: "🟢 Models: Ready"
   - **Real-time Analysis**: Tables ready for data
   - **Configuration**: Default settings loaded

## ⚙️ Configuration

### **Initial Configuration**

1. **Navigate to Configuration Tab**
2. **Set Detection Sensitivity** (recommended: 7/10):
   - **1-3**: Conservative (fewer false positives)
   - **4-6**: Balanced (general use)
   - **7-10**: Aggressive (maximum detection)

3. **Enable/Disable Features**:
   - ✅ **ML-based Detection**: Core AI functionality
   - ✅ **Anomaly Detection**: Behavioral analysis
   - ✅ **Nuclei Integration**: Template scanning
   - ✅ **Pattern Learning**: Adaptive learning

4. **Click "Save Configuration"**

### **Advanced Configuration**

#### **Performance Tuning**
```yaml
# For high-traffic environments
Analysis Threads: 6-8
Queue Capacity: 15000
Vulnerability Threshold: 0.8

# For low-resource systems  
Analysis Threads: 2
Queue Capacity: 5000
Vulnerability Threshold: 0.6
```

#### **Memory Optimization**
```bash
# Increase JVM heap size for Burp Suite
java -Xmx8g -jar burpsuite.jar

# Or set environment variable
export JAVA_OPTS="-Xmx8g -XX:+UseG1GC"
```

## 🔍 Verification & Testing

### **Basic Functionality Test**

1. **Configure Browser Proxy**:
   - Set browser proxy to `127.0.0.1:8080`
   - Ensure Burp Suite proxy is running

2. **Test Real-time Analysis**:
   ```bash
   # Browse to a test application
   # Example: http://testphp.vulnweb.com/
   
   # Expected Results:
   # - Request count increases in Dashboard
   # - No errors in extension output
   # - Real-time Analysis tab shows activity
   ```

3. **Test Nuclei Integration**:
   - Go to **Nuclei Integration** tab
   - Enter test URL: `http://testphp.vulnweb.com/`
   - Click **"Start Comprehensive Scan"**
   - Wait for scan completion
   - Review results

4. **Test ML Detection**:
   ```bash
   # Send test XSS payload through proxy
   curl -x http://127.0.0.1:8080 \
     "http://testapp.com/search?q=<script>alert('test')</script>"
   
   # Check Real-time Analysis for XSS detection
   ```

### **Performance Verification**

1. **Monitor System Resources**:
   ```bash
   # Check CPU usage (should be <70% sustained)
   top -p $(pgrep -f burp)
   
   # Check memory usage (should be <6GB)
   ps aux | grep burp
   ```

2. **Check Extension Logs**:
   - Go to `Extensions` → `Installed`
   - Select AI Security Extension
   - Review `Output` and `Errors` tabs
   - Look for initialization success messages

## 🚨 Troubleshooting

### **Common Issues**

#### **"Extension not loading"**
```bash
# Solutions:
1. Verify Java version: java -version
2. Check JAR file integrity
3. Review Burp Suite extension errors
4. Clear extension cache and restart
5. Increase JVM heap size: -Xmx8g
```

#### **"Models not loading"**
```bash
# Solutions:
1. Check internet connection
2. Verify firewall/proxy settings
3. Clear model cache: ~/.ai-security-extension/
4. Check available RAM (4GB+ required)
5. Wait 5 minutes for complete initialization
```

#### **"Nuclei installation failed"**
```bash
# Solutions:
1. Check internet connectivity
2. Verify write permissions
3. Whitelist in antivirus software
4. Manual install: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
5. Set NUCLEI_PATH environment variable
```

#### **"High memory usage"**
```bash
# Solutions:
1. Reduce analysis threads (Configuration tab)
2. Lower detection sensitivity
3. Increase JVM heap: java -Xmx8g -jar burpsuite.jar
4. Clear caches periodically
5. Disable unused features
```

### **Advanced Troubleshooting**

#### **Enable Debug Logging**
```bash
# Add to Burp Suite startup
-Dlogging.level.com.secure.ai.burp=DEBUG
```

#### **Reset Configuration**
```bash
# Delete configuration files
rm -rf ~/.ai-security-extension/config/
# Restart Burp Suite to recreate defaults
```

#### **Performance Profiling**
```bash
# Monitor extension performance
jconsole # Connect to Burp Suite process
# Monitor memory, CPU, threading
```

## 📞 Getting Help

### **Support Resources**

- 📖 **Documentation**: [GitHub Wiki](https://github.com/your-repo/ai-burp-extension/wiki)
- 💬 **Community Support**: [GitHub Discussions](https://github.com/your-repo/ai-burp-extension/discussions)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/your-repo/ai-burp-extension/issues)
- 🎥 **Video Tutorials**: [YouTube Playlist](https://youtube.com/playlist/ai-burp-tutorials)

### **Enterprise Support**

- 📧 **Enterprise Help**: enterprise@ai-security-extension.com
- 🎓 **Training Programs**: Professional training available
- 🏢 **Custom Installation**: White-glove installation service
- 🔧 **Custom Configuration**: Tailored setup for enterprise environments

## ✅ **Installation Complete!**

Your AI-Driven Security Testing Extension is now ready to use.

**Next Steps:**
1. ✅ Browse your target application through Burp proxy
2. ✅ Monitor real-time vulnerabilities in the extension tab
3. ✅ Run comprehensive Nuclei scans
4. ✅ Review adaptive learning patterns
5. ✅ Configure sensitivity based on your needs

**🎯 Happy Security Testing!**

---

*For technical issues or questions, please visit our [GitHub repository](https://github.com/your-repo/ai-burp-extension) or contact support.*