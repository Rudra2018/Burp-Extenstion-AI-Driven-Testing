# 🤖 AI-Powered Security Extension for Burp Suite

[![Version](https://img.shields.io/badge/version-2.0.0--dual-blue.svg)](https://github.com/Rudra2018/Burp-Extenstion-AI-Driven-Testing)
[![Java](https://img.shields.io/badge/java-11%2B-orange.svg)](https://openjdk.java.net/projects/jdk/11/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional%2FCommunity-red.svg)](https://portswigger.net/burp)
[![API](https://img.shields.io/badge/API-Legacy%20%2B%20Montoya-green.svg)](https://portswigger.net/burp/documentation/desktop/extensions/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A dual-compatible AI-powered security extension that supports both **Legacy Burp API** and **Montoya API** patterns, providing comprehensive security analysis, pattern recognition, and vulnerability detection for modern penetration testing workflows.

## 🎯 Features

### 🔄 **Dual API Compatibility**
- **Legacy Burp API**: Full support for IBurpExtender, IProxyListener, ITab
- **Montoya API Patterns**: Modern request/response handlers and lifecycle management
- **Seamless Migration**: Side-by-side comparison of API approaches
- **Backward Compatibility**: Works with all Burp Suite versions

### 🛡️ **AI-Powered Security Analysis**
- **Pattern Recognition**: SQL injection, XSS, authentication bypass detection
- **Security Event Tracking**: Comprehensive audit trail with ConcurrentHashMap storage
- **Real-time Processing**: Multi-threaded analysis with ExecutorService
- **Statistical Analysis**: Anomaly detection based on response patterns

### 🔍 **Advanced Traffic Monitoring**
- **Proxy Interception**: Real-time HTTP request/response analysis
- **Performance Metrics**: Request/response/vulnerability counters
- **Background Processing**: Non-blocking security analysis
- **Memory Efficient**: Optimized data structures for high-traffic scenarios

### 🖥️ **Modern UI Components**
- **Tabbed Interface**: Organized dashboard with real-time statistics
- **API Comparison**: Side-by-side Legacy vs Montoya feature comparison
- **Migration Guide**: Built-in documentation for API transitions
- **Live Logging**: Real-time security event display

### ⚡ **Performance Optimized**
- **Concurrent Processing**: Thread-safe security analysis
- **Intelligent Caching**: Efficient pattern matching and storage
- **Resource Management**: Automatic cleanup and memory optimization
- **Scalable Architecture**: Handles high-volume traffic analysis

## 📦 Installation

### Prerequisites

- **Java 11 or higher** (Java 17+ recommended for optimal performance)
- **Burp Suite Professional or Community Edition**
- **2GB+ RAM** recommended for concurrent processing
- **Multi-core CPU** recommended for background analysis

### Quick Installation

#### Method 1: Download Pre-built JAR (Recommended)

1. **Download the latest release**:
   ```bash
   # Download from GitHub Releases
   wget https://github.com/Rudra2018/Burp-Extenstion-AI-Driven-Testing/releases/download/v2.0.0-dual/ai-burp-extension-pro-2.0.0-enterprise.jar
   ```

2. **Install in Burp Suite**:
   - Open Burp Suite
   - Go to `Extensions` → `Installed` 
   - Click `Add`
   - Select `Java` as extension type
   - Browse and select: `ai-burp-extension-pro-2.0.0-enterprise.jar`
   - Click `Next` and then `Close`

3. **Verify Installation**:
   - Look for the "AI Security Extension (Dual-Compatible)" tab
   - Check extension output for initialization messages
   - Status should show: "🔄 DUAL-COMPATIBLE AI SECURITY EXTENSION"

#### Method 2: Build from Source

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Rudra2018/Burp-Extenstion-AI-Driven-Testing.git
   cd Burp-Extenstion-AI-Driven-Testing
   ```

2. **Build the extension**:
   ```bash
   # Using Gradle
   gradle clean build
   
   # The JAR will be created at: build/libs/ai-burp-extension-pro-2.0.0-enterprise.jar
   ```

3. **Install in Burp Suite** (follow steps 2-3 from Method 1)

### First-Time Setup

1. **Launch Burp Suite** with the extension installed
2. **Navigate to the "AI Security Extension (Dual-Compatible)" tab**
3. **Verify Setup**:
   - Extension output should show dual API initialization
   - Legacy API status: "✅ ACTIVE"
   - Montoya Style status: "✅ ACTIVE" or "❌ INACTIVE" (fallback mode)
   - Background processing should start automatically

## 🚀 Usage Guide

### Basic Usage

#### 1. **Automatic Security Analysis**
- **Configure your browser** to use Burp Suite proxy (usually 127.0.0.1:8080)
- **Browse your target application** normally
- **Monitor the extension tab** for real-time security analysis
- **Check statistics** for processed requests and detected vulnerabilities
- **Review security events** in the logging area

#### 2. **Extension Features**

**Three Extension Variants Available:**
- **DualCompatibleAIExtension**: Main extension with both API patterns
- **SimpleBurpAIExtension**: Legacy API demonstration
- **SimpleMontoyaExtension**: Modern API patterns showcase

**Real-time Monitoring:**
- HTTP request/response interception
- Pattern-based vulnerability detection
- Statistical anomaly detection
- Performance metrics tracking

#### 3. **API Comparison & Migration**

**Legacy API Features:**
- Traditional IBurpExtender implementation
- IProxyListener for traffic interception
- ITab interface for UI integration

**Montoya-Style Features:**
- Modern request/response handlers
- Enhanced HTTP editor providers
- Extension lifecycle management
- Theme-aware UI components

## 📊 Extension Architecture

### **Built-in Extensions**

The JAR contains **three complete extension implementations**:

1. **DualCompatibleAIExtension.java** - Main dual-compatible extension
2. **SimpleBurpAIExtension.java** - Legacy API demonstration  
3. **SimpleMontoyaExtension.java** - Montoya patterns showcase

### **Core Components**

- **Security Analysis Engine**: Pattern recognition and threat detection
- **Multi-threaded Processing**: Concurrent request/response analysis
- **Statistical Monitoring**: Performance metrics and anomaly detection
- **UI Framework**: Tabbed interface with real-time updates
- **Event Logging**: Comprehensive security event tracking

### **Technical Specifications**

- **Language**: Java 11+
- **Threading**: ExecutorService with configurable thread pools
- **Data Structures**: ConcurrentHashMap for thread-safe operations
- **UI Framework**: Swing with custom components
- **Memory Management**: Efficient caching and cleanup

## 🔧 Configuration

### **Extension Settings**

The extension includes built-in configuration options:

- **Thread Pool Size**: Configurable concurrent processing threads
- **Queue Capacity**: Maximum pending analysis requests
- **Analysis Timeout**: Request processing timeout settings  
- **Logging Level**: Adjustable verbosity for debugging
- **UI Refresh Rate**: Dashboard update intervals

## 🔧 Troubleshooting

### Common Issues

#### **Extension Not Loading**
- Verify Java 11+ compatibility
- Check extension output tab for error messages
- Ensure JAR file is not corrupted

#### **Performance Issues**
- Reduce thread pool size in high-traffic scenarios
- Monitor memory usage in Burp Suite
- Check extension logs for processing bottlenecks

#### **API Compatibility Issues**  
- Legacy API should always work (IBurpExtender)
- Montoya-style features may fall back gracefully
- Check extension output for API initialization status

### Getting Help

1. Check the extension **Output** and **Errors** tabs in Burp Suite
2. Look for initialization and processing logs
3. Report issues with full logs and system information

## 📈 Understanding Results

### **Security Analysis Output**

The extension provides security analysis through several mechanisms:

- **Real-time Pattern Detection**: Identifies suspicious patterns in HTTP traffic
- **Statistical Anomaly Detection**: Flags unusual request/response characteristics  
- **Security Event Logging**: Comprehensive logging of potential threats
- **Performance Metrics**: Request processing and vulnerability detection statistics

### **Interpreting Results**

- **High Confidence Detections**: Clear security patterns requiring immediate review
- **Statistical Anomalies**: Unusual traffic patterns that may indicate attacks
- **Security Events**: Logged incidents with timestamps and details
- **Performance Data**: Processing throughput and resource utilization

## 🤝 Contributing

We welcome contributions to improve the dual-compatible AI security extension!

### **Development Setup**

```bash
git clone https://github.com/Rudra2018/Burp-Extenstion-AI-Driven-Testing.git
cd Burp-Extenstion-AI-Driven-Testing
gradle build
```

### **Contribution Areas**
- API compatibility improvements
- Security pattern detection enhancements
- UI/UX improvements
- Performance optimizations
- Documentation updates

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/Rudra2018/Burp-Extenstion-AI-Driven-Testing/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Rudra2018/Burp-Extenstion-AI-Driven-Testing/discussions)

---

**⚡ Enhance your security testing with dual-compatible AI-driven intelligence!** 

*For questions, support, or contributions, please visit our [GitHub repository](https://github.com/Rudra2018/Burp-Extenstion-AI-Driven-Testing).*