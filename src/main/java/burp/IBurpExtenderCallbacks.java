package burp;

import java.io.OutputStream;

/**
 * Standard Burp Suite extension callbacks interface
 */
public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    void registerProxyListener(IProxyListener listener);
    void addSuiteTab(ITab tab);
    OutputStream getStdout();
    OutputStream getStderr();
    void printOutput(String output);
    void printError(String error);
}