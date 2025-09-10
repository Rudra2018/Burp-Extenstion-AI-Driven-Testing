package burp;

/**
 * Standard Burp Suite extension interface
 * This interface must be implemented by all Burp Suite extensions
 */
public interface IBurpExtender {
    /**
     * This method is invoked when the extension is loaded
     * @param callbacks An object that exposes the Burp Suite APIs available to extensions
     */
    void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
}