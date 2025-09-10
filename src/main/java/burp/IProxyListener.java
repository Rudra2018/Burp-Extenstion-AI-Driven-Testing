package burp;

/**
 * Standard Burp Suite proxy listener interface
 */
public interface IProxyListener {
    void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message);
}