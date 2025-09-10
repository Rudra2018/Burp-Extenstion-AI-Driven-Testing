package burp;

/**
 * Standard Burp Suite intercepted proxy message interface
 */
public interface IInterceptedProxyMessage {
    int getMessageId();
    boolean isResponse();
    String getListenerInterface();
    IHttpRequestResponse getMessageInfo();
}