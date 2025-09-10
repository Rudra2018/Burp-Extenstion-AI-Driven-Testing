package burp;

/**
 * Standard Burp Suite HTTP service interface
 */
public interface IHttpService {
    String getHost();
    int getPort();
    String getProtocol();
}