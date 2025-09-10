package burp;

import java.util.List;

/**
 * Burp Suite response info interface
 */
public interface IResponseInfo {
    List<String> getHeaders();
    int getBodyOffset();
    short getStatusCode();
    String getInferredMimeType();
    List<String> getCookies();
}