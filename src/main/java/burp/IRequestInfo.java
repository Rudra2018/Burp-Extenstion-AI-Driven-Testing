package burp;

import java.net.URL;
import java.util.List;

/**
 * Burp Suite request info interface
 */
public interface IRequestInfo {
    String getMethod();
    URL getUrl();
    List<String> getHeaders();
    List<IParameter> getParameters();
    byte getContentType();
    int getBodyOffset();
}