package burp;

import java.net.URL;

/**
 * Burp Suite extension helpers interface
 */
public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(IHttpRequestResponse request);
    IRequestInfo analyzeRequest(IHttpService httpService, byte[] request);
    IRequestInfo analyzeRequest(byte[] request);
    IResponseInfo analyzeResponse(byte[] response);
    IParameter getRequestParameter(byte[] request, String parameterName);
    byte[] updateParameter(byte[] request, IParameter parameter);
    byte[] addParameter(byte[] request, IParameter parameter);
    byte[] removeParameter(byte[] request, IParameter parameter);
    String urlDecode(String data);
    String urlEncode(String data);
    byte[] base64Decode(String data);
    byte[] base64Decode(byte[] data);
    String base64Encode(String data);
    String base64Encode(byte[] data);
    byte[] stringToBytes(String data);
    String bytesToString(byte[] data);
    int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to);
    byte[] buildHttpRequest(URL url);
    IHttpService buildHttpService(String host, int port, boolean useHttps);
    IHttpService buildHttpService(String host, int port, String protocol);
}