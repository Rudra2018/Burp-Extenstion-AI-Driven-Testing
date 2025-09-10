package burp;

import java.awt.Component;

/**
 * Standard Burp Suite tab interface
 */
public interface ITab {
    String getTabCaption();
    Component getUiComponent();
}