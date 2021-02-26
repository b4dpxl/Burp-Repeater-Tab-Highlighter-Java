package b4dpxl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

import javax.swing.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;

public class Utilities {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private static boolean debug = false;

    public Utilities(final IBurpExtenderCallbacks _callbacks) {
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    public Utilities(final IBurpExtenderCallbacks _callbacks, boolean _debug) {
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        debug = _debug;
    }

    public static void debug(String _message) {
        if (debug) {
            stdout.println(_message);
        }
    }
    public static void debug(Object _obj) {
        if (debug) {
            stdout.println(_obj.toString());
        }
    }
    public static void println(String _message) {
        stdout.println(_message);
    }
    public static void println(Object _obj) {
        stdout.println(_obj.toString());
    }
    public static void err(String _message) {
        stderr.println(_message);
    }
    public static void err(String _message, Exception _e) {
        stderr.println(_message);
        _e.printStackTrace(stderr);
    }

    public static void alert(String _message) {
        JOptionPane.showMessageDialog(null,
                _message,
                "Error",
                JOptionPane.ERROR_MESSAGE
        );
    }
    public static void alert(String _message, Exception _e) {
        JOptionPane.showMessageDialog(null,
                _message + "\n\n" + _e.getMessage(),
                "Error",
                JOptionPane.ERROR_MESSAGE
        );
        _e.printStackTrace(stderr);
    }

    public static URL getURL(IScanIssue _issue) throws MalformedURLException {
        URL url = _issue.getUrl();
        if (
                (url.getProtocol().equalsIgnoreCase("HTTPS") && url.getPort() == 443) ||
                (url.getProtocol().equalsIgnoreCase("HTTP") && url.getPort() == 80)
        ) {
            url = new URL(url.getProtocol(), url.getHost(), url.getPath());
        }
        return url;
    }

    public static String getResponse(IScanIssue _issue) {
        IHttpRequestResponse requestResponse = _issue.getHttpMessages()[0];
        byte[] response = requestResponse.getResponse();
        return new String(Arrays.copyOfRange(
                response,
                helpers.analyzeResponse(response).getBodyOffset(),
                response.length
        ));
    }

    public static String[] splitHeader(String header) {
        if (!header.contains(":")) {
            return new String[]{header, null};
        }
        String name = header.substring(0, header.indexOf(":")).trim();
        String value = header.substring(header.indexOf(":")+1).trim();
        return new String[]{name, value};
    }

    public static void enableDebug() {
        debug = true;
    }

    public static void disableDebug() {
        debug = false;
    }

    public static boolean isDebug() {
        return debug;
    }
}
