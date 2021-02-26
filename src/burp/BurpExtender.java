package burp;

import b4dpxl.tabhighlighter.Highlighter;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        new Highlighter(callbacks);

    }

}
