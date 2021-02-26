package b4dpxl.tabhighlighter;

import b4dpxl.Utilities;
import burp.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.net.URL;
import java.util.List;
import java.util.*;

public class Highlighter implements IContextMenuFactory, IExtensionStateListener {

    public static final String NAME = "Repeater Tab Highlighter Test";
    public static final String CONFIG_URL = "http://tabhighlighterextensionjava.local/state";

    TabIndexPCL tabListener;

    private JTabbedPane repeater = null;

    /**
     * Called by registerExtenderCallbacks()
     * @param callbacks
     */
    public Highlighter(IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);

        for (Frame frame : Frame.getFrames()) {
            find_repeater(frame);
        }
        if (repeater == null) {
            Utilities.err("ERROR: Unable to locate Repeater");
            return;
        }

        Utilities.callbacks.registerExtensionStateListener(this);
        Utilities.callbacks.registerContextMenuFactory(this);

        repeater.addPropertyChangeListener("indexForTabComponent", tabListener = new TabIndexPCL());
        loadSettings();

    }

    class TabIndexPCL implements PropertyChangeListener {

        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            if ((int)evt.getNewValue() >= 0) {
                delayedSave(2000);
            }
        }

    }

    private void find_repeater(Container container) {
        if (container.getComponents() != null && this.repeater == null) {
            if (container instanceof Frame && ((Frame)container).getTitle().equalsIgnoreCase("Burp Repeater")) {
                // TODO find popped out Repeater
            }
            for (Component c : container.getComponents()) {
                try {
                    if (c instanceof JTabbedPane) {
                        JTabbedPane t = (JTabbedPane)c;
                        for (int x = 0; x < t.getTabCount(); x++) {
                            if (t.getTitleAt(x).equalsIgnoreCase("Repeater")) {
                                this.repeater = (JTabbedPane) t.getComponentAt(x);
                                Utilities.debug("Found repeater :)");
                                return;
                            }
                        }
                    }
                } catch (Exception e) {
                }
                if (c instanceof Container) {
                    find_repeater((Container) c);
                }
            }
        }
    }

    private void loadSettings() {
        IHttpRequestResponse[] requestResponse = Utilities.callbacks.getSiteMap(CONFIG_URL);
        if (requestResponse.length > 0 && requestResponse[0].getResponse() != null) {
            Utilities.debug("loading colours");
            byte[] response = requestResponse[0].getResponse();
            IResponseInfo responseInfo = Utilities.helpers.analyzeResponse(response);
            int len = response.length - responseInfo.getBodyOffset();
            byte[] body = new byte[len];
            System.arraycopy(response, responseInfo.getBodyOffset(), body, 0, len);

            try {
                ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(body));
                ObjectInputStream ois = new ObjectInputStream(bais);
                List<Highlight> tabs = (List<Highlight>)ois.readObject();

                for (int i=0; i<tabs.size(); i++) {
                    if (tabs.get(i) != null) {
                        highlightTab(tabs.get(i), i, true);
                    }
                }

            } catch (IOException | ClassNotFoundException e) {
                Utilities.err("Unable to deserialize settings", e);

            }
        }
    }

    private boolean hasDelayedSave = false;
    private void delayedSave(int delay) {
        if (hasDelayedSave) {
            return;
        }
        hasDelayedSave = true;
        new java.util.Timer().schedule(
                new java.util.TimerTask() {
                    @Override
                    public void run() {
                        saveSettings();
                        hasDelayedSave = false;
                    }
                },
                delay
        );
    }

    List<Highlight> previousSettings = null;
    private void saveSettings() {
        saveSettings(false);
    }

    int count = 0;

    private ConfigStoreRequestResponse config = null;

    private void saveSettings(boolean force) {
        List<Highlight> settings = new ArrayList<>();
        // grab the default tab colour from the "..." tab:
        Container newTabTab = (Container)repeater.getTabComponentAt(repeater.getTabCount()-1);
        if (newTabTab == null) {
            // in some transition state, probably due to drag'n'drop. Don't save this.
            Utilities.debug("newTabTab is null");
            return;
        }
        Color baseColour = newTabTab.getComponent(0).getForeground();
        // loop through the tabs
        for (int idx=0; idx<repeater.getTabCount()-1; idx++) {
            Container tab = (Container)repeater.getTabComponentAt(idx);
            if (tab == null) {
                // in some transition state, probably due to drag'n'drop. Don't save this.
                Utilities.debug("tab " + idx + " is null");
                return;
            }
            JTextField tabLabel = (JTextField)tab.getComponent(0);
            Color tabColour = tabLabel.getForeground();
            int tabStyle = tabLabel.getFont().getStyle();
            if (tabColour.equals(baseColour)) {
                // not highlighted, ignore it. This should handle theme changes
                settings.add(null);
            } else {
                settings.add(new Highlight(tabColour, tabStyle));
            }
        }
        if (force || previousSettings == null || ! previousSettings.equals(settings)) {
            // only save if the values have actually changed
            Utilities.debug("Saving colours");
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);
                oos.writeObject(settings);
                oos.close();
                String serialized = Base64.getEncoder().encodeToString(baos.toByteArray());
                if (config == null) {
                    config = new ConfigStoreRequestResponse(new URL(CONFIG_URL), serialized);
                } else {
                    // trying a reset because sometimes it doesn't save otherwise :|
                    config.setValue("NOTHING TO SEE HERE!!!");
                    config.saveToProject();
                    config.setValue(serialized);
                }
                config.saveToProject();

                previousSettings = settings;
            } catch (IOException e) {
                Utilities.err("Unable to serialize settings", e);
            }
        }
    }

    private void highlightTab(Highlight highlight) {
        highlightTab(highlight, -1);
    }

    private void highlightTab(Highlight highlight, int idx) {
        highlightTab(highlight, idx, false);
    }

    private void highlightTab(Highlight highlight, int idx, boolean doNotSave) {
        try {
            if (idx < 0) {
                idx = repeater.getSelectedIndex();
            }
            boolean changed = false;
            boolean hasListener = false;

            Container tab = (Container) repeater.getTabComponentAt(idx);
            JTextField tabLabel = (JTextField) tab.getComponent(0);

            if (!tabLabel.getForeground().equals(highlight.getColor())) {
                changed = true;
                // "disable" the listener before making this change
                for (PropertyChangeListener l : tabLabel.getPropertyChangeListeners("disabledTextColor")) {
                    if (l instanceof TabStylePCL) {
                        ((TabStylePCL) l).setHighlight(highlight);
                        hasListener = true;
                        break;
                    }
                }
                repeater.setBackgroundAt(idx, highlight.getColor());
            }

            Font newFont = tabLabel.getFont().deriveFont(highlight.getStyle());
            if (!tabLabel.getFont().equals(newFont)) {
                changed = true;
                tabLabel.setFont(newFont);
            }

            if (changed) {
                Utilities.debug("Tab highlighted");
                if (!doNotSave) {
                    saveSettings();
                }

                // create a listener if we don't have one already.
                if (! hasListener) {
                    tabLabel.addPropertyChangeListener("disabledTextColor", new TabStylePCL(tabLabel, highlight));
                }

            }
        } catch (Exception e) {
            Utilities.err("highlightTab error", e);
        }
    }

    class TabStylePCL implements PropertyChangeListener {

        private JTextField label;
        private Highlight highlight;
        private boolean deliberateChange = false;

        public TabStylePCL(JTextField label, Highlight highlight) {
            this.label = label;
            this.highlight = highlight;
            Utilities.debug("New listener");
        }

        public void setHighlight(Highlight highlight) {
            this.highlight = highlight;
            this.deliberateChange = true;
            Utilities.debug("Updating highlight");
        }

        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            if (deliberateChange) {
                deliberateChange = false;
                return;
            }

            // dirty hack with a delay to revert the colours, because this event sometimes fires too soon :|
            new java.util.Timer().schedule(
                    new TimerTask() {
                        @Override
                        public void run() {
                            deliberateChange = true;
                            label.setForeground(highlight.getColor());
                            label.setDisabledTextColor(highlight.getColor());
                            delayedSave(2000);
                        }
                    },
                    100
            );
        }

    }

    @Override
    public void extensionUnloaded() {
        // remove all listeners
        if (tabListener != null) {
            repeater.removePropertyChangeListener(tabListener);
        }
        for (int idx=0; idx<repeater.getTabCount()-1; idx++) {
            Component tabLabel = ((Container) repeater.getTabComponentAt(idx)).getComponent(0);
            for (PropertyChangeListener pcl : tabLabel.getPropertyChangeListeners()) {
                if (pcl instanceof TabStylePCL) {
                    tabLabel.removePropertyChangeListener(pcl);

                }
            }
        }
        saveSettings(true);
        Utilities.debug("Unloaded "+NAME);
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (invocation.getToolFlag() != Utilities.callbacks.TOOL_REPEATER) {
            return null;
        }

        JMenu subMenu = new JMenu("Highlight Tab");
        subMenu.add(createMenuItem("Red", new Color(255, 50, 0)));
        subMenu.add(createMenuItem("Blue", new Color(102, 153, 255)));
        subMenu.add(createMenuItem("Green", new Color(0, 204, 51)));
        subMenu.add(createMenuItem("Orange", new Color(255, 204, 51)));
        subMenu.add(createMenuItem("Purple", new Color(204, 51, 255)));
        subMenu.add(createMenuItem("None", null));

        if (Utilities.isDebug()) {
            subMenu.add(new JSeparator());
            JMenuItem save = new JMenuItem("Save now");
            save.addActionListener(new SaveMenuListener());
            save.setFont(save.getFont().deriveFont(Font.ITALIC));
            subMenu.add(save);
        }

        List<JMenuItem> menu = new ArrayList<>();
        menu.add(subMenu);
        return menu;
    }

    private JMenuItem createMenuItem(String name, Color colour) {
        if (colour != null) {
            JMenu subSubMenu = new JMenu(name);
            subSubMenu.setForeground(colour);
            subSubMenu.add(createMenuItemStyled("Normal", colour, Font.PLAIN));
            subSubMenu.add(createMenuItemStyled("Bold", colour, Font.BOLD));
            subSubMenu.add(createMenuItemStyled("Italic", colour, Font.ITALIC));
            return subSubMenu;
        } else {
            JMenuItem menu = new JMenuItem(name);
            menu.addActionListener(new HighlightMenuListener(null, Font.PLAIN));
            return menu;
        }
    }

    private JMenuItem createMenuItemStyled(String name, Color colour, int style) {
        JMenuItem item = new JMenuItem(name);
        item.setFont(item.getFont().deriveFont(style));
        item.addActionListener(new HighlightMenuListener(colour, style));
        return item;
    }

    private class HighlightMenuListener implements ActionListener {

        private Highlight highlight;

        public HighlightMenuListener(Color colour, int style) {
            this.highlight = new Highlight(colour, style);
        }

        public void actionPerformed(ActionEvent e) {
            highlightTab(highlight);
        }

    }

    private class SaveMenuListener implements ActionListener {

        public void actionPerformed(ActionEvent e) {
            saveSettings(true);
        }
    }

}

class Highlight implements Serializable {

    boolean isNullColour;  // we use null colours to reset to the default, but java.awt.Color isn't serializable
    int colourRGB;
    int style;

    public Highlight(Color colour, int style) {
        this.colourRGB = colour == null ? 0 : colour.getRGB();
        isNullColour = colour == null;
        this.style = style;
    }

    public Color getColor() {
        return isNullColour ? null : new Color(colourRGB);
    }

    public int getStyle() {
        return style;
    }

    public String toString() {
        return getColor() + " " + style;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Highlight highlight = (Highlight) o;
        return isNullColour == highlight.isNullColour && colourRGB == highlight.colourRGB && style == highlight.style;
    }

    @Override
    public int hashCode() {
        return Objects.hash(isNullColour, colourRGB, style);
    }
}