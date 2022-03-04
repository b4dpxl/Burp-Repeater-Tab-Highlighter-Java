package b4dpxl.tabhighlighter;

import b4dpxl.Utilities;
import burp.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.font.TextAttribute;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.net.URL;
import java.util.List;
import java.util.*;

public class Highlighter implements IContextMenuFactory, IExtensionStateListener {

    public static final String NAME = "Tab Highlighter";
    public static final String CONFIG_URL = "http://tabhighlighterextensionjava.local/state";

    TabIndexPCL tabListener;

    private JTabbedPane repeater = null;

    /**
     * Called by registerExtenderCallbacks()
     * @param callbacks
     */
    public Highlighter(IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks, false);
        Utilities.callbacks.setExtensionName(NAME);

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

        private boolean alive = true;

        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            if (!alive) {
                return;
            }
            if ((int)evt.getNewValue() >= 0) {
                delayedSave(2000);
            }
        }

        // sometimes listeners don't get removed when unloading the extension. This will at least kill it off.
        public void kill(Component owner) {
            this.alive = false;
            owner.removePropertyChangeListener(this);
        }

    }

    private void find_repeater(Container container) {
        if (container.getComponents() != null && this.repeater == null) {
            try {
                if (container instanceof JRootPane) {
                    JMenuBar menubar = ((JRootPane) container).getJMenuBar();
                    if (menubar != null && menubar.getMenu(0).getText().equalsIgnoreCase("Repeater")) {
                        if (((JRootPane) container).getContentPane().getComponent(0) instanceof JTabbedPane) {
                            this.repeater = (JTabbedPane) ((JRootPane) container).getContentPane().getComponent(0);
                            Utilities.debug("Found detached Repeater");
                            return;
                        }
                    }
                }

                for (Component c : container.getComponents()) {
                    if (c instanceof JTabbedPane) {
                        JTabbedPane t = (JTabbedPane)c;
                        for (int x = 0; x < t.getTabCount(); x++) {
                            if (t.getTitleAt(x).equalsIgnoreCase("Repeater")) {
                                Component component = t.getComponentAt(x);
                                if (component instanceof JTabbedPane) {
                                    this.repeater = (JTabbedPane) component;
                                    Utilities.debug("Found repeater :)");

                                } else if (component instanceof JPanel) {
                                    this.repeater = (JTabbedPane) ((JPanel)component).getComponent(0);
                                    Utilities.debug("Found repeater :)");

                                } else {
                                    Utilities.err("Swing structure does not match known structure");
                                }
                                return;
                            }
                        }
                    }
                    if (c instanceof Container) {
                        find_repeater((Container) c);
                    }
                }
            } catch (Exception e) {
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
                Utilities.err("Unable to deserialize settings. Version incompatibility?");

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
            boolean struck = false;
            if (tabLabel.getFont().getAttributes().containsKey(TextAttribute.STRIKETHROUGH)) {
                Boolean v =(Boolean)(tabLabel.getFont().getAttributes().get(TextAttribute.STRIKETHROUGH));
                struck = v == null ? false : v.booleanValue();
            }
            if (tabColour.equals(baseColour)) {
                // not highlighted, ignore it. This should handle theme changes
                settings.add(null);
            } else {
                settings.add(new Highlight(tabColour, tabStyle, struck));
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

            Font tmpFont = tabLabel.getFont().deriveFont(highlight.getStyle());
            Map fontAttributes = tmpFont.getAttributes();
            fontAttributes.put(TextAttribute.STRIKETHROUGH, highlight.isStrikethrough());
            Font newFont = tmpFont.deriveFont(fontAttributes);
            if (!tabLabel.getFont().equals(newFont)) {
                changed = true;
                tabLabel.setFont(newFont);
            }

            if (changed) {
//                Utilities.debug("Tab highlighted");
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

        private boolean alive = true;
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
            // make sure the listener is inactive if it wasn't removed cleanly
            if (!alive) {
                return;
            }

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

        public void kill(Component owner) {
            alive = false;
            owner.removePropertyChangeListener(this);
        }

    }

    @Override
    public void extensionUnloaded() {
        // remove all listeners
        if (tabListener != null) {
            tabListener.kill(repeater);
        }
        for (int idx=0; idx<repeater.getTabCount()-1; idx++) {
            Component tabLabel = ((Container) repeater.getTabComponentAt(idx)).getComponent(0);
            for (PropertyChangeListener pcl : tabLabel.getPropertyChangeListeners()) {
                if (pcl instanceof TabStylePCL) {
                    ((TabStylePCL)pcl).kill(tabLabel);

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

        List<JMenuItem> subMenu = new ArrayList<>();

        subMenu.add(createMenuItem("1: Red", new Color(255, 50, 0)));
        subMenu.add(createMenuItem("2: Blue", new Color(102, 153, 255)));
        subMenu.add(createMenuItem("3: Green", new Color(0, 204, 51)));
        subMenu.add(createMenuItem("4: Orange", new Color(255, 204, 51)));
        subMenu.add(createMenuItem("5: Purple", new Color(204, 51, 255)));
        subMenu.add(createMenuItem("99: None", null));

        if (Utilities.isDebug()) {
            Utilities.debug("Adding debug options");
//            subMenu.add(new JSeparator());
            JMenuItem save = new JMenuItem("Save now");
            save.addActionListener(new SaveMenuListener());
            save.setFont(save.getFont().deriveFont(Font.ITALIC));
            subMenu.add(save);
        }

        return subMenu;
    }

    private JMenuItem createMenuItem(String name, Color colour) {
        if (colour != null) {
            JMenu subSubMenu = new JMenu(name);
            subSubMenu.setForeground(colour);
            subSubMenu.add(createMenuItemStyled("Normal", colour, Font.PLAIN, false));
            subSubMenu.add(createMenuItemStyled("Bold", colour, Font.BOLD, false));
            subSubMenu.add(createMenuItemStyled("Italic", colour, Font.ITALIC, false));
            subSubMenu.add(createMenuItemStyled("Strike", colour, Font.PLAIN, true));
            return subSubMenu;
        } else {
            JMenuItem menu = new JMenuItem(name);
            menu.addActionListener(new HighlightMenuListener(null, Font.PLAIN, false));
            return menu;
        }
    }

    private JMenuItem createMenuItemStyled(String name, Color colour, int style, boolean strikethrough) {
        JMenuItem item = new JMenuItem(name);
        Font styledFont = item.getFont().deriveFont(style);
        if (strikethrough) {
            Map attributes = styledFont.getAttributes();
            attributes.put(TextAttribute.STRIKETHROUGH, TextAttribute.STRIKETHROUGH_ON);
            styledFont = styledFont.deriveFont(attributes);
        }
        item.setFont(styledFont);
        item.addActionListener(new HighlightMenuListener(colour, style, strikethrough));
        return item;
    }

    private class HighlightMenuListener implements ActionListener {

        private Highlight highlight;

        public HighlightMenuListener(Color colour, int style, boolean strikethrough) {
            this.highlight = new Highlight(colour, style, strikethrough);
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
    boolean strikethrough;

    public Highlight(Color colour, int style, boolean strikethrough) {
        this.colourRGB = colour == null ? 0 : colour.getRGB();
        isNullColour = colour == null;
        this.style = style;
        this.strikethrough = strikethrough;
    }

    public Color getColor() {
        return isNullColour ? null : new Color(colourRGB);
    }

    public int getStyle() {
        return style;
    }

    public boolean isStrikethrough() { return strikethrough; }

    public String toString() {
        return getColor() + " " + style + " " + strikethrough;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Highlight otherHighlight = (Highlight) o;
        return isNullColour == otherHighlight.isNullColour && colourRGB == otherHighlight.colourRGB && style == otherHighlight.style && strikethrough == otherHighlight.strikethrough;
    }

    @Override
    public int hashCode() {
        return Objects.hash(isNullColour, colourRGB, style);
    }
}