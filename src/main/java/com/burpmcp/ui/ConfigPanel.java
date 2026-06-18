package com.burpmcp.ui;

import burp.api.montoya.core.ToolType;
import com.burpmcp.config.LoggingConfig;
import com.burpmcp.db.LogStore;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * "Logger MCP" suite tab: an "All tools" master toggle plus a per-tool toggle and purge button
 * for each tracked tool, and a purge-everything button. Only the request-originating tools
 * (LoggingConfig.TRACKED_TOOLS) are shown.
 */
public class ConfigPanel extends JPanel {

    private final Map<String, JCheckBox> toolBoxes = new LinkedHashMap<>();

    public ConfigPanel(LogStore store, LoggingConfig config, String serverUrl) {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JLabel header = new JLabel("Burp Logger MCP");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 16f));
        JLabel sub = new JLabel("MCP endpoint: " + serverUrl);
        JPanel top = new JPanel(new GridLayout(2, 1));
        top.add(header);
        top.add(sub);
        add(top, BorderLayout.NORTH);

        JPanel grid = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;

        Map<String, Boolean> snap = config.snapshot();

        // "All tools" master toggle (row 0).
        JCheckBox allBox = new JCheckBox("All tools");
        Font f = allBox.getFont();
        allBox.setFont(f.deriveFont(Font.BOLD));
        c.gridx = 0; c.gridy = 0;
        grid.add(allBox, c);

        // One row per tracked tool.
        int row = 1;
        for (ToolType t : LoggingConfig.TRACKED_TOOLS) {
            final String tool = t.name();
            c.gridx = 0; c.gridy = row;
            JCheckBox cb = new JCheckBox(tool, snap.getOrDefault(tool, false));
            cb.addActionListener(e -> {
                config.setEnabled(tool, cb.isSelected());
                allBox.setSelected(allSelected()); // does not fire allBox's own listener
            });
            toolBoxes.put(tool, cb);
            grid.add(cb, c);

            c.gridx = 1;
            JButton purge = new JButton("Purge " + tool);
            purge.addActionListener(e -> {
                int n = store.purge(tool, null);
                JOptionPane.showMessageDialog(this, "Deleted " + n + " entries from " + tool);
            });
            grid.add(purge, c);
            row++;
        }

        // Master toggle reflects + drives all per-tool boxes.
        allBox.setSelected(allSelected());
        allBox.addActionListener(e -> {
            boolean on = allBox.isSelected();
            for (Map.Entry<String, JCheckBox> en : toolBoxes.entrySet()) {
                en.getValue().setSelected(on);   // programmatic: doesn't fire per-tool listener
                config.setEnabled(en.getKey(), on);
            }
        });

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        JButton purgeAll = new JButton("Purge ALL logs");
        purgeAll.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this,
                    "Delete every log entry?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (ok == JOptionPane.YES_OPTION) {
                int n = store.purge(null, null);
                JOptionPane.showMessageDialog(this, "Deleted " + n + " entries");
            }
        });
        grid.add(purgeAll, c);

        add(new JScrollPane(grid), BorderLayout.CENTER);
    }

    /** True only if every tracked tool's box is checked. */
    private boolean allSelected() {
        for (JCheckBox cb : toolBoxes.values()) if (!cb.isSelected()) return false;
        return !toolBoxes.isEmpty();
    }
}
