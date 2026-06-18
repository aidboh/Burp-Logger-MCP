package com.burpmcp.ui;

import burp.api.montoya.core.ToolType;
import com.burpmcp.config.LoggingConfig;
import com.burpmcp.db.LogStore;

import javax.swing.*;
import java.awt.*;
import java.util.Map;

/** Minimal "Logger MCP" suite tab: toggle logging per tool, purge per tool, show server URL. */
public class ConfigPanel extends JPanel {

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

        int row = 0;
        Map<String, Boolean> snap = config.snapshot();
        for (ToolType t : ToolType.values()) {
            final String tool = t.name();
            c.gridx = 0; c.gridy = row;
            JCheckBox cb = new JCheckBox(tool, snap.getOrDefault(tool, false));
            cb.addActionListener(e -> config.setEnabled(tool, cb.isSelected()));
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
}
