package com.burpmcp.ui;

import burp.api.montoya.core.ToolType;
import com.burpmcp.config.LoggingConfig;
import com.burpmcp.db.LogStore;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * "Logger MCP" suite tab: an "All tools" master toggle plus a per-tool toggle and purge button
 * for each tracked tool, a purge-everything button, the MCP endpoint, and a live storage readout.
 * Only the request-originating tools (LoggingConfig.TRACKED_TOOLS) are shown.
 */
public class ConfigPanel extends JPanel {

    private final Map<String, JCheckBox> toolBoxes = new LinkedHashMap<>();
    private final LogStore store;
    private final JLabel storageLabel = new JLabel();

    public ConfigPanel(LogStore store, LoggingConfig config, String serverUrl,
                       boolean persist, Consumer<Boolean> onPersistChange) {
        this.store = store;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JLabel header = new JLabel("Burp Logger MCP");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 16f));
        JLabel sub = new JLabel("MCP endpoint: " + serverUrl);

        JCheckBox persistBox = new JCheckBox("Persist logs to disk (keep after Burp closes)", persist);
        persistBox.setToolTipText("When off, this project's log database is deleted when the extension "
                + "unloads (Burp close / project switch). Logs still work normally during the session.");
        persistBox.addActionListener(e -> onPersistChange.accept(persistBox.isSelected()));

        JPanel top = new JPanel(new GridLayout(4, 1));
        top.add(header);
        top.add(sub);
        top.add(storageLabel);
        top.add(persistBox);
        add(top, BorderLayout.NORTH);

        JPanel grid = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;

        Map<String, Boolean> snap = config.snapshot();

        // "All tools" master toggle (row 0).
        JCheckBox allBox = new JCheckBox("All tools");
        allBox.setFont(allBox.getFont().deriveFont(Font.BOLD));
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
                updateStorage();
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
        JButton purgeAll = new JButton("Purge ALL Logs / Reset Current Project DB");
        purgeAll.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this,
                    "Delete all logs for this project and compact the database?",
                    "Confirm", JOptionPane.YES_NO_OPTION);
            if (ok == JOptionPane.YES_OPTION) {
                int n = store.purge(null, null);
                updateStorage();
                JOptionPane.showMessageDialog(this, "Deleted " + n + " entries");
            }
        });
        grid.add(purgeAll, c);

        add(new JScrollPane(grid), BorderLayout.CENTER);

        // Destructive cross-project action, isolated at the bottom-right.
        JButton deleteAll = new JButton("Delete ALL Project Databases");
        deleteAll.setToolTipText("Removes the stored logs for EVERY project on disk, not just this one.");
        deleteAll.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this,
                    "Delete the log databases for ALL projects (every project, not just this one)?\n"
                    + "This resets the current project and permanently removes every other project's "
                    + "stored logs from disk.",
                    "Confirm — Affects ALL Projects", JOptionPane.YES_NO_OPTION);
            if (ok == JOptionPane.YES_OPTION) {
                int others = store.deleteOtherProjectDatabases();
                store.purge(null, null); // reset the current (open) project's DB in place
                updateStorage();
                JOptionPane.showMessageDialog(this,
                        "Reset this project and deleted " + others + " other project database(s).");
            }
        });
        JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        south.add(deleteAll);
        add(south, BorderLayout.SOUTH);

        // Live storage readout: refresh now, then every 3s on the EDT.
        updateStorage();
        new javax.swing.Timer(3000, e -> updateStorage()).start();
    }

    private void updateStorage() {
        storageLabel.setText("Storage used: " + LogStore.humanBytes(store.dbSizeBytes()));
    }

    /** True only if every tracked tool's box is checked. */
    private boolean allSelected() {
        for (JCheckBox cb : toolBoxes.values()) if (!cb.isSelected()) return false;
        return !toolBoxes.isEmpty();
    }
}
