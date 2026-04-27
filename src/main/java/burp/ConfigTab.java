package burp;

import burp.api.montoya.MontoyaApi;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.AbstractBorder;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.basic.BasicButtonUI;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.geom.Arc2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Styled configuration tab for the AES Traffic Decryptor extension.
 */
public class ConfigTab {

    private static final Font HEADER_TITLE_FONT = new Font("Arial", Font.BOLD, 20);
    private static final Font HEADER_SUBTITLE_FONT = new Font("Arial", Font.ITALIC, 12);
    private static final Font SECTION_TITLE_FONT = new Font("Arial", Font.BOLD, 16);
    private static final Font FIELD_LABEL_FONT = new Font("Arial", Font.BOLD, 13);
    private static final Font FIELD_FONT = new Font("Arial", Font.PLAIN, 12);
    private static final Font HELP_FONT = new Font("Arial", Font.ITALIC, 11);
    private static final Font ERROR_FONT = new Font("Arial", Font.BOLD, 11);
    private static final Font COUNTER_FONT = new Font("Arial", Font.BOLD, 12);
    private static final Font STATUS_FONT = new Font("Arial", Font.BOLD, 13);
    private static final Font STATUS_DETAIL_FONT = new Font("Arial", Font.PLAIN, 12);
    private static final Font BUTTON_FONT = new Font("Arial", Font.BOLD, 13);

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final JComponent panel;

    public ConfigTab(BurpAesExtension extension, MontoyaApi api) {
        Theme theme = Theme.light();

        JTextField keyField = makeField(theme);
        JTextField ivField = makeField(theme);
        JTextField hostField = makeField(theme);

        keyField.setText(extension.getAesKey());
        ivField.setText(extension.getAesIv());
        hostField.setText(extension.getTargetHost());

        JLabel keyCounter = makeCounterLabel(theme);
        JLabel ivCounter = makeCounterLabel(theme);
        JLabel keyError = makeErrorLabel(theme);
        JLabel ivError = makeErrorLabel(theme);
        JLabel hostError = makeErrorLabel(theme);

        JLabel statusMessage = makeInfoLabel(STATUS_FONT, theme.statusText);
        JLabel configSummary = makeInfoLabel(STATUS_DETAIL_FONT, theme.detailText);
        JLabel lastSaved = makeInfoLabel(STATUS_DETAIL_FONT, theme.detailText);
        JLabel statusDot = makeStatusDot(theme.statusOff);

        StatusChip statusChip = new StatusChip();

        JButton saveBtn = new ActionButton(
                "Save Configuration",
                new SymbolIcon(SymbolIcon.Kind.SAVE, 15, new Color(236, 244, 255)),
                theme);
        JButton clearBtn = new ActionButton(
                "Clear All",
                new SymbolIcon(SymbolIcon.Kind.TRASH, 15, new Color(236, 244, 255)),
                theme);
        JButton testBtn = new ActionButton(
                "Test Encryption",
                new SymbolIcon(SymbolIcon.Kind.KEY, 15, new Color(236, 244, 255)),
                theme);

        saveBtn.setEnabled(false);

        JPanel outer = new JPanel();
        outer.setOpaque(false);
        outer.setLayout(new BoxLayout(outer, BoxLayout.Y_AXIS));
        outer.setBorder(BorderFactory.createEmptyBorder(14, 18, 18, 18));

        outer.add(buildHeaderBar(statusChip, theme));
        outer.add(Box.createRigidArea(new Dimension(0, 10)));

        SectionPanel cryptoSection = new SectionPanel("Cryptographic Configuration", theme);
        addFieldBlock(cryptoSection.content(),
                0,
                new SymbolIcon(SymbolIcon.Kind.KEY, 26, theme.iconStroke),
                "AES Key",
                "(hex):",
                keyField,
                keyCounter,
                "32, 48, or 64 hex characters",
                keyError,
                theme);
        addFieldBlock(cryptoSection.content(),
                3,
                new SymbolIcon(SymbolIcon.Kind.LOCK, 26, theme.iconStroke),
                "IV",
                "(hex):",
                ivField,
                ivCounter,
                "Exactly 32 hex characters (16 bytes)",
                ivError,
                theme);
        outer.add(cryptoSection);
        outer.add(Box.createRigidArea(new Dimension(0, 10)));

        SectionPanel targetSection = new SectionPanel("Target Configuration", theme);
        addFieldBlock(targetSection.content(),
                0,
                new SymbolIcon(SymbolIcon.Kind.SERVER, 26, theme.iconStroke),
                "Target Host",
                ":",
                hostField,
                null,
                "Hostname to match (e.g., api.target.com or localhost)",
                hostError,
                theme);
        outer.add(targetSection);
        outer.add(Box.createRigidArea(new Dimension(0, 10)));

        SectionPanel statusSection = new SectionPanel("Extension Status", theme);
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        statusRow.setOpaque(false);
        statusRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusRow.add(statusDot);
        statusRow.add(statusMessage);

        statusSection.content().setLayout(new BoxLayout(statusSection.content(), BoxLayout.Y_AXIS));
        statusSection.content().add(statusRow);
        statusSection.content().add(Box.createRigidArea(new Dimension(0, 5)));
        statusSection.content().add(configSummary);
        statusSection.content().add(Box.createRigidArea(new Dimension(0, 3)));
        statusSection.content().add(lastSaved);
        outer.add(statusSection);
        outer.add(Box.createRigidArea(new Dimension(0, 10)));

        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        separator.setForeground(theme.divider);
        separator.setAlignmentX(Component.LEFT_ALIGNMENT);
        separator.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        outer.add(separator);
        outer.add(Box.createRigidArea(new Dimension(0, 10)));

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 0));
        buttonBar.setOpaque(false);
        buttonBar.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttonBar.add(saveBtn);
        buttonBar.add(clearBtn);
        buttonBar.add(testBtn);
        outer.add(buttonBar);
        outer.add(Box.createRigidArea(new Dimension(0, 12)));
        outer.add(buildManualCryptoPanel(theme, keyField, ivField));

        JPanel contentPanel = new BackgroundPanel(theme);
        contentPanel.setLayout(new BorderLayout());
        contentPanel.add(outer, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(
                contentPanel,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getViewport().setBackground(theme.panelBg);
        panel = scrollPane;

        final String[] lastSavedText = {
                hasSavedConfig(extension) ? "Loaded saved configuration." : "Last saved: Not yet saved"
        };

        Runnable refresh = () -> {
            String key = keyField.getText().trim();
            String iv = ivField.getText().trim();
            String host = hostField.getText().trim();

            boolean keyValid = validateKey(key, keyError);
            boolean ivValid = validateIv(iv, ivError);
            boolean hostValid = validateHost(host, hostError);
            boolean readyToSave = keyValid && ivValid && hostValid;

            keyCounter.setText(key.isEmpty() ? "0 chars" : key.length() + " chars");
            ivCounter.setText(iv.isEmpty() ? "0 chars" : iv.length() + " chars");
            keyCounter.setForeground(keyValid || key.isEmpty() ? theme.counterText : theme.errorText);
            ivCounter.setForeground(ivValid || iv.isEmpty() ? theme.counterText : theme.errorText);
            saveBtn.setEnabled(readyToSave);

            updateFieldBorder(keyField, keyValid, theme);
            updateFieldBorder(ivField, ivValid, theme);
            updateFieldBorder(hostField, hostValid, theme);

            boolean active = hasSavedConfig(extension);
            if (active) {
                statusChip.setActive(true);
                statusDot.setForeground(theme.statusOn);
                statusMessage.setText("Active \u2014 Extension is configured and ready");
                configSummary.setText("Key: " + abbrev(extension.getAesKey()) + " (" + keyBitLabel(extension.getAesKey())
                        + ") | IV: " + abbrev(extension.getAesIv()) + " | Host: " + extension.getTargetHost());
            } else {
                statusChip.setActive(false);
                statusDot.setForeground(theme.statusOff);
                statusMessage.setText("Not Configured \u2014 Please save valid settings");
                String keySummary = key.isEmpty() ? "not set" : abbrev(key) + " (" + keyBitLabel(key) + ")";
                String ivSummary = iv.isEmpty() ? "not set" : abbrev(iv);
                String hostSummary = host.isEmpty() ? "not set" : host;
                configSummary.setText("Key: " + keySummary + " | IV: " + ivSummary + " | Host: " + hostSummary);
            }
            lastSaved.setText(lastSavedText[0]);
        };

        DocumentListener validator = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                SwingUtilities.invokeLater(refresh);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                SwingUtilities.invokeLater(refresh);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                SwingUtilities.invokeLater(refresh);
            }
        };

        keyField.getDocument().addDocumentListener(validator);
        ivField.getDocument().addDocumentListener(validator);
        hostField.getDocument().addDocumentListener(validator);

        saveBtn.addActionListener(e -> {
            String key = keyField.getText().trim();
            String iv = ivField.getText().trim();
            String host = hostField.getText().trim();

            extension.setAesKey(key);
            extension.setAesIv(iv);
            extension.setTargetHost(host);
            api.persistence().extensionData().setString("aesKey", key);
            api.persistence().extensionData().setString("aesIv", iv);
            api.persistence().extensionData().setString("targetHost", host);

            lastSavedText[0] = "Last saved: " + LocalTime.now().format(TIME_FMT);
            api.logging().logToOutput("AES config saved for host: " + host);
            refresh.run();
        });

        clearBtn.addActionListener(e -> {
            keyField.setText("");
            ivField.setText("");
            hostField.setText("");
            extension.setAesKey("");
            extension.setAesIv("");
            extension.setTargetHost("");
            api.persistence().extensionData().setString("aesKey", "");
            api.persistence().extensionData().setString("aesIv", "");
            api.persistence().extensionData().setString("targetHost", "");

            lastSavedText[0] = "Last saved: Not yet saved";
            refresh.run();
        });

        testBtn.addActionListener(e -> {
            String key = keyField.getText().trim();
            String iv = ivField.getText().trim();

            if (!validateKey(key, null) || !validateIv(iv, null)) {
                JOptionPane.showMessageDialog(
                        panel,
                        "Please enter a valid Key and IV before testing.",
                        "Test Encryption",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }

            try {
                String encrypted = testEncrypt("test", key, iv);
                byte[] roundTrip = testDecrypt(encrypted, key, iv);
                String plain = new String(roundTrip, StandardCharsets.UTF_8);

                JOptionPane.showMessageDialog(
                        panel,
                        "Input plaintext : \"test\"\n"
                                + "Encrypted (B64) : " + encrypted + "\n"
                                + "Round-trip back : \"" + plain + "\"\n\n"
                                + "Cryptographic settings are working correctly.",
                        "Test Encryption \u2014 Success",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                        panel,
                        "Encryption test failed:\n" + ex.getMessage(),
                        "Test Encryption \u2014 Error",
                        JOptionPane.ERROR_MESSAGE);
                api.logging().logToError("Test encryption failed: " + ex.getMessage());
            }
        });

        refresh.run();
    }

    public JComponent getPanel() {
        return panel;
    }

    private static JPanel buildHeaderBar(StatusChip chip, Theme theme) {
        GradientHeaderPanel bar = new GradientHeaderPanel(theme);
        bar.setLayout(new BorderLayout(12, 0));
        bar.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        bar.setPreferredSize(new Dimension(0, 54));
        bar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 54));
        bar.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel titleBlock = new JPanel();
        titleBlock.setOpaque(false);
        titleBlock.setLayout(new BoxLayout(titleBlock, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("AES Traffic Decryptor");
        title.setFont(HEADER_TITLE_FONT);
        title.setForeground(Color.WHITE);

        JLabel subtitle = new JLabel("Transparent AES-CBC decryption, replay, and scan-aware analysis for Burp traffic.");
        subtitle.setFont(HEADER_SUBTITLE_FONT);
        subtitle.setForeground(new Color(213, 221, 232));

        titleBlock.add(title);
        titleBlock.add(Box.createRigidArea(new Dimension(0, 1)));
        titleBlock.add(subtitle);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.setOpaque(false);
        right.add(chip);

        bar.add(titleBlock, BorderLayout.CENTER);
        bar.add(right, BorderLayout.EAST);
        return bar;
    }

    private static JPanel buildManualCryptoPanel(Theme theme,
                                                 JTextField keyField,
                                                 JTextField ivField) {
        JTextArea inputArea = makeManualTextArea(theme, true);
        JTextArea outputArea = makeManualTextArea(theme, false);

        JButton encryptBtn = new ActionButton(
                "Encrypt",
                new SymbolIcon(SymbolIcon.Kind.KEY, 15, new Color(236, 244, 255)),
                theme);
        JButton decryptBtn = new ActionButton(
                "Decrypt",
                new SymbolIcon(SymbolIcon.Kind.LOCK, 15, new Color(236, 244, 255)),
                theme);

        encryptBtn.addActionListener(e -> {
            String key = keyField.getText().trim();
            String iv = ivField.getText().trim();

            if (!validateKey(key, null) || !validateIv(iv, null)) {
                outputArea.setText("Error: Please enter a valid AES key and IV before encrypting.");
                return;
            }

            try {
                outputArea.setText(testEncrypt(inputArea.getText(), key, iv));
                outputArea.setCaretPosition(0);
            } catch (Exception ex) {
                outputArea.setText("Encryption error: " + ex.getMessage());
                outputArea.setCaretPosition(0);
            }
        });

        decryptBtn.addActionListener(e -> {
            String key = keyField.getText().trim();
            String iv = ivField.getText().trim();

            if (!validateKey(key, null) || !validateIv(iv, null)) {
                outputArea.setText("Error: Please enter a valid AES key and IV before decrypting.");
                return;
            }

            try {
                byte[] plaintext = testDecrypt(inputArea.getText().trim(), key, iv);
                outputArea.setText(new String(plaintext, StandardCharsets.UTF_8));
                outputArea.setCaretPosition(0);
            } catch (Exception ex) {
                outputArea.setText("Decryption error: " + ex.getMessage());
                outputArea.setCaretPosition(0);
            }
        });

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 0));
        buttonRow.setOpaque(false);
        buttonRow.add(encryptBtn);
        buttonRow.add(decryptBtn);

        JPanel manualPanel = new JPanel(new GridBagLayout());
        manualPanel.setOpaque(false);
        manualPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        manualPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));

        TitledBorder titledBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(theme.sectionBorder, 1),
                "Manual Encrypt/Decrypt");
        titledBorder.setTitleFont(SECTION_TITLE_FONT);
        titledBorder.setTitleColor(theme.labelText);
        manualPanel.setBorder(BorderFactory.createCompoundBorder(
                titledBorder,
                BorderFactory.createEmptyBorder(8, 10, 10, 10)));

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1.0;
        c.insets = new Insets(0, 0, 5, 0);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        manualPanel.add(makeManualLabel("Input text", theme), c);

        c.gridy = 1;
        c.insets = new Insets(0, 0, 10, 0);
        c.fill = GridBagConstraints.BOTH;
        c.weighty = 0.5;
        manualPanel.add(makeManualScrollPane(inputArea, theme), c);

        c.gridy = 2;
        c.insets = new Insets(0, 0, 10, 0);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weighty = 0;
        manualPanel.add(buttonRow, c);

        c.gridy = 3;
        c.insets = new Insets(0, 0, 5, 0);
        manualPanel.add(makeManualLabel("Output text", theme), c);

        c.gridy = 4;
        c.insets = new Insets(0, 0, 0, 0);
        c.fill = GridBagConstraints.BOTH;
        c.weighty = 0.5;
        manualPanel.add(makeManualScrollPane(outputArea, theme), c);

        return manualPanel;
    }

    private static JLabel makeManualLabel(String text, Theme theme) {
        JLabel label = new JLabel(text);
        label.setFont(FIELD_LABEL_FONT);
        label.setForeground(theme.labelText);
        return label;
    }

    private static JTextArea makeManualTextArea(Theme theme, boolean editable) {
        JTextArea area = new JTextArea(5, 48);
        area.setEditable(editable);
        area.setFont(FIELD_FONT);
        area.setForeground(theme.text);
        area.setCaretColor(theme.text);
        area.setBackground(theme.fieldBg);
        area.setLineWrap(true);
        area.setWrapStyleWord(false);
        area.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        return area;
    }

    private static JScrollPane makeManualScrollPane(JTextArea area, Theme theme) {
        JScrollPane scrollPane = new JScrollPane(area);
        scrollPane.setBorder(fieldBorder(theme.fieldBorder));
        scrollPane.getViewport().setBackground(theme.fieldBg);
        return scrollPane;
    }

    private static void addFieldBlock(JPanel parent,
                                      int baseRow,
                                      Icon icon,
                                      String mainLabel,
                                      String suffixLabel,
                                      JTextField field,
                                      JLabel counter,
                                      String helpText,
                                      JLabel errorLabel,
                                      Theme theme) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = baseRow;
        c.insets = new Insets(0, 0, 0, 0);

        JPanel label = new JPanel(new FlowLayout(FlowLayout.LEFT, 7, 0));
        label.setOpaque(false);
        label.setPreferredSize(new Dimension(230, 28));
        label.setMinimumSize(new Dimension(230, 28));

        JLabel iconLabel = new JLabel(icon);
        iconLabel.setAlignmentY(Component.CENTER_ALIGNMENT);

        JPanel textWrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 2));
        textWrap.setOpaque(false);
        textWrap.setAlignmentY(Component.CENTER_ALIGNMENT);

        JLabel main = new JLabel(mainLabel);
        main.setFont(FIELD_LABEL_FONT);
        main.setForeground(theme.labelText);

        JLabel suffix = new JLabel(" " + suffixLabel);
        suffix.setFont(new Font(FIELD_LABEL_FONT.getName(), Font.PLAIN, FIELD_LABEL_FONT.getSize()));
        suffix.setForeground(theme.labelText);

        textWrap.add(main);
        textWrap.add(suffix);
        label.add(iconLabel);
        label.add(textWrap);

        c.gridx = 0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        parent.add(label, c);

        c.gridx = 1;
        c.insets = new Insets(0, 8, 0, 0);
        c.weightx = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        parent.add(field, c);

        if (counter != null) {
            c.gridx = 2;
            c.insets = new Insets(0, 8, 0, 0);
            c.weightx = 0;
            c.fill = GridBagConstraints.NONE;
            c.anchor = GridBagConstraints.NORTHEAST;
            parent.add(counter, c);
        }

        JTextArea help = makeInfoText(theme, HELP_FONT, theme.helpText);
        help.setText(helpText);
        help.setBorder(BorderFactory.createEmptyBorder(3, 0, 0, 0));

        c.gridx = 1;
        c.gridy = baseRow + 1;
        c.gridwidth = counter != null ? 2 : 1;
        c.insets = new Insets(0, 8, 0, 0);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.weightx = 1.0;
        parent.add(help, c);

        errorLabel.setBorder(BorderFactory.createEmptyBorder(2, 0, 6, 0));
        c.gridy = baseRow + 2;
        c.insets = new Insets(0, 8, 0, 0);
        parent.add(errorLabel, c);
        c.gridwidth = 1;
    }

    private static JTextField makeField(Theme theme) {
        Border normalBorder = fieldBorder(theme.fieldBorder);
        Border focusBorder = fieldBorder(theme.fieldFocus);

        JTextField field = new JTextField();
        field.setFont(FIELD_FONT);
        field.setForeground(theme.text);
        field.setCaretColor(theme.text);
        field.setBackground(theme.fieldBg);
        field.setBorder(normalBorder);
        field.setPreferredSize(new Dimension(420, 28));
        field.setMinimumSize(new Dimension(180, 28));
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        field.setMargin(new Insets(4, 10, 4, 10));

        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                field.setBorder(focusBorder);
            }

            @Override
            public void focusLost(FocusEvent e) {
                field.setBorder(normalBorder);
            }
        });
        return field;
    }

    private static void updateFieldBorder(JTextField field, boolean valid, Theme theme) {
        if (field.getText().trim().isEmpty()) {
            field.setBorder(fieldBorder(field.hasFocus() ? theme.fieldFocus : theme.fieldBorder));
            return;
        }
        field.setBorder(fieldBorder(valid
                ? (field.hasFocus() ? theme.fieldFocus : theme.fieldBorder)
                : theme.errorText));
    }

    private static Border fieldBorder(Color color) {
        return BorderFactory.createCompoundBorder(
                new RoundLineBorder(color, 7),
                BorderFactory.createEmptyBorder(0, 0, 0, 0));
    }

    private static JLabel makeCounterLabel(Theme theme) {
        JLabel label = new JLabel("0 chars");
        label.setFont(COUNTER_FONT);
        label.setForeground(theme.counterText);
        label.setHorizontalAlignment(SwingConstants.RIGHT);
        label.setPreferredSize(new Dimension(82, 28));
        return label;
    }

    private static JLabel makeErrorLabel(Theme theme) {
        JLabel label = new JLabel(" ");
        label.setFont(ERROR_FONT);
        label.setForeground(theme.errorText);
        return label;
    }

    private static JLabel makeStatusDot(Color color) {
        JLabel label = new JLabel("\u25CF");
        label.setFont(new Font("Arial", Font.BOLD, 14));
        label.setForeground(color);
        label.setPreferredSize(new Dimension(16, 16));
        return label;
    }

    private static JLabel makeInfoLabel(Font font, Color color) {
        JLabel label = new JLabel();
        label.setFont(font);
        label.setForeground(color);
        label.setOpaque(false);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setMaximumSize(new Dimension(Integer.MAX_VALUE, label.getPreferredSize().height));
        return label;
    }

    private static JTextArea makeInfoText(Theme theme, Font font, Color color) {
        JTextArea area = new JTextArea();
        area.setFont(font);
        area.setForeground(color);
        area.setOpaque(false);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        area.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        area.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        return area;
    }

    private static boolean validateKey(String key, JLabel errorLabel) {
        if (key.isEmpty()) {
            if (errorLabel != null) errorLabel.setText(" ");
            return false;
        }
        if (!key.matches("[0-9a-fA-F]+")) {
            if (errorLabel != null) errorLabel.setText("Invalid hex characters");
            return false;
        }
        if (key.length() != 32 && key.length() != 48 && key.length() != 64) {
            if (errorLabel != null) errorLabel.setText("Must be 32, 48, or 64 hex chars");
            return false;
        }
        if (errorLabel != null) errorLabel.setText(" ");
        return true;
    }

    private static boolean validateIv(String iv, JLabel errorLabel) {
        if (iv.isEmpty()) {
            if (errorLabel != null) errorLabel.setText(" ");
            return false;
        }
        if (!iv.matches("[0-9a-fA-F]+")) {
            if (errorLabel != null) errorLabel.setText("Invalid hex characters");
            return false;
        }
        if (iv.length() != 32) {
            if (errorLabel != null) errorLabel.setText("Must be exactly 32 hex chars");
            return false;
        }
        if (errorLabel != null) errorLabel.setText(" ");
        return true;
    }

    private static boolean validateHost(String host, JLabel errorLabel) {
        if (host.isEmpty()) {
            if (errorLabel != null) errorLabel.setText(" ");
            return false;
        }
        if (errorLabel != null) errorLabel.setText(" ");
        return true;
    }

    private static boolean hasSavedConfig(BurpAesExtension extension) {
        return !extension.getAesKey().isEmpty()
                && !extension.getAesIv().isEmpty()
                && !extension.getTargetHost().isEmpty();
    }

    private static String abbrev(String value) {
        if (value == null || value.isEmpty()) {
            return "not set";
        }
        return value.length() >= 8
                ? value.substring(0, 4) + "..." + value.substring(value.length() - 4)
                : value;
    }

    private static String keyBitLabel(String hex) {
        switch (hex.length()) {
            case 32:
                return "128-bit";
            case 48:
                return "192-bit";
            case 64:
                return "256-bit";
            default:
                return "?-bit";
        }
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static String testEncrypt(String plaintext, String hexKey, String hexIv) throws Exception {
        byte[] keyBytes = hexToBytes(hexKey);
        byte[] ivBytes = hexToBytes(hexIv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] testDecrypt(String b64Ciphertext, String hexKey, String hexIv) throws Exception {
        byte[] keyBytes = hexToBytes(hexKey);
        byte[] ivBytes = hexToBytes(hexIv);
        byte[] ct = Base64.getDecoder().decode(b64Ciphertext.trim());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));
        return cipher.doFinal(ct);
    }

    private static final class Theme {
        private final Color panelBg;
        private final Color panelGlow;
        private final Color text;
        private final Color labelText;
        private final Color detailText;
        private final Color helpText;
        private final Color errorText;
        private final Color counterText;
        private final Color sectionBorder;
        private final Color sectionShadow;
        private final Color divider;
        private final Color fieldBg;
        private final Color fieldBorder;
        private final Color fieldFocus;
        private final Color statusOn;
        private final Color statusOff;
        private final Color statusText;
        private final Color iconStroke;
        private final Color buttonFill;
        private final Color buttonHover;
        private final Color buttonPressed;
        private final Color buttonBorder;
        private final Color buttonText;
        private final Color buttonDisabled;
        private final Color headerStart;
        private final Color headerEnd;
        private final Color headerAccent;
        private final Color chipBg;
        private final Color chipBorder;

        private Theme(Color panelBg,
                      Color panelGlow,
                      Color text,
                      Color labelText,
                      Color detailText,
                      Color helpText,
                      Color errorText,
                      Color counterText,
                      Color sectionBorder,
                      Color sectionShadow,
                      Color divider,
                      Color fieldBg,
                      Color fieldBorder,
                      Color fieldFocus,
                      Color statusOn,
                      Color statusOff,
                      Color statusText,
                      Color iconStroke,
                      Color buttonFill,
                      Color buttonHover,
                      Color buttonPressed,
                      Color buttonBorder,
                      Color buttonText,
                      Color buttonDisabled,
                      Color headerStart,
                      Color headerEnd,
                      Color headerAccent,
                      Color chipBg,
                      Color chipBorder) {
            this.panelBg = panelBg;
            this.panelGlow = panelGlow;
            this.text = text;
            this.labelText = labelText;
            this.detailText = detailText;
            this.helpText = helpText;
            this.errorText = errorText;
            this.counterText = counterText;
            this.sectionBorder = sectionBorder;
            this.sectionShadow = sectionShadow;
            this.divider = divider;
            this.fieldBg = fieldBg;
            this.fieldBorder = fieldBorder;
            this.fieldFocus = fieldFocus;
            this.statusOn = statusOn;
            this.statusOff = statusOff;
            this.statusText = statusText;
            this.iconStroke = iconStroke;
            this.buttonFill = buttonFill;
            this.buttonHover = buttonHover;
            this.buttonPressed = buttonPressed;
            this.buttonBorder = buttonBorder;
            this.buttonText = buttonText;
            this.buttonDisabled = buttonDisabled;
            this.headerStart = headerStart;
            this.headerEnd = headerEnd;
            this.headerAccent = headerAccent;
            this.chipBg = chipBg;
            this.chipBorder = chipBorder;
        }

        private static Theme light() {
            return new Theme(
                    new Color(248, 248, 247),
                    new Color(255, 255, 255),
                    new Color(38, 44, 54),
                    new Color(42, 47, 55),
                    new Color(46, 46, 46),
                    new Color(76, 76, 76),
                    new Color(198, 73, 64),
                    new Color(123, 123, 123),
                    new Color(186, 186, 186),
                    new Color(0, 0, 0, 14),
                    new Color(216, 216, 216),
                    Color.WHITE,
                    new Color(192, 192, 192),
                    new Color(104, 145, 204),
                    new Color(62, 170, 82),
                    new Color(211, 91, 78),
                    new Color(33, 33, 33),
                    new Color(44, 44, 44),
                    new Color(111, 150, 198),
                    new Color(127, 164, 209),
                    new Color(89, 126, 173),
                    new Color(84, 117, 160),
                    Color.WHITE,
                    new Color(161, 171, 184),
                    new Color(57, 67, 83),
                    new Color(36, 46, 61),
                    new Color(75, 144, 191),
                    new Color(51, 61, 76),
                    new Color(70, 80, 93));
        }
    }

    private static final class BackgroundPanel extends JPanel {
        private final Theme theme;

        private BackgroundPanel(Theme theme) {
            this.theme = theme;
            setOpaque(true);
            setBackground(theme.panelBg);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setPaint(new GradientPaint(0, 0, theme.panelGlow, 0, getHeight(), theme.panelBg));
            g2.fillRect(0, 0, getWidth(), getHeight());

            int glowSize = 280;
            RadialGradientPaint glow = new RadialGradientPaint(
                    new Point(getWidth() / 2, getHeight() - 10),
                    glowSize,
                    new float[]{0f, 1f},
                    new Color[]{new Color(255, 255, 255, 85), new Color(255, 255, 255, 0)});
            g2.setPaint(glow);
            g2.fillOval(getWidth() / 2 - glowSize, getHeight() - glowSize / 2, glowSize * 2, glowSize);

            SymbolIcon sparkle = new SymbolIcon(SymbolIcon.Kind.SPARKLE, 28, new Color(255, 255, 255, 170));
            sparkle.paintIcon(this, g2, getWidth() - 48, getHeight() - 44);
            g2.dispose();
        }
    }

    private static final class GradientHeaderPanel extends JPanel {
        private final Theme theme;

        private GradientHeaderPanel(Theme theme) {
            this.theme = theme;
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int width = getWidth() - 1;
            int height = getHeight() - 1;
            g2.setColor(new Color(0, 0, 0, 16));
            g2.fillRoundRect(0, 2, width, Math.max(0, height - 2), 8, 8);
            g2.setPaint(new GradientPaint(0, 0, theme.headerStart, getWidth(), 0, theme.headerEnd));
            g2.fillRoundRect(0, 0, width, height, 8, 8);
            g2.setColor(new Color(255, 255, 255, 34));
            g2.drawRoundRect(0, 0, width, height, 8, 8);
            g2.setColor(theme.headerAccent);
            g2.fillRect(0, height - 2, getWidth(), 2);
            g2.dispose();

            super.paintComponent(g);
        }
    }

    private static final class SectionPanel extends JPanel {
        private final JPanel content;

        private SectionPanel(String title, Theme theme) {
            setOpaque(false);
            setLayout(new BorderLayout());
            setAlignmentX(Component.LEFT_ALIGNMENT);
            setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
            setBorder(new EmptySectionBorder());

            JPanel shell = new RoundedSectionShell(theme);
            shell.setLayout(new BorderLayout());
            shell.setOpaque(false);
            shell.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JLabel titleLabel = new JLabel(title);
            titleLabel.setFont(SECTION_TITLE_FONT);
            titleLabel.setForeground(theme.labelText);

            content = new JPanel(new GridBagLayout());
            content.setOpaque(false);
            content.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));

            shell.add(titleLabel, BorderLayout.NORTH);
            shell.add(content, BorderLayout.CENTER);
            add(shell, BorderLayout.CENTER);
        }

        private JPanel content() {
            return content;
        }
    }

    private static final class EmptySectionBorder extends AbstractBorder {
        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(0, 0, 0, 0);
        }
    }

    private static final class RoundedSectionShell extends JPanel {
        private final Theme theme;

        private RoundedSectionShell(Theme theme) {
            this.theme = theme;
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int width = getWidth() - 1;
            int height = getHeight() - 1;
            Shape shape = new RoundRectangle2D.Double(0, 0, width, height, 12, 12);

            g2.setColor(theme.sectionShadow);
            g2.fill(new RoundRectangle2D.Double(0, 2, width, Math.max(0, height - 2), 12, 12));
            g2.setColor(Color.WHITE);
            g2.fill(shape);
            g2.setColor(theme.sectionBorder);
            g2.draw(shape);
            g2.dispose();

            super.paintComponent(g);
        }
    }

    private static final class RoundLineBorder extends AbstractBorder {
        private final Color color;
        private final int arc;

        private RoundLineBorder(Color color, int arc) {
            this.color = color;
            this.arc = arc;
        }

        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(1, 1, 1, 1);
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(color);
            g2.drawRoundRect(x, y, width - 1, height - 1, arc, arc);
            g2.dispose();
        }
    }

    private static final class ActionButton extends JButton {
        private final Theme theme;

        private ActionButton(String text, Icon icon, Theme theme) {
            super(text, icon);
            this.theme = theme;
            setUI(new BasicButtonUI());
            setOpaque(false);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setRolloverEnabled(true);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setHorizontalAlignment(SwingConstants.CENTER);
            setHorizontalTextPosition(SwingConstants.RIGHT);
            setIconTextGap(7);
            setFont(BUTTON_FONT);
            setForeground(theme.buttonText);
            setPreferredSize(new Dimension(228, 34));
            setMinimumSize(new Dimension(228, 34));
            setMaximumSize(new Dimension(228, 34));
            setMargin(new Insets(0, 18, 0, 18));
            setBorder(BorderFactory.createEmptyBorder(0, 18, 0, 18));
        }

        @Override
        public void updateUI() {
            setUI(new BasicButtonUI());
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            ButtonModel model = getModel();
            Color fill = !isEnabled()
                    ? theme.buttonDisabled
                    : model.isPressed()
                    ? theme.buttonPressed
                    : model.isRollover()
                    ? theme.buttonHover
                    : theme.buttonFill;

            int width = getWidth() - 1;
            int height = getHeight() - 1;
            g2.setColor(new Color(0, 0, 0, isEnabled() ? 18 : 8));
            g2.fillRoundRect(0, 2, width, Math.max(0, height - 2), 9, 9);
            g2.setColor(fill);
            g2.fillRoundRect(0, 0, width, height, 9, 9);
            g2.setPaint(new GradientPaint(
                    0, 0, new Color(255, 255, 255, isEnabled() ? 30 : 0),
                    0, getHeight(), new Color(0, 0, 0, isEnabled() ? 10 : 0)));
            g2.fillRoundRect(0, 0, width, height, 9, 9);
            g2.dispose();

            setForeground(theme.buttonText);
            super.paintComponent(g);
        }

        @Override
        protected void paintBorder(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(theme.buttonBorder);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 9, 9);
            g2.dispose();
        }
    }

    private static final class StatusChip extends JComponent {
        private boolean active;

        private StatusChip() {
            setPreferredSize(new Dimension(40, 36));
            setMinimumSize(new Dimension(40, 36));
            setMaximumSize(new Dimension(40, 36));
            setToolTipText("Status");
        }

        private void setActive(boolean active) {
            this.active = active;
            setToolTipText(active ? "Configured" : "Not configured");
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Theme theme = Theme.light();
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int width = getWidth() - 1;
            int height = getHeight() - 1;
            g2.setColor(new Color(0, 0, 0, 28));
            g2.fillRoundRect(0, 2, width, Math.max(0, height - 2), 6, 6);
            g2.setColor(theme.chipBg);
            g2.fillRoundRect(0, 0, width, height, 6, 6);
            g2.setColor(theme.chipBorder);
            g2.drawRoundRect(0, 0, width, height, 6, 6);

            Color powerColor = active ? theme.statusOn : theme.statusOff;
            SymbolIcon icon = new SymbolIcon(SymbolIcon.Kind.POWER, 17, powerColor);
            icon.paintIcon(this, g2, (getWidth() - 17) / 2, (getHeight() - 17) / 2);
            g2.dispose();
        }
    }

    private static final class SymbolIcon implements Icon {
        private enum Kind {
            KEY,
            LOCK,
            SERVER,
            SAVE,
            TRASH,
            POWER,
            SPARKLE
        }

        private final Kind kind;
        private final int size;
        private final Color color;

        private SymbolIcon(Kind kind, int size, Color color) {
            this.kind = kind;
            this.size = size;
            this.color = color;
        }

        @Override
        public int getIconWidth() {
            return size;
        }

        @Override
        public int getIconHeight() {
            return size;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.translate(x, y);
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
            g2.setColor(color);

            switch (kind) {
                case KEY:
                    paintKey(g2);
                    break;
                case LOCK:
                    paintLock(g2);
                    break;
                case SERVER:
                    paintServer(g2);
                    break;
                case SAVE:
                    paintSave(g2);
                    break;
                case TRASH:
                    paintTrash(g2);
                    break;
                case POWER:
                    paintPower(g2);
                    break;
                case SPARKLE:
                    paintSparkle(g2);
                    break;
                default:
                    break;
            }
            g2.dispose();
        }

        private void paintKey(Graphics2D g2) {
            float s = size / 26f;
            g2.setStroke(new BasicStroke(2.0f * s, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawOval(Math.round(2 * s), Math.round(2 * s), Math.round(10 * s), Math.round(10 * s));
            g2.drawLine(Math.round(10 * s), Math.round(10 * s), Math.round(22 * s), Math.round(22 * s));
            g2.drawLine(Math.round(18 * s), Math.round(18 * s), Math.round(18 * s), Math.round(24 * s));
            g2.drawLine(Math.round(21 * s), Math.round(21 * s), Math.round(21 * s), Math.round(25 * s));
            g2.drawLine(Math.round(16 * s), Math.round(20 * s), Math.round(22 * s), Math.round(20 * s));
        }

        private void paintLock(Graphics2D g2) {
            float s = size / 26f;
            g2.setStroke(new BasicStroke(2.0f * s, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawRoundRect(Math.round(4 * s), Math.round(11 * s), Math.round(18 * s), Math.round(12 * s), Math.round(3 * s), Math.round(3 * s));
            g2.draw(new Arc2D.Double(7 * s, 4 * s, 12 * s, 12 * s, 30, 120, Arc2D.OPEN));
            g2.drawLine(Math.round(13 * s), Math.round(15 * s), Math.round(13 * s), Math.round(19 * s));
        }

        private void paintServer(Graphics2D g2) {
            float s = size / 26f;
            g2.setStroke(new BasicStroke(1.8f * s, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawRoundRect(Math.round(3 * s), Math.round(4 * s), Math.round(20 * s), Math.round(7 * s), Math.round(2 * s), Math.round(2 * s));
            g2.drawRoundRect(Math.round(3 * s), Math.round(15 * s), Math.round(20 * s), Math.round(7 * s), Math.round(2 * s), Math.round(2 * s));
            g2.drawLine(Math.round(10 * s), Math.round(11 * s), Math.round(10 * s), Math.round(15 * s));
            g2.drawLine(Math.round(16 * s), Math.round(11 * s), Math.round(16 * s), Math.round(15 * s));
            g2.fillOval(Math.round(6 * s), Math.round(6 * s), Math.round(2.5f * s), Math.round(2.5f * s));
            g2.fillOval(Math.round(6 * s), Math.round(17 * s), Math.round(2.5f * s), Math.round(2.5f * s));
        }

        private void paintSave(Graphics2D g2) {
            float s = size / 15f;
            g2.setStroke(new BasicStroke(1.5f * s, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawRoundRect(Math.round(1 * s), Math.round(1 * s), Math.round(13 * s), Math.round(13 * s), Math.round(2 * s), Math.round(2 * s));
            g2.drawRect(Math.round(4 * s), Math.round(2 * s), Math.round(6 * s), Math.round(4 * s));
            g2.drawRect(Math.round(4 * s), Math.round(9 * s), Math.round(7 * s), Math.round(4 * s));
            g2.drawLine(Math.round(10 * s), Math.round(2 * s), Math.round(12 * s), Math.round(4 * s));
        }

        private void paintTrash(Graphics2D g2) {
            float s = size / 15f;
            g2.setStroke(new BasicStroke(1.5f * s, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawLine(Math.round(4 * s), Math.round(4 * s), Math.round(11 * s), Math.round(4 * s));
            g2.drawLine(Math.round(6 * s), Math.round(2 * s), Math.round(9 * s), Math.round(2 * s));
            g2.drawRoundRect(Math.round(4 * s), Math.round(4 * s), Math.round(7 * s), Math.round(9 * s), Math.round(2 * s), Math.round(2 * s));
            g2.drawLine(Math.round(6 * s), Math.round(6 * s), Math.round(6 * s), Math.round(11 * s));
            g2.drawLine(Math.round(8 * s), Math.round(6 * s), Math.round(8 * s), Math.round(11 * s));
            g2.drawLine(Math.round(10 * s), Math.round(6 * s), Math.round(10 * s), Math.round(11 * s));
        }

        private void paintPower(Graphics2D g2) {
            float s = size / 17f;
            g2.setStroke(new BasicStroke(2.0f * s, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.draw(new Arc2D.Double(2 * s, 3 * s, 13 * s, 12 * s, 45, 270, Arc2D.OPEN));
            g2.drawLine(Math.round(8.5f * s), Math.round(1.5f * s), Math.round(8.5f * s), Math.round(8 * s));
        }

        private void paintSparkle(Graphics2D g2) {
            float s = size / 28f;
            Path2D.Double path = new Path2D.Double();
            path.moveTo(14 * s, 0);
            path.lineTo(18 * s, 10 * s);
            path.lineTo(28 * s, 14 * s);
            path.lineTo(18 * s, 18 * s);
            path.lineTo(14 * s, 28 * s);
            path.lineTo(10 * s, 18 * s);
            path.lineTo(0, 14 * s);
            path.lineTo(10 * s, 10 * s);
            path.closePath();
            g2.fill(path);
        }
    }
}
