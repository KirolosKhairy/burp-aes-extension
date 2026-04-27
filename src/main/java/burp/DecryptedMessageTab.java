package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Custom decrypted message tab shown in HTTP History and Repeater.
 */
public class DecryptedMessageTab
        implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

    private static final Font TITLE_FONT = new Font("Segoe UI", Font.BOLD, 13);
    private static final Font SUBTITLE_FONT = new Font("Segoe UI", Font.PLAIN, 11);
    private static final Font BADGE_FONT = new Font("Segoe UI", Font.BOLD, 11);
    private static final Font TEXT_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private static final Font STATUS_FONT = new Font("Segoe UI", Font.BOLD, 11);

    private final BurpAesExtension extension;
    private final boolean isRequest;
    private final boolean editable;

    private final Theme theme;
    private final JTextArea textArea;
    private final JLabel modeBadge;
    private final JLabel statusBar;
    private final JPanel panel;

    private HttpRequestResponse currentRequestResponse;
    private volatile boolean modified = false;
    private volatile boolean decryptedSuccessfully = false;

    public DecryptedMessageTab(BurpAesExtension extension, boolean isRequest, boolean editable) {
        this.extension = extension;
        this.isRequest = isRequest;
        this.editable = editable;
        this.theme = Theme.detect();

        JLabel titleLabel = new JLabel(isRequest ? "Decrypted request body" : "Decrypted response body");
        titleLabel.setFont(TITLE_FONT);
        titleLabel.setForeground(theme.primaryText);

        JLabel subtitleLabel = new JLabel(editable
                ? "Edit plaintext here. Burp will re-encrypt the request body before sending."
                : "Read-only plaintext view of the encrypted message body.");
        subtitleLabel.setFont(SUBTITLE_FONT);
        subtitleLabel.setForeground(theme.secondaryText);

        modeBadge = new JLabel(editable ? "EDITABLE" : "READ ONLY");
        modeBadge.setFont(BADGE_FONT);
        modeBadge.setOpaque(true);
        modeBadge.setBackground(editable ? theme.accentSoft : theme.neutralSoft);
        modeBadge.setForeground(editable ? theme.accentText : theme.secondaryText);
        modeBadge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(editable ? theme.accentBorder : theme.neutralBorder, 1),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)));

        JPanel titleStack = new JPanel();
        titleStack.setLayout(new BoxLayout(titleStack, BoxLayout.Y_AXIS));
        titleStack.setOpaque(false);
        titleStack.add(titleLabel);
        titleStack.add(Box.createRigidArea(new Dimension(0, 4)));
        titleStack.add(subtitleLabel);

        JPanel badgeWrap = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        badgeWrap.setOpaque(false);
        badgeWrap.add(modeBadge);

        JPanel header = new JPanel(new BorderLayout(12, 0));
        header.setOpaque(true);
        header.setBackground(theme.headerBg);
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 4, 0, 0, editable ? theme.accent : theme.neutralBorder),
                        BorderFactory.createLineBorder(theme.headerBorder, 1)),
                BorderFactory.createEmptyBorder(12, 12, 12, 12)));
        header.add(titleStack, BorderLayout.CENTER);
        header.add(badgeWrap, BorderLayout.EAST);

        textArea = new JTextArea();
        textArea.setEditable(editable);
        textArea.setFont(TEXT_FONT);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(false);
        textArea.setTabSize(2);
        textArea.setForeground(theme.primaryText);
        textArea.setBackground(editable ? theme.editorBg : theme.readOnlyBg);
        textArea.setCaretColor(theme.primaryText);
        textArea.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        if (editable) {
            textArea.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    markModified();
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    markModified();
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    markModified();
                }

                private void markModified() {
                    modified = true;
                    if (decryptedSuccessfully) {
                        setStatus(
                                "Plaintext modified. Burp will re-encrypt this request body when you send it.",
                                StatusTone.INFO);
                    }
                }
            });
        }

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(theme.editorBorder, 1),
                BorderFactory.createEmptyBorder()));
        scrollPane.getViewport().setBackground(textArea.getBackground());

        statusBar = new JLabel(" ");
        statusBar.setFont(STATUS_FONT);
        statusBar.setOpaque(true);
        statusBar.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        panel = new JPanel(new BorderLayout(0, 10));
        panel.setBackground(theme.canvasBg);
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        panel.add(header, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(statusBar, BorderLayout.SOUTH);

        clearDisplay("Select a message to view its decrypted body.", StatusTone.NEUTRAL);
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        currentRequestResponse = requestResponse;
        modified = false;
        decryptedSuccessfully = false;

        if (requestResponse == null) {
            clearDisplay("Select a message to view its decrypted body.", StatusTone.NEUTRAL);
            return;
        }

        String body;
        if (isRequest) {
            body = requestResponse.request().bodyToString().trim();
        } else {
            if (!requestResponse.hasResponse()) {
                clearDisplay("No response has been received for this request yet.", StatusTone.NEUTRAL);
                return;
            }
            body = requestResponse.response().bodyToString().trim();
        }

        if (body.isEmpty()) {
            clearDisplay("The selected message does not contain an encrypted body.", StatusTone.NEUTRAL);
            return;
        }

        try {
            byte[] plaintext = extension.getCryptoHelper().decrypt(body);
            String plainText = new String(plaintext, StandardCharsets.UTF_8);
            decryptedSuccessfully = true;

            SwingUtilities.invokeLater(() -> {
                textArea.setForeground(theme.primaryText);
                textArea.setBackground(editable ? theme.editorBg : theme.readOnlyBg);
                textArea.setText(plainText);
                modified = false;
                textArea.setCaretPosition(0);
                setStatus(
                        "Decryption successful. Plaintext size: " + plaintext.length
                                + " bytes from " + body.length() + " bytes of ciphertext.",
                        StatusTone.SUCCESS);
            });
        } catch (Exception e) {
            String reason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (isReadablePlaintext(body)) {
                showPlaintextBody(body);
                return;
            }
            extension.getLogging().logToError("DecryptedMessageTab: " + reason);
            showDecryptionFailure(reason, body);
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        String targetHost = extension.getTargetHost();
        if (targetHost == null || targetHost.isEmpty()) {
            return false;
        }

        try {
            String host = requestResponse.request().httpService().host();
            return host != null
                    && host.toLowerCase(Locale.ROOT).contains(targetHost.toLowerCase(Locale.ROOT));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String caption() {
        return "decrypted_message";
    }

    @Override
    public Component uiComponent() {
        return panel;
    }

    @Override
    public Selection selectedData() {
        String selected = textArea.getSelectedText();
        if (selected == null) {
            return null;
        }
        return Selection.selection(ByteArray.byteArray(selected.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public boolean isModified() {
        return modified;
    }

    @Override
    public HttpRequest getRequest() {
        if (!isRequest || currentRequestResponse == null) {
            return currentRequestResponse != null ? currentRequestResponse.request() : null;
        }
        if (!decryptedSuccessfully) {
            return currentRequestResponse.request();
        }

        try {
            String reEncrypted = extension.getCryptoHelper().encrypt(
                    textArea.getText().getBytes(StandardCharsets.UTF_8));
            return currentRequestResponse.request().withBody(reEncrypted);
        } catch (Exception e) {
            extension.getLogging().logToError("Re-encryption error: " + e.getMessage());
            return currentRequestResponse.request();
        }
    }

    @Override
    public HttpResponse getResponse() {
        return currentRequestResponse != null ? currentRequestResponse.response() : null;
    }

    private void clearDisplay(String message, StatusTone tone) {
        SwingUtilities.invokeLater(() -> {
            textArea.setText(message);
            modified = false;
            textArea.setCaretPosition(0);
            textArea.setForeground(theme.secondaryText);
            textArea.setBackground(editable ? theme.editorBg : theme.readOnlyBg);
            setStatus(message, tone);
        });
    }

    private void showPlaintextBody(String plaintextBody) {
        decryptedSuccessfully = true;
        byte[] plaintextBytes = plaintextBody.getBytes(StandardCharsets.UTF_8);

        SwingUtilities.invokeLater(() -> {
            textArea.setForeground(theme.primaryText);
            textArea.setBackground(editable ? theme.editorBg : theme.readOnlyBg);
            textArea.setText(plaintextBody);
            modified = false;
            textArea.setCaretPosition(0);
            setStatus(
                    "\u2713 Body displayed. Auto-encrypted before sending to server. Plaintext size: "
                            + plaintextBytes.length + " bytes.",
                    StatusTone.INFO);
        });
    }

    private void showDecryptionFailure(String reason, String encryptedBody) {
        String preview = encryptedBody.length() > 220
                ? encryptedBody.substring(0, 220) + "..."
                : encryptedBody;
        String message = "Unable to decrypt this message.\n\n"
                + "Reason:\n"
                + reason + "\n\n"
                + "What to verify:\n"
                + "- AES key and IV in the AES Config tab\n"
                + "- Target host matches this traffic\n"
                + "- The full body is Base64-wrapped AES-CBC data\n\n"
                + "Encrypted body preview:\n"
                + preview;

        SwingUtilities.invokeLater(() -> {
            textArea.setText(message);
            modified = false;
            textArea.setCaretPosition(0);
            textArea.setForeground(theme.errorText);
            textArea.setBackground(theme.errorSoft);
            setStatus("Decryption failed. Review the configured AES key, IV, and body format.", StatusTone.ERROR);
        });
    }

    private static boolean isReadablePlaintext(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }

        String trimmed = body.trim();
        if (looksLikeBase64(trimmed)) {
            return false;
        }

        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '\uFFFD') {
                return false;
            }
            if (c == '\n' || c == '\r' || c == '\t') {
                continue;
            }
            if (Character.isISOControl(c)) {
                return false;
            }
        }
        return true;
    }

    private static boolean looksLikeBase64(String body) {
        return body.length() >= 16
                && body.length() % 4 == 0
                && body.matches("[A-Za-z0-9+/]+={0,2}");
    }

    private void setStatus(String message, StatusTone tone) {
        statusBar.setText(message);
        switch (tone) {
            case SUCCESS:
                statusBar.setBackground(theme.successSoft);
                statusBar.setForeground(theme.successText);
                break;
            case ERROR:
                statusBar.setBackground(theme.errorSoft);
                statusBar.setForeground(theme.errorText);
                break;
            case INFO:
                statusBar.setBackground(theme.accentSoft);
                statusBar.setForeground(theme.accentText);
                break;
            default:
                statusBar.setBackground(theme.neutralSoft);
                statusBar.setForeground(theme.secondaryText);
                break;
        }
    }

    private enum StatusTone {
        SUCCESS,
        ERROR,
        INFO,
        NEUTRAL
    }

    private static double luminance(Color color) {
        return 0.2126 * (color.getRed() / 255.0)
                + 0.7152 * (color.getGreen() / 255.0)
                + 0.0722 * (color.getBlue() / 255.0);
    }

    private static Color mix(Color a, Color b, double ratio) {
        double clamped = Math.max(0.0, Math.min(1.0, ratio));
        int red = (int) Math.round(a.getRed() * (1.0 - clamped) + b.getRed() * clamped);
        int green = (int) Math.round(a.getGreen() * (1.0 - clamped) + b.getGreen() * clamped);
        int blue = (int) Math.round(a.getBlue() * (1.0 - clamped) + b.getBlue() * clamped);
        return new Color(red, green, blue);
    }

    private static final class Theme {
        private final Color canvasBg;
        private final Color headerBg;
        private final Color headerBorder;
        private final Color editorBg;
        private final Color readOnlyBg;
        private final Color editorBorder;
        private final Color primaryText;
        private final Color secondaryText;
        private final Color accent;
        private final Color accentSoft;
        private final Color accentText;
        private final Color accentBorder;
        private final Color neutralSoft;
        private final Color neutralBorder;
        private final Color successSoft;
        private final Color successText;
        private final Color errorSoft;
        private final Color errorText;

        private Theme(Color canvasBg,
                      Color headerBg,
                      Color headerBorder,
                      Color editorBg,
                      Color readOnlyBg,
                      Color editorBorder,
                      Color primaryText,
                      Color secondaryText,
                      Color accent,
                      Color accentSoft,
                      Color accentText,
                      Color accentBorder,
                      Color neutralSoft,
                      Color neutralBorder,
                      Color successSoft,
                      Color successText,
                      Color errorSoft,
                      Color errorText) {
            this.canvasBg = canvasBg;
            this.headerBg = headerBg;
            this.headerBorder = headerBorder;
            this.editorBg = editorBg;
            this.readOnlyBg = readOnlyBg;
            this.editorBorder = editorBorder;
            this.primaryText = primaryText;
            this.secondaryText = secondaryText;
            this.accent = accent;
            this.accentSoft = accentSoft;
            this.accentText = accentText;
            this.accentBorder = accentBorder;
            this.neutralSoft = neutralSoft;
            this.neutralBorder = neutralBorder;
            this.successSoft = successSoft;
            this.successText = successText;
            this.errorSoft = errorSoft;
            this.errorText = errorText;
        }

        private static Theme detect() {
            Color panelBg = UIManager.getColor("Panel.background");
            if (panelBg == null) panelBg = new JPanel().getBackground();

            Color editorBg = UIManager.getColor("TextArea.background");
            if (editorBg == null) editorBg = Color.WHITE;

            Color labelFg = UIManager.getColor("Label.foreground");
            if (labelFg == null) labelFg = new JLabel().getForeground();

            Color accentBase = UIManager.getColor("TextField.selectionBackground");
            if (accentBase == null) accentBase = UIManager.getColor("Focus.color");
            if (accentBase == null) accentBase = new Color(71, 120, 204);

            boolean dark = luminance(panelBg) < 0.45;

            Color accent = dark ? mix(accentBase, Color.WHITE, 0.10) : accentBase;
            Color primaryText = labelFg;
            Color secondaryText = dark ? mix(labelFg, panelBg, 0.40) : mix(labelFg, panelBg, 0.28);
            Color headerBg = dark ? mix(panelBg, accent, 0.12) : mix(panelBg, accent, 0.06);
            Color headerBorder = mix(accent, panelBg, dark ? 0.30 : 0.42);
            Color readOnlyBg = dark ? mix(editorBg, panelBg, 0.22) : mix(editorBg, panelBg, 0.10);
            Color editorBorder = dark ? mix(labelFg, panelBg, 0.74) : mix(labelFg, panelBg, 0.82);
            Color accentSoft = mix(panelBg, accent, dark ? 0.32 : 0.18);
            Color accentText = dark ? mix(accent, Color.WHITE, 0.18) : mix(accent, Color.BLACK, 0.14);
            Color accentBorder = mix(accent, panelBg, dark ? 0.28 : 0.36);
            Color neutralSoft = dark ? mix(panelBg, Color.WHITE, 0.08) : mix(panelBg, Color.BLACK, 0.04);
            Color neutralBorder = dark ? mix(labelFg, panelBg, 0.72) : mix(labelFg, panelBg, 0.82);
            Color successBase = new Color(40, 140, 92);
            Color successSoft = mix(panelBg, successBase, dark ? 0.28 : 0.14);
            Color successText = dark ? mix(successBase, Color.WHITE, 0.18) : mix(successBase, Color.BLACK, 0.12);
            Color errorBase = new Color(186, 66, 66);
            Color errorSoft = mix(panelBg, errorBase, dark ? 0.28 : 0.14);
            Color errorText = dark ? mix(errorBase, Color.WHITE, 0.16) : mix(errorBase, Color.BLACK, 0.08);

            return new Theme(
                    panelBg,
                    headerBg,
                    headerBorder,
                    editorBg,
                    readOnlyBg,
                    editorBorder,
                    primaryText,
                    secondaryText,
                    accent,
                    accentSoft,
                    accentText,
                    accentBorder,
                    neutralSoft,
                    neutralBorder,
                    successSoft,
                    successText,
                    errorSoft,
                    errorText);
        }
    }
}
