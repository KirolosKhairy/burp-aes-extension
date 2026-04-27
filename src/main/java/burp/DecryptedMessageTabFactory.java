package burp;

import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

/**
 * Factory that creates {@link DecryptedMessageTab} instances on demand.
 *
 * <p>Implements both {@link HttpRequestEditorProvider} and {@link HttpResponseEditorProvider}
 * so a single instance can be registered for both roles.
 *
 * <ul>
 *   <li>Request tabs in Repeater ({@link EditorMode#DEFAULT}) are <em>editable</em>.</li>
 *   <li>Request tabs in HTTP History ({@link EditorMode#READ_ONLY}) are read-only.</li>
 *   <li>Response tabs are always read-only.</li>
 * </ul>
 */
public class DecryptedMessageTabFactory implements HttpRequestEditorProvider, HttpResponseEditorProvider {

    private final BurpAesExtension extension;

    /**
     * @param extension the shared extension state (key, IV, target host)
     */
    public DecryptedMessageTabFactory(BurpAesExtension extension) {
        this.extension = extension;
    }

    /**
     * Creates a request editor tab. Editable only in {@link EditorMode#DEFAULT} (Repeater).
     *
     * @param context information about the tool and mode requesting the editor
     * @return a new {@link DecryptedMessageTab} for requests
     */
    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext context) {
        boolean editable = context.editorMode() == EditorMode.DEFAULT;
        return new DecryptedMessageTab(extension, true, editable);
    }

    /**
     * Creates a read-only response editor tab.
     *
     * @param context information about the tool and mode requesting the editor
     * @return a new read-only {@link DecryptedMessageTab} for responses
     */
    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
        return new DecryptedMessageTab(extension, false, false);
    }
}
