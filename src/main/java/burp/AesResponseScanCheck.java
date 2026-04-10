package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner check that analyzes decrypted responses so encrypted endpoints can still produce
 * meaningful audit findings on Burp's Dashboard.
 *
 * <p>Montoya does not expose a public hook to feed synthetic plaintext responses back into
 * Burp's built-in passive analyzers. This check therefore decrypts the response body and
 * returns first-class {@link AuditIssue} objects based on extension-owned analysis.
 */
@SuppressWarnings("deprecation")
public class AesResponseScanCheck implements ScanCheck {

    private static final String REFLECTION_PROBE = "aes-reflect-probe-7f4c1d";
    private static final String SQLI_PROBE = "'\"aes-sql-probe-7f4c1d";
    private static final String ERROR_PROBE = "${aes-error-probe-7f4c1d}";

    private static final Pattern[] SQL_ERROR_PATTERNS = new Pattern[] {
            ci("SQL syntax.*MySQL"),
            ci("Warning.*mysql_"),
            ci("valid MySQL result"),
            ci("PostgreSQL.*ERROR"),
            ci("Warning.*pg_"),
            ci("pg_query\\("),
            ci("Driver.* SQL[\\-_ ]*Server"),
            ci("OLE DB.* SQL Server"),
            ci("Unclosed quotation mark after the character string"),
            ci("Microsoft SQL Native Client error"),
            ci("ORA-\\d{4,}"),
            ci("Oracle error"),
            ci("SQLite/JDBCDriver"),
            ci("SQLite.Exception"),
            ci("near \".*\": syntax error"),
            ci("SQLSTATE\\[[A-Z0-9]+\\]"),
            ci("PDOException"),
            ci("DB2 SQL error"),
            ci("supplied argument is not a valid .* result"),
            ci("Syntax error in string in query expression")
    };

    private static final Pattern[] STACK_TRACE_PATTERNS = new Pattern[] {
            Pattern.compile("(?m)^\\s*at\\s+[\\w.$]+\\([^)]*\\.java:\\d+\\)"),
            ci("Exception in thread"),
            ci("java\\.lang\\.[A-Za-z]+(?:Exception|Error)"),
            ci("org\\.springframework"),
            ci("Traceback \\(most recent call last\\):"),
            ci("System\\.[A-Za-z.]+Exception"),
            ci("Fatal error: Uncaught"),
            ci("\\bStack trace\\b"),
            ci("Unhandled exception"),
            ci("NullReferenceException")
    };

    private final BurpAesExtension extension;
    private final MontoyaApi api;

    public AesResponseScanCheck(BurpAesExtension extension, MontoyaApi api) {
        this.extension = extension;
        this.api = api;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        if (!hostMatches(baseRequestResponse) || !baseRequestResponse.hasResponse()) {
            return emptyResult();
        }

        DecryptedEvidence evidence = decryptedEvidence(baseRequestResponse);
        if (evidence == null) {
            return emptyResult();
        }

        List<AuditIssue> issues = new ArrayList<>();
        addErrorDisclosureIssues(
                issues,
                evidence,
                "Passive inspection of decrypted response content identified indicators that would be hidden from Scanner while the response remains encrypted.");

        return issues.isEmpty() ? emptyResult() : AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        if (!hostMatches(baseRequestResponse) || insertionPoint == null) {
            return emptyResult();
        }

        List<AuditIssue> issues = new ArrayList<>();
        runProbe(baseRequestResponse, insertionPoint, REFLECTION_PROBE, ProbeKind.REFLECTION, issues);
        runProbe(baseRequestResponse, insertionPoint, SQLI_PROBE, ProbeKind.SQL_ERROR, issues);
        runProbe(baseRequestResponse, insertionPoint, ERROR_PROBE, ProbeKind.STACK_TRACE, issues);

        return issues.isEmpty() ? emptyResult() : AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue.name().equals(newIssue.name())
                && existingIssue.baseUrl().equals(newIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    private void runProbe(HttpRequestResponse baseRequestResponse,
                          AuditInsertionPoint insertionPoint,
                          String payload,
                          ProbeKind probeKind,
                          List<AuditIssue> issues) {
        try {
            HttpRequest attackRequest = insertionPoint.buildHttpRequestWithPayload(
                    ByteArray.byteArray(payload.getBytes(StandardCharsets.UTF_8)));
            HttpRequestResponse attackResult = api.http().sendRequest(attackRequest);

            String injectedPayload = payload;
            if (insertionPoint instanceof AesInsertionPoint) {
                String lastPayload = ((AesInsertionPoint) insertionPoint).getLastPayload();
                if (lastPayload != null && !lastPayload.isEmpty()) {
                    injectedPayload = lastPayload;
                }
            }

            DecryptedEvidence evidence = decryptedEvidence(attackResult);
            if (evidence == null) {
                return;
            }

            if (probeKind == ProbeKind.REFLECTION) {
                addReflectedInputIssue(issues, evidence, insertionPoint.name(), injectedPayload);
                return;
            }

            if (probeKind == ProbeKind.SQL_ERROR) {
                addSqlErrorIssues(
                        issues,
                        evidence,
                        "The decrypted response to an injected request contained SQL error indicators, suggesting the payload reached backend query handling.");
                return;
            }

            addStackTraceIssues(
                    issues,
                    evidence,
                    "The decrypted response to an injected request exposed application stack trace details.");
        } catch (Exception e) {
            extension.getLogging().logToError("AesResponseScanCheck [" + probeKind
                    + "] failed: " + e.getMessage());
        }
    }

    private void addReflectedInputIssue(List<AuditIssue> issues,
                                        DecryptedEvidence evidence,
                                        String parameterName,
                                        String payload) {
        int start = evidence.decryptedBody.indexOf(payload);
        if (start < 0) {
            return;
        }

        int end = start + payload.length();
        HttpRequestResponse markedEvidence = withBodyMarker(evidence, start, end);
        issues.add(AuditIssue.auditIssue(
                "Reflected Input in Encrypted Response",
                "Scanner injected a payload into the decrypted parameter '" + parameterName
                        + "' and the same payload was reflected in the decrypted response body. "
                        + "This indicates the encrypted endpoint can still reflect attacker-controlled input "
                        + "after server-side processing.",
                "Review how decrypted input is rendered. Apply output encoding and contextual escaping before reflecting any user-controlled data.",
                safeBaseUrl(markedEvidence),
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.TENTATIVE,
                "This issue is reported when attacker-controlled input is reflected in a response after the extension decrypts the encrypted application traffic for analysis.",
                "Apply context-aware output encoding and avoid rendering unsanitized user input in HTML, JavaScript, JSON, or template contexts.",
                AuditIssueSeverity.MEDIUM,
                markedEvidence));
    }

    private void addErrorDisclosureIssues(List<AuditIssue> issues,
                                          DecryptedEvidence evidence,
                                          String contextDetail) {
        addSqlErrorIssues(issues, evidence, contextDetail);
        addStackTraceIssues(issues, evidence, contextDetail);
    }

    private void addSqlErrorIssues(List<AuditIssue> issues,
                                   DecryptedEvidence evidence,
                                   String contextDetail) {
        Match sqlMatch = firstMatch(evidence.decryptedBody, SQL_ERROR_PATTERNS);
        if (sqlMatch == null) {
            return;
        }

        HttpRequestResponse markedEvidence = withBodyMarker(evidence, sqlMatch.start, sqlMatch.end);
        issues.add(AuditIssue.auditIssue(
                "SQL Error Disclosure in Encrypted Response",
                contextDetail + " The decrypted response contains SQL error text: '" + sqlMatch.preview + "'.",
                "Handle database exceptions safely and return generic error responses. Avoid leaking database engine details to clients.",
                safeBaseUrl(markedEvidence),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "Verbose SQL error messages can reveal backend technology details and may indicate that attacker-controlled input is reaching query execution paths.",
                "Catch database exceptions, log them server-side, and return sanitized error responses without SQL engine details.",
                AuditIssueSeverity.HIGH,
                markedEvidence));
    }

    private void addStackTraceIssues(List<AuditIssue> issues,
                                     DecryptedEvidence evidence,
                                     String contextDetail) {
        Match stackMatch = firstMatch(evidence.decryptedBody, STACK_TRACE_PATTERNS);
        if (stackMatch == null) {
            return;
        }

        HttpRequestResponse markedEvidence = withBodyMarker(evidence, stackMatch.start, stackMatch.end);
        issues.add(AuditIssue.auditIssue(
                "Stack Trace Disclosure in Encrypted Response",
                contextDetail + " The decrypted response exposes application stack trace details: '"
                        + stackMatch.preview + "'.",
                "Disable verbose exception rendering in production and return sanitized error pages or API responses.",
                safeBaseUrl(markedEvidence),
                AuditIssueSeverity.LOW,
                AuditIssueConfidence.FIRM,
                "Stack traces reveal implementation details, frameworks, code paths, and sometimes secrets that help attackers target the application more effectively.",
                "Use centralized exception handling and production-safe error responses that do not expose internal stack traces.",
                AuditIssueSeverity.LOW,
                markedEvidence));
    }

    private DecryptedEvidence decryptedEvidence(HttpRequestResponse requestResponse) {
        if (requestResponse == null || !requestResponse.hasResponse()) {
            return null;
        }

        String encryptedBody = requestResponse.response().bodyToString().trim();
        if (encryptedBody.isEmpty()) {
            return null;
        }

        try {
            String decryptedBody = new String(
                    extension.getCryptoHelper().decrypt(encryptedBody),
                    StandardCharsets.UTF_8);
            HttpResponse decryptedResponse = requestResponse.response().withBody(decryptedBody);
            HttpRequestResponse evidence = HttpRequestResponse.httpRequestResponse(
                    requestResponse.request(),
                    decryptedResponse,
                    requestResponse.annotations());
            return new DecryptedEvidence(evidence, decryptedBody);
        } catch (Exception e) {
            extension.getLogging().logToError("AesResponseScanCheck: response decryption failed: "
                    + e.getMessage());
            return null;
        }
    }

    private HttpRequestResponse withBodyMarker(DecryptedEvidence evidence, int start, int end) {
        if (start < 0 || end <= start) {
            return evidence.requestResponse;
        }

        int bodyOffset = evidence.requestResponse.response().bodyOffset();
        return evidence.requestResponse.withResponseMarkers(
                Marker.marker(bodyOffset + start, bodyOffset + end));
    }

    private boolean hostMatches(HttpRequestResponse requestResponse) {
        String target = extension.getTargetHost();
        if (target == null || target.isEmpty() || requestResponse == null) {
            return false;
        }
        try {
            String host = requestResponse.request().httpService().host();
            return host != null && host.contains(target);
        } catch (Exception e) {
            return false;
        }
    }

    private static AuditResult emptyResult() {
        return AuditResult.auditResult(Collections.emptyList());
    }

    private static Pattern ci(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
    }

    private static Match firstMatch(String body, Pattern[] patterns) {
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(body);
            if (matcher.find()) {
                return new Match(matcher.start(), matcher.end(), body.substring(matcher.start(), matcher.end()));
            }
        }
        return null;
    }

    private static String safeBaseUrl(HttpRequestResponse requestResponse) {
        try {
            return requestResponse.url();
        } catch (Exception e) {
            return requestResponse.request().url();
        }
    }

    private enum ProbeKind {
        REFLECTION,
        SQL_ERROR,
        STACK_TRACE
    }

    private static final class DecryptedEvidence {
        private final HttpRequestResponse requestResponse;
        private final String decryptedBody;

        private DecryptedEvidence(HttpRequestResponse requestResponse, String decryptedBody) {
            this.requestResponse = requestResponse;
            this.decryptedBody = decryptedBody;
        }
    }

    private static final class Match {
        private final int start;
        private final int end;
        private final String preview;

        private Match(int start, int end, String preview) {
            this.start = start;
            this.end = end;
            this.preview = preview;
        }
    }
}
