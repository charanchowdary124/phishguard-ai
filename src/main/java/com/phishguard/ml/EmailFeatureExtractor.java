package com.phishguard.ml;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class EmailFeatureExtractor {

    private static final Set<String> STOP_WORDS = Set.of(
        "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from",
        "has", "he", "in", "is", "it", "its", "of", "on", "or", "that", "the",
        "to", "was", "we", "will", "with", "you"
    );
    private static final Set<String> SUSPICIOUS_TERMS = Set.of(
        "urgent", "verify", "password", "suspend", "account", "confirmation",
        "invoice", "payment", "wire", "gift card", "crypto", "login"
    );
    private static final Pattern URL_PATTERN = Pattern.compile(
        "(?:https?://|www\\.)[^\\s<>\"']+",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern CREDENTIAL_REQUEST_PATTERN = Pattern.compile(
        "\\b(?:send|share|provide|reply\\s+with|enter|submit|confirm|verify|give|tell\\s+us|forward|type\\s+in)\\b"
            + ".{0,40}\\b(?:your\\s+)?(?:password|passcode|credentials?|pin|access token|secret key)\\b",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern ONE_TIME_CODE_REQUEST_PATTERN = Pattern.compile(
        "\\b(?:send|share|provide|reply\\s+with|enter|submit|confirm|verify|give|tell\\s+us|forward|type\\s+in)\\b"
            + ".{0,40}\\b(?:your\\s+)?(?:otp|one[- ]time (?:password|code)|verification code|security code"
            + "|authentication code)\\b",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SENDER_EMAIL_PATTERN = Pattern.compile(
        "[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})"
    );
    private static final Pattern ATTACHMENT_PATTERN = Pattern.compile(
        "\\b(\\.exe|\\.scr|\\.bat|\\.cmd|\\.js|\\.html|\\.hta|\\.zip|\\.rar)\\b",
        Pattern.CASE_INSENSITIVE
    );

    public EmailFeatureVector extract(String subject, String body, String sender) {
        if ((subject == null || subject.isBlank()) && (body == null || body.isBlank())) {
            throw new IllegalArgumentException("Email subject or body must be provided");
        }

        String plainText = stripHtml((subject == null ? "" : subject) + " " + (body == null ? "" : body));
        String lowerText = plainText.toLowerCase(Locale.ROOT);
        List<String> tokens = tokenize(lowerText);
        Matcher urlMatcher = URL_PATTERN.matcher(
            (subject == null ? "" : subject) + " " + (body == null ? "" : body)
        );
        int linkCount = 0;
        while (urlMatcher.find()) linkCount++;

        long suspiciousTerms = SUSPICIOUS_TERMS.stream()
            .filter(lowerText::contains)
            .count();

        Map<String, Double> values = new LinkedHashMap<>();
        values.put("textLength", (double) plainText.length());
        values.put("tokenCount", (double) tokens.size());
        values.put("suspiciousTermCount", (double) suspiciousTerms);
        values.put("urgentLanguage", containsAny(lowerText,
            "urgent", "immediately", "within 24 hours", "final notice", "act now") ? 1.0 : 0.0);
        values.put("passwordRequest", CREDENTIAL_REQUEST_PATTERN.matcher(lowerText).find() ? 1.0 : 0.0);
        values.put("oneTimeCodeRequest",
            ONE_TIME_CODE_REQUEST_PATTERN.matcher(lowerText).find() ? 1.0 : 0.0);
        values.put("accountVerification",
            containsAny(lowerText, "verify account", "confirm account", "account verification") ? 1.0 : 0.0);
        values.put("paymentRequest",
            containsAny(lowerText, "invoice", "payment", "wire transfer", "gift card") ? 1.0 : 0.0);
        values.put("financialInformationRequest",
            containsAny(lowerText, "credit card", "debit card", "bank account", "routing number",
                "account number", "card number", "payment details", "social security number") ? 1.0 : 0.0);
        values.put("embeddedLinkCount", (double) linkCount);
        values.put("attachmentIndicator", ATTACHMENT_PATTERN.matcher(plainText).find() ? 1.0 : 0.0);
        values.put("senderMismatch", senderMismatch(sender, lowerText) ? 1.0 : 0.0);
        values.put("malformedSender",
            sender != null && !sender.isBlank() && !SENDER_EMAIL_PATTERN.matcher(sender).find() ? 1.0 : 0.0);
        return new EmailFeatureVector(values);
    }

    public List<String> indicators(String subject, String body, String sender, EmailFeatureVector features) {
        List<String> indicators = new ArrayList<>();
        if (features.get("urgentLanguage") == 1.0) indicators.add("Urgent or pressure language");
        if (features.get("passwordRequest") == 1.0) indicators.add("Password or credential request");
        if (features.get("oneTimeCodeRequest") == 1.0) indicators.add("One-time or verification code request");
        if (features.get("accountVerification") == 1.0) indicators.add("Account verification request");
        if (features.get("paymentRequest") == 1.0) indicators.add("Suspicious payment or invoice request");
        if (features.get("financialInformationRequest") == 1.0) {
            indicators.add("Sensitive financial information request");
        }
        if (features.get("embeddedLinkCount") >= 1.0) indicators.add("Embedded link present");
        if (features.get("attachmentIndicator") == 1.0) indicators.add("Potentially risky attachment reference");
        if (features.get("senderMismatch") == 1.0) indicators.add("Sender address does not match referenced domain");
        if (features.get("malformedSender") == 1.0) indicators.add("Sender address format is suspicious");
        return indicators;
    }

    private String stripHtml(String html) {
        if (html == null) return "";
        return html
            .replaceAll("(?is)<script.*?>.*?</script>", " ")
            .replaceAll("(?is)<style.*?>.*?</style>", " ")
            .replaceAll("(?s)<[^>]*>", " ")
            .replaceAll("\\s+", " ")
            .trim();
    }

    private List<String> tokenize(String text) {
        return Pattern.compile("[a-z0-9]+")
            .matcher(text)
            .results()
            .map(result -> result.group())
            .filter(token -> token.length() > 1)
            .filter(token -> !STOP_WORDS.contains(token))
            .toList();
    }

    private boolean containsAny(String text, String... phrases) {
        for (String phrase : phrases) {
            if (text.contains(phrase)) return true;
        }
        return false;
    }

    private boolean senderMismatch(String sender, String text) {
        if (sender == null || sender.isBlank()) return false;
        String senderLower = sender.toLowerCase(Locale.ROOT);
        Matcher emailMatcher = SENDER_EMAIL_PATTERN.matcher(senderLower);
        if (!emailMatcher.find()) return false;
        String senderDomain = emailMatcher.group(1);
        Matcher domainReferences = Pattern.compile("([A-Za-z0-9-]+\\.[A-Za-z]{2,})")
            .matcher(text);
        while (domainReferences.find()) {
            String referenced = domainReferences.group(1);
            if (!referenced.endsWith(senderDomain) && !senderDomain.endsWith(referenced)) {
                return true;
            }
        }
        return false;
    }
}
