package com.phishguard.ml;

import org.springframework.stereotype.Component;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Component
public class UrlFeatureExtractor {

    private static final Set<String> SUSPICIOUS_KEYWORDS = Set.of(
        "login", "verify", "secure", "account", "update", "password",
        "signin", "banking", "confirm", "urgent", "suspend"
    );
    private static final Set<String> SHORTENERS = Set.of(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "cutt.ly"
    );
    private static final Set<String> BLOCKED_HOSTNAMES = Set.of(
        "metadata", "metadata.google", "metadata.google.internal", "instance-data"
    );
    private static final Pattern IPV4 = Pattern.compile(
        "(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)(?:\\."
        + "(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)){3}"
    );
    private static final Pattern NUMERIC_HOST = Pattern.compile("[0-9.]+");

    public UrlFeatureVector extract(String submittedUrl) {
        if (submittedUrl == null || submittedUrl.isBlank()) {
            throw new IllegalArgumentException("URL must not be blank");
        }
        if (submittedUrl.length() > 2048) {
            throw new IllegalArgumentException("URL must not exceed 2048 characters");
        }

        String normalized = submittedUrl.trim();
        URI uri = parseUri(normalized);

        String host = normalizedHost(uri.getHost());
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : uri.getRawQuery();
        String lowerUrl = normalized.toLowerCase(Locale.ROOT);

        long specialCharacters = normalized.chars()
            .filter(ch -> "@#$%&*!?=+;~".indexOf(ch) >= 0)
            .count();

        int subdomainCount = host.isEmpty()
            ? 0
            : Math.max(0, host.split("\\.").length - 2);

        long suspiciousKeywordCount = SUSPICIOUS_KEYWORDS.stream()
            .filter(lowerUrl::contains)
            .count();

        Map<String, Double> values = new LinkedHashMap<>();
        values.put("urlLength", (double) normalized.length());
        values.put("domainLength", (double) host.length());
        values.put("subdomainCount", (double) subdomainCount);
        values.put("hasHttps", "https".equalsIgnoreCase(uri.getScheme()) ? 1.0 : 0.0);
        values.put("ipAddress", isIpAddress(host) ? 1.0 : 0.0);
        values.put("userInfo", uri.getRawUserInfo() == null ? 0.0 : 1.0);
        values.put("suspiciousKeywords", (double) suspiciousKeywordCount);
        values.put("specialCharacterCount", (double) specialCharacters);
        values.put("urlEntropy", shannonEntropy(normalized));
        values.put("pathLength", (double) path.length());
        values.put("queryParameterCount", (double) countQueryParameters(query));
        values.put("urlShortener", SHORTENERS.contains(host) ? 1.0 : 0.0);
        values.put("suspiciousDomainStructure",
            (host.contains("-") || subdomainCount >= 3 || uri.getRawUserInfo() != null) ? 1.0 : 0.0);

        return new UrlFeatureVector(values);
    }

    public List<String> indicators(String submittedUrl, UrlFeatureVector features) {
        java.util.ArrayList<String> indicators = new java.util.ArrayList<>();
        URI uri = parseUri(submittedUrl.trim());
        String host = normalizedHost(uri.getHost());

        if (features.get("hasHttps") == 0.0) indicators.add("No HTTPS scheme");
        if (features.get("ipAddress") == 1.0) indicators.add("IP address used instead of domain name");
        if (features.get("userInfo") == 1.0) indicators.add("Credentials or misleading text precede the host");
        if (features.get("suspiciousKeywords") >= 1.0) indicators.add("Suspicious keyword present");
        if (features.get("subdomainCount") >= 3.0) indicators.add("Excessive subdomain structure");
        if (features.get("urlShortener") == 1.0) indicators.add("Known URL shortening domain");
        if (features.get("specialCharacterCount") >= 8.0) indicators.add("Unusually many special characters");
        if (features.get("queryParameterCount") >= 5.0) indicators.add("Many query parameters");
        if (host.contains("-")) indicators.add("Hyphenated domain name");
        return indicators;
    }

    private URI parseUri(String value) {
        boolean hasHttpScheme = value.regionMatches(true, 0, "http://", 0, 7)
            || value.regionMatches(true, 0, "https://", 0, 8);
        if (!hasHttpScheme && value.contains("://")) {
            throw new IllegalArgumentException("Only HTTP and HTTPS URLs are accepted");
        }
        URI uri;
        try {
            uri = new URI(hasHttpScheme ? value : "http://" + value);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        if (!"http".equalsIgnoreCase(uri.getScheme())
            && !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("Only HTTP and HTTPS URLs are accepted");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("URL must contain a valid hostname");
        }

        String host = normalizedHost(uri.getHost());
        if (isBlockedHostname(host)) {
            throw new IllegalArgumentException("Local and metadata hosts cannot be analyzed");
        }
        InetAddress address = parseIpAddress(host);
        if (address != null && isNonPublicAddress(address)) {
            throw new IllegalArgumentException("Local and private IP addresses cannot be analyzed");
        }
        return uri;
    }

    private String normalizedHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.startsWith("[") && normalized.endsWith("]")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private boolean isBlockedHostname(String host) {
        return host.equals("localhost")
            || host.endsWith(".localhost")
            || host.endsWith(".local")
            || BLOCKED_HOSTNAMES.contains(host);
    }

    private boolean isIpAddress(String host) {
        return IPV4.matcher(host).matches() || host.indexOf(':') >= 0;
    }

    private InetAddress parseIpAddress(String host) {
        try {
            if (IPV4.matcher(host).matches()) {
                String[] octets = host.split("\\.");
                byte[] address = new byte[4];
                for (int i = 0; i < octets.length; i++) {
                    address[i] = (byte) Integer.parseInt(octets[i]);
                }
                return InetAddress.getByAddress(address);
            }
            if (NUMERIC_HOST.matcher(host).matches()) {
                throw new IllegalArgumentException("Invalid numeric IP address");
            }
            if (host.indexOf(':') >= 0) {
                return InetAddress.getByName(host);
            }
            return null;
        } catch (java.net.UnknownHostException ex) {
            throw new IllegalArgumentException("Invalid IP address");
        }
    }

    private boolean isNonPublicAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
            || address.isLoopbackAddress()
            || address.isLinkLocalAddress()
            || address.isSiteLocalAddress()
            || address.isMulticastAddress()) {
            return true;
        }
        if (address instanceof Inet6Address) {
            byte[] bytes = address.getAddress();
            return (bytes[0] & 0xfe) == 0xfc;
        }
        return false;
    }

    private int countQueryParameters(String query) {
        if (query.isBlank()) return 0;
        return query.split("&", -1).length;
    }

    private double shannonEntropy(String value) {
        Map<Character, Integer> counts = new LinkedHashMap<>();
        for (char ch : value.toCharArray()) {
            counts.put(ch, counts.getOrDefault(ch, 0) + 1);
        }
        double entropy = 0.0;
        for (int count : counts.values()) {
            double probability = (double) count / value.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }
}
