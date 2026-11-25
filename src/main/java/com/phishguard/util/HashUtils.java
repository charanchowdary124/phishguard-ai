package com.phishguard.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Cryptographic Utility for Hashing Scan Targets and Identifiers.
 * Protects user privacy by storing SHA-256 hashes instead of raw sensitive content.
 */
public final class HashUtils {

    private HashUtils() {
        // Utility class
    }

    public static String sha256Hex(String input) {
        if (input == null) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available in JVM", e);
        }
    }
}
