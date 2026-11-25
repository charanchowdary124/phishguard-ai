package com.phishguard.ml;

import java.util.Map;

public record EmailFeatureVector(Map<String, Double> values) {
    public EmailFeatureVector {
        values = Map.copyOf(values);
    }

    public double get(String name) {
        return values.getOrDefault(name, 0.0);
    }
}
