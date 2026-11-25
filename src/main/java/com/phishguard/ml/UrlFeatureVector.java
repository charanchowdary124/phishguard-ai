package com.phishguard.ml;

import java.util.LinkedHashMap;
import java.util.Map;

public record UrlFeatureVector(Map<String, Double> values) {
    public UrlFeatureVector {
        values = Map.copyOf(new LinkedHashMap<>(values));
    }

    public double get(String name) {
        return values.getOrDefault(name, 0.0);
    }

    public Map<String, Double> asMap() {
        return values;
    }
}
