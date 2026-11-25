package com.phishguard.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "model_registry")
public class ModelRegistry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String modelVersion;

    @Column(nullable = false, length = 20)
    private String modelType;

    @Column(nullable = false)
    private boolean active;

    @Column(nullable = false)
    private Instant registeredAt = Instant.now();

    public Long getId() { return id; }
    public String getModelVersion() { return modelVersion; }
    public void setModelVersion(String modelVersion) { this.modelVersion = modelVersion; }
    public String getModelType() { return modelType; }
    public void setModelType(String modelType) { this.modelType = modelType; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public Instant getRegisteredAt() { return registeredAt; }
}
