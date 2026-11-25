package com.phishguard.entity;

import jakarta.persistence.Column;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scan_history")
public class ScanHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 20)
    private String scanType;

    @Column(nullable = false, length = 64)
    private String inputHash;

    @Column(name = "input_summary", length = 2048)
    private String inputSummary;

    @Column(nullable = false, length = 30)
    private String prediction;

    @Column(nullable = false, length = 20)
    private String riskCategory;

    @Column(nullable = false)
    private int riskScore;

    @Column(nullable = false, length = 50)
    private String modelVersion;

    @Column(nullable = false)
    private Instant scannedAt = Instant.now();

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ThreatIndicator> indicators = new ArrayList<>();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public String getScanType() { return scanType; }
    public void setScanType(String scanType) { this.scanType = scanType; }
    public String getInputHash() { return inputHash; }
    public void setInputHash(String inputHash) { this.inputHash = inputHash; }
    public String getInputSummary() { return inputSummary; }
    public void setInputSummary(String inputSummary) { this.inputSummary = inputSummary; }
    public String getPrediction() { return prediction; }
    public void setPrediction(String prediction) { this.prediction = prediction; }
    public String getRiskCategory() { return riskCategory; }
    public void setRiskCategory(String riskCategory) { this.riskCategory = riskCategory; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public String getModelVersion() { return modelVersion; }
    public void setModelVersion(String modelVersion) { this.modelVersion = modelVersion; }
    public Instant getScannedAt() { return scannedAt; }
    public void setScannedAt(Instant scannedAt) { this.scannedAt = scannedAt; }
    public List<ThreatIndicator> getIndicators() { return indicators; }
}
