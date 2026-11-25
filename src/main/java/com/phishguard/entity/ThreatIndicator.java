package com.phishguard.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "threat_indicators")
public class ThreatIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "scan_id", nullable = false)
    private ScanHistory scan;

    @Column(nullable = false, length = 300)
    private String description;

    public Long getId() { return id; }
    public ScanHistory getScan() { return scan; }
    public void setScan(ScanHistory scan) { this.scan = scan; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
