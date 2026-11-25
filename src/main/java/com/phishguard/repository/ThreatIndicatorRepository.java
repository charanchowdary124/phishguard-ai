package com.phishguard.repository;

import com.phishguard.entity.ThreatIndicator;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ThreatIndicatorRepository extends JpaRepository<ThreatIndicator, Long> {
}
