package com.phishguard.repository;

import com.phishguard.entity.ModelRegistry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ModelRegistryRepository extends JpaRepository<ModelRegistry, Long> {
    Optional<ModelRegistry> findByModelVersion(String modelVersion);
}
