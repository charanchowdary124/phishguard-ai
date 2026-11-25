package com.phishguard.repository;

import com.phishguard.entity.ScanHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {
    List<ScanHistory> findByUserUsernameOrderByScannedAtDesc(String username);

    Optional<ScanHistory> findByIdAndUserUsernameIgnoreCase(Long id, String username);

    @Query("""
        select scan from ScanHistory scan
        where lower(scan.user.username) = lower(:username)
          and (:scanType = '' or upper(scan.scanType) = :scanType)
          and lower(coalesce(scan.inputSummary, '')) like lower(concat('%', :search, '%'))
        """)
    List<ScanHistory> searchMine(
        @Param("username") String username,
        @Param("scanType") String scanType,
        @Param("search") String search,
        Sort sort
    );
}
