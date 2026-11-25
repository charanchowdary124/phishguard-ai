package com.phishguard.repository;

import com.phishguard.entity.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsernameIgnoreCase(String username);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where lower(u.username) = lower(:username)")
    Optional<User> findByUsernameIgnoreCaseForUpdate(@Param("username") String username);
    boolean existsByUsernameIgnoreCase(String username);
    boolean existsByEmailIgnoreCase(String email);
    boolean existsByUsernameIgnoreCaseAndIdNot(String username, Long id);
    boolean existsByEmailIgnoreCaseAndIdNot(String email, Long id);
}
