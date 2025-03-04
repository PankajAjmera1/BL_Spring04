package org.ajmera.greetingapp.repository;

import org.ajmera.greetingapp.model.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthUserRepository extends JpaRepository<AuthUser,Long> {
//    <optional> AuthUser findByEmail(String email);
//
//    boolean existsByEmail(String email);

    Optional<AuthUser> findByUsername(String username);
}