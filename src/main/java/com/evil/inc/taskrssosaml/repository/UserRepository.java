package com.evil.inc.taskrssosaml.repository;

import com.evil.inc.taskrssosaml.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
