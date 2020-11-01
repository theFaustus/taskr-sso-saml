package com.evil.inc.taskrssosaml.repository;

import com.evil.inc.taskrssosaml.domain.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {
    @Query(nativeQuery = true, value = "select * from tasks where user_id = :userId")
    List<Task> findAllByUserId(long userId);
}
