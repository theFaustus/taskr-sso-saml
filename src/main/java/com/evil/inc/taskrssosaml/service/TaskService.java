package com.evil.inc.taskrssosaml.service;

import com.evil.inc.taskrssosaml.domain.Task;

import java.util.List;

public interface TaskService {
    Task addTask(Task task);
    List<Task> getTasksByUsername(String username);
    void deleteTaskById(long id);
}
