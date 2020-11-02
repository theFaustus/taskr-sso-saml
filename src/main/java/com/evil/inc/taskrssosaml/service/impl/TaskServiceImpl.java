package com.evil.inc.taskrssosaml.service.impl;

import com.evil.inc.taskrssosaml.domain.Task;
import com.evil.inc.taskrssosaml.domain.User;
import com.evil.inc.taskrssosaml.repository.TaskRepository;
import com.evil.inc.taskrssosaml.repository.UserRepository;
import com.evil.inc.taskrssosaml.service.TaskService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;

@Service
@RequiredArgsConstructor
class TaskServiceImpl implements TaskService {
    private final TaskRepository taskRepository;
    private final UserRepository userRepository;

    @Transactional
    @Override
    public Task addTask(Task task) {
        return taskRepository.save(task);
    }

    @Transactional
    @Override
    public List<Task> getTasksByUsername(String username) {
        User user = userRepository.findByUsername(username);
        List<Task> allByUserId = taskRepository.findAllByUserId(user.getId());
        allByUserId.sort(Comparator.comparing(Task::getCreationDateTime).reversed());
        return allByUserId;
    }

    @Override
    public void deleteTaskById(long id) {
        taskRepository.deleteById(id);
    }
}
