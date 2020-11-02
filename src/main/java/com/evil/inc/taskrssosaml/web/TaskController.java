package com.evil.inc.taskrssosaml.web;

import com.evil.inc.taskrssosaml.domain.Priority;
import com.evil.inc.taskrssosaml.domain.Task;
import com.evil.inc.taskrssosaml.service.TaskService;
import com.evil.inc.taskrssosaml.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequiredArgsConstructor
@RequestMapping("/")
public class TaskController {
    private final UserService userService;
    private final TaskService taskService;

    @GetMapping
    public ModelAndView tasks(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        ModelAndView modelAndView = new ModelAndView("tasks");
        modelAndView.addObject("userName", authentication.getName());
        modelAndView.addObject("userTasks", taskService.getTasksByUsername(authentication.getName()));
        modelAndView.addObject("priorities", Priority.values());
        modelAndView.addObject("task", new Task());
        return modelAndView;
    }

    @PostMapping("/add")
    public ModelAndView addTask(@ModelAttribute Task task){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        task.setUser(userService.getByUsername(authentication.getName()));
        taskService.addTask(task);
        return new ModelAndView("redirect:/");
    }

    @PostMapping("/delete/{taskId}")
    public ModelAndView deleteTask(@PathVariable long taskId){
        taskService.deleteTaskById(taskId);
        return new ModelAndView("redirect:/");
    }
}
