package com.evil.inc.taskrssosaml.web;

import com.evil.inc.taskrssosaml.service.TaskService;
import com.evil.inc.taskrssosaml.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequiredArgsConstructor
public class IndexController {
    private final UserService userService;
    private final TaskService taskService;

    @RequestMapping("/")
    public ModelAndView index(){
        ModelAndView modelAndView = new ModelAndView("index");
        modelAndView.addObject("userTasks", taskService.getTasksByUsername("johndoe"));
        return modelAndView;
    }
}
