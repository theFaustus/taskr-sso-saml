package com.evil.inc.taskrssosaml;

import com.evil.inc.taskrssosaml.domain.Task;
import com.evil.inc.taskrssosaml.domain.Priority;
import com.evil.inc.taskrssosaml.domain.User;
import com.evil.inc.taskrssosaml.repository.TaskRepository;
import com.evil.inc.taskrssosaml.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class TaskrSsoSamlApplication {

	public static void main(String[] args) {
		SpringApplication.run(TaskrSsoSamlApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(TaskRepository taskRepository, UserRepository userRepository){
		return args -> {
			User user = userRepository.save(new User("thejohndoe", "john", "doe", 25));
			taskRepository.save(new Task("Read!", "Start reading, at least 30 minutes per day", Priority.HIGH, user));
			taskRepository.save(new Task("Workout", "Need to workout", Priority.HIGH, user));
			taskRepository.save(new Task("Meditate", "Get some mindfulness", Priority.MEDIUM, user));
			taskRepository.save(new Task("Be nice", "Give smiles", Priority.LOW, user));
			taskRepository.save(new Task("Eat bananas", "One banana a day, keeps the doctor away", Priority.LOW, user));
		};
	}
}
