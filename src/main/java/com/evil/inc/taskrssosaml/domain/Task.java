package com.evil.inc.taskrssosaml.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.time.LocalDateTime;

@Data
@EqualsAndHashCode(callSuper = true)
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "tasks")
public class Task extends AbstractEntity{
    private String name;
    private String description;
    private final LocalDateTime creationDateTime = LocalDateTime.now();
    @Enumerated(value = EnumType.STRING)
    private Priority priority;
    @ManyToOne
    private User user;
}
