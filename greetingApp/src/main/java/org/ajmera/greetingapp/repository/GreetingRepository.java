package org.ajmera.greetingapp.repository;

import org.ajmera.greetingapp.model.Greeting;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GreetingRepository extends JpaRepository<Greeting,Long> {

}
