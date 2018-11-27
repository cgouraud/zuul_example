package com.example.beercatalogservice;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.springframework.boot.CommandLineRunner;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter @Setter @AllArgsConstructor 
@NoArgsConstructor
public class User implements Serializable{
	@Id
	@GeneratedValue
	private Long id;
	private String name;
	private String email;
	
}
@RepositoryRestResource
interface UserRepository extends JpaRepository<User, Long> {}
@Component
class UserInitializer implements CommandLineRunner {

  private final UserRepository userRepository;

  UserInitializer(UserRepository userRepository) {
      this.userRepository = userRepository;
  }

  @Override
  public void run(String... args) throws Exception {
	  userRepository.save(new User(Long.valueOf(1),"celine","celine@yopmail.com"));

      userRepository.findAll().forEach(System.out::println);
  }
}