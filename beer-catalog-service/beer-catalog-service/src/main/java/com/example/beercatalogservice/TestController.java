package com.example.beercatalogservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

import javax.inject.Inject;

@RestController
public class TestController {
	
	@Autowired
	private UserRepository repo;
	

    @GetMapping("/catalog/test")
    public Principal getUser(Model model, Principal principal) {
    	return principal;
    }
    
    @GetMapping("/catalog/users")
    public List<User> getAll() {
    	return repo.findAll();
    }
}