package com.JobProtal.Repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.JobProtal.Entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByEmail(String email);

	User findByUsername(String username);
}
