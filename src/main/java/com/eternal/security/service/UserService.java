package com.eternal.security.service;

import com.eternal.security.domain.model.Role;
import com.eternal.security.domain.model.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> getUsers();
}
