package com.eternal.security.domain.dto;

import lombok.Data;

@Data
public class RoleToUserForm {
    private String username;
    private String roleName;
}