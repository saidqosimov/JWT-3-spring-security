package com.example.jwtspringsecurity.web.rest.vm;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class LoginVM {
    private String username;
    private String password;
    private Boolean rememberMe;
}
