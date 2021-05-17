package com.ensas.securitywebapp.listeners;

import com.ensas.securitywebapp.Services.LoginAttemptService;
import com.ensas.securitywebapp.domain.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessListener {
    private LoginAttemptService loginAttemptService;

    @Autowired
    public AuthenticationSuccessListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event){
        Object userPrincipal = event.getAuthentication().getPrincipal();
        if(userPrincipal instanceof UserPrincipal){
            UserPrincipal user = (UserPrincipal)userPrincipal;
            loginAttemptService.evictUserFromLoginAttemptCache(((UserPrincipal) userPrincipal).getUsername());
        }
    }
}
