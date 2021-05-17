package com.ensas.securitywebapp.enumeration;

import com.ensas.securitywebapp.constant.Authorities;

import static com.ensas.securitywebapp.constant.Authorities.*;

public enum Role {
    ROLE_USER(USER_AUTHORITIES),
    ROLE_HR(HR_AUTHORITIES),
    ROLE_MANAGER(MANAGER_AUTHORITIES),
    ROLE_ADMIN(MANAGER_AUTHORITIES),
    ROLE_SUPPER_ADMIN(SUPPER_ADMIN_AUTHORITIES);

    private String[] authorities;

    Role(String... authorities) {
        this.authorities = authorities;
    }

    public String[] getAuthorities(){
        return authorities;
    }
}
