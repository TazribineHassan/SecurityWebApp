package com.ensas.securitywebapp.constant;

public class Authorities {
    public static final  String[] USER_AUTHORITIES = {"user:read"};
    public static final  String[] HR_AUTHORITIES = {"user:read", "user:update"};
    public static final  String[] MANAGER_AUTHORITIES = {"user:read", "user:update"};
    public static final  String[] SUPPER_ADMIN_AUTHORITIES = {"user:read", "user:create", "user:update", "user:delete"};
}
