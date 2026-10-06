package com.example;

public class Auth {
    public boolean authenticate(String password) {
        if (password == null) {
            return false;
        }
        return password.equals("secret");
    }
}
