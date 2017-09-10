package com.cloud9ers.jwtldap.jwtcalls;

import java.io.Serializable;

public class JwtRequest implements Serializable {


    private String username;

    private String password;

    public JwtRequest() {
        super();
    }

    public JwtRequest(final String username, final String password) {
        this.setUsername(username);
        this.setPassword(password);
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }
}
