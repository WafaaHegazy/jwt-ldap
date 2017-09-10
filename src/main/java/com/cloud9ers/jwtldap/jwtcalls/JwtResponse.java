package com.cloud9ers.jwtldap.jwtcalls;

import java.io.Serializable;

public class JwtResponse implements Serializable {


    private final String token;

    public JwtResponse(final String token) {
        this.token = token;
    }

    public String getToken() {
        return this.token;
    }
}
