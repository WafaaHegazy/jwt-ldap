package com.cloud9ers.jwtldap.jwtUser;


import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * All user information handled by the JWT token
 */
public class JwtUser implements UserDetails {

    private String username;

    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    private Date creationDate;

    public JwtUser(final String username, final Date creationDate) {
        this(username, creationDate, Collections.EMPTY_LIST);
    }

    public JwtUser(final String username, final Date creationDate, final Collection<? extends GrantedAuthority> authorities) {
        this.username = username;
        this.creationDate = creationDate;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        // no password inside JWT token.
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // A token is never locked
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // == token expiration
        // TODO
        return true;
    }

    @Override
    public boolean isEnabled() {
        // always enabled in JWT case.
        return true;
    }
}