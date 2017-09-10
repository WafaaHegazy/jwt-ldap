package com.cloud9ers.jwtldap.jwtconfig;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.cloud9ers.jwtldap.jwtUser.JwtUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -3301605591108950415L;

    static final String CLAIM_KEY_USERNAME = "sub";
    static final String CLAIM_KEY_AUDIENCE = "audience";
    static final String CLAIM_KEY_CREATED = "created";
    static final String CLAIM_KEY_EXPIRED = "exp";

    static final String AUDIENCE_UNKNOWN = "unknown";
    static final String AUDIENCE_WEB = "web";
    static final String AUDIENCE_MOBILE = "mobile";
    static final String AUDIENCE_TABLET = "tablet";



    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public String getUsernameFromToken(final String token) {
        String username;
        try {
            final Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();
        } catch (final Exception e) {
            username = null;
        }
        return username;
    }

    public Date getCreatedDateFromToken(final String token) {
        Date created;
        try {
            final Claims claims = getClaimsFromToken(token);
            created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
        } catch (final Exception e) {
            created = null;
        }
        return created;
    }

    public Date getExpirationDateFromToken(final String token) {
        Date expiration;
        try {
            final Claims claims = getClaimsFromToken(token);
            expiration = claims.getExpiration();
        } catch (final Exception e) {
            expiration = null;
        }
        return expiration;
    }

    public String getAudienceFromToken(final String token) {
        String audience;
        try {
            final Claims claims = getClaimsFromToken(token);
            audience = (String) claims.get(CLAIM_KEY_AUDIENCE);
        } catch (final Exception e) {
            audience = null;
        }
        return audience;
    }

    private Claims getClaimsFromToken(final String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (final Exception e) {
            claims = null;
        }
        return claims;
    }

    private Boolean isTokenExpired(final String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
    private Boolean ignoreTokenExpiration(final String token) {
        final String audience = getAudienceFromToken(token);
        return AUDIENCE_TABLET.equals(audience) || AUDIENCE_MOBILE.equals(audience);
    }

    public String generateToken(final UserDetails userDetails) {
        final Map<String, Object> claims = new HashMap<>();

        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());


        final Date createdDate = new Date();
        claims.put(CLAIM_KEY_CREATED, createdDate);

        return doGenerateToken(claims);
    }

    private String doGenerateToken(final Map<String, Object> claims) {
        final Date createdDate = (Date) claims.get(CLAIM_KEY_CREATED);
        final Date expirationDate = new Date(createdDate.getTime() + expiration * 1000);

        System.out.println("doGenerateToken " + createdDate);

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public Boolean canTokenBeRefreshed(final String token) {
        return !isTokenExpired(token) || ignoreTokenExpiration(token);
    }

    public String refreshToken(final String token) {
        String refreshedToken;
        try {
            final Claims claims = getClaimsFromToken(token);
            claims.put(CLAIM_KEY_CREATED, new Date());
            refreshedToken = doGenerateToken(claims);
        } catch (final Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }

    public Boolean validateToken(final String token, final UserDetails userDetails) {
        final JwtUser user = (JwtUser) userDetails;
        final String username = getUsernameFromToken(token);
        getCreatedDateFromToken(token);
        return username.equals(user.getUsername())
                && !isTokenExpired(token);

    }
}