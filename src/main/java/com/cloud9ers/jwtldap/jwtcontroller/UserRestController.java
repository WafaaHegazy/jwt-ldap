package com.cloud9ers.jwtldap.jwtcontroller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.cloud9ers.jwtldap.jwtconfig.JwtTokenUtil;


@RestController
public class UserRestController {

    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    // @Autowired
    // private UserDetailsService userDetailsService;

    @RequestMapping(value = "user", method = RequestMethod.GET)
    public String getAuthenticatedUser(final HttpServletRequest request) {
        final String token = request.getHeader(tokenHeader);
        final String username = jwtTokenUtil.getUsernameFromToken(token);
        // final JwtUser user = (JwtUser) userDetailsService.loadUserByUsername(username);
        return username;
    }

}
