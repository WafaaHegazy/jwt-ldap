package com.cloud9ers.jwtldap.jwtcontroller;

import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.cloud9ers.jwtldap.jwtUser.JwtUser;
import com.cloud9ers.jwtldap.jwtcalls.JwtRequest;
import com.cloud9ers.jwtldap.jwtcalls.JwtResponse;
import com.cloud9ers.jwtldap.jwtconfig.JwtTokenUtil;


@RestController
public class AuthenticationRestController {

    private final Log logger = LogFactory.getLog(this.getClass());

    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    // @Autowired
    // private UserDetailsService userDetailsService;

    @RequestMapping(value = "${jwt.route.authentication.path}", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody final JwtRequest authenticationRequest) throws AuthenticationException {
        logger.info("/auth ");
        // Perform the security
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUsername(),
                        authenticationRequest.getPassword()
                        )
                );
        logger.info("authentication ");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Reload password post-security so we can generate token
        final String username = authenticationRequest.getUsername();
        final Date creationDate = new Date();
        final UserDetails userDetails = new JwtUser(username, creationDate);
        final String token = jwtTokenUtil.generateToken(userDetails);
        logger.info("token created");
        // Return the token
        return ResponseEntity.ok(new JwtResponse(token));
    }

    // @RequestMapping(value = "${jwt.route.authentication.refresh}", method = RequestMethod.GET)
    // public ResponseEntity<?> refreshAndGetAuthenticationToken(final HttpServletRequest request) {
    // final String token = request.getHeader(tokenHeader);
    // final String username = jwtTokenUtil.getUsernameFromToken(token);
    // userDetailsService.loadUserByUsername(username);
    //
    // if (jwtTokenUtil.canTokenBeRefreshed(token)) {
    // final String refreshedToken = jwtTokenUtil.refreshToken(token);
    // return ResponseEntity.ok(new JwtResponse(refreshedToken));
    // } else {
    // return ResponseEntity.badRequest().body(null);
    // }
    // }

}
