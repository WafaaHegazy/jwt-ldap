package com.cloud9ers.jwtldap.jwtconfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

    // @Autowired
    // private UserDetailsService userDetailsService;
    //
    // @Autowired
    // public void configureAuthentication(final AuthenticationManagerBuilder authenticationManagerBuilder) throws
    // Exception {
    // authenticationManagerBuilder
    // .userDetailsService(this.userDetailsService);
    //
    // }


    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationTokenFilter();
    }

    @Override
    protected void configure(final HttpSecurity httpSecurity) throws Exception {
        httpSecurity
        // we don't need CSRF because our token is invulnerable
        .csrf().disable()

        .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()

        // don't create session
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

        .authorizeRequests()
        //.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

        // allow anonymous resource requests
        .antMatchers(
                HttpMethod.GET,
                "/",
                "/*.html",
                "/favicon.ico",
                "/**/*.html",
                "/**/*.css",
                "/**/*.js"
                ).permitAll()
        .antMatchers("/auth/**").permitAll()
        .anyRequest().authenticated();

        // Custom JWT based security filter
        httpSecurity
        .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

        // disable page caching
        httpSecurity.headers().cacheControl();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        /*
         * Overloaded to expose Authenticationmanager's bean created by configure(AuthenticationManagerBuilder). This
         * bean is used by the AuthenticationController.
         */
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        final LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldaps://192.168.100.123:3269/");
        contextSource.setBase("DC=c9,DC=local");
        contextSource.setUserDn("CN=Admin,CN=Users,DC=c9,DC=local");
        contextSource.setPassword("Cloud9ers");
        contextSource.afterPropertiesSet();

        final LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthenticationProviderConfigurer = authenticationManagerBuilder
                .ldapAuthentication();
        ldapAuthenticationProviderConfigurer.contextSource(contextSource).userSearchFilter("sAMAccountName={0}");

        // WAY 2
        /*
         * authenticationManagerBuilder.ldapAuthentication()
         * .contextSource().url("ldaps://192.168.100.123:3269/dc=c9,dc=local")
         * .managerDn("CN=Admin,cn=Users,dc=c9,dc=local").managerPassword("Cloud9ers") .and()
         * .userSearchFilter("sAMAccountName={0}"); // login with all users except Domain Admin because Domain Admin
         * doesn't have userPrincipal name
         * //.userSearchBase("CN=Users").userSearchFilter("(userPrincipalName={0}@c9.local)");
         */
    }
}