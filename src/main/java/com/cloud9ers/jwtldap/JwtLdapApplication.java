package com.cloud9ers.jwtldap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtLdapApplication {

    public static void main(final String[] args) {
        System.setProperty("javax.net.ssl.trustStore", "C://cmis//cert_cmis");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        SpringApplication.run(JwtLdapApplication.class, args);
    }
}
