package com.cloud9ers.jwtldap.jwtcontroller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class home {

    @RequestMapping("/home")
    public String index() {
        return "index";
    }
}
