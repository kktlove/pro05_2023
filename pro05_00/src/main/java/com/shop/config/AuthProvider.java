package com.shop.config;

import com.shop.entity.UserRole;
import com.shop.service.UserService;
import com.shop.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class AuthProvider implements AuthenticationProvider {

    @Autowired
    private UserService userService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        log.info("ID : "+username);
        log.info("PW : "+password);
        PasswordEncoder passwordEncoder = userService.passwordEncoder();
        UsernamePasswordAuthenticationToken token;
        User userVo = userService.findByUserId(username);
        UserRole userRole = userService.getUserRole(userVo.getId());

        log.info("DB user number : "+userVo.getId());
        log.info("DB user id : "+userVo.getUsername());
        log.info("DB user password : "+ userVo.getPassword());
        log.info("DB user role : "+ userRole.getRoleId());

        if (userVo != null && passwordEncoder.matches(password, userVo.getPassword())) { // 일치하는 user 정보가 있는지 확인
            List<GrantedAuthority> roles = new ArrayList<>();
            if(userRole.getRoleId()==1){
                roles.add(new SimpleGrantedAuthority("ADMIN")); // 권한 부여
            }
            token = new UsernamePasswordAuthenticationToken(userVo.getId(), null, roles);
            return token;
        }

        throw new BadCredentialsException("No such user or wrong password.");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
