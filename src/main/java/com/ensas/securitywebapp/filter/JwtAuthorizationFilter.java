package com.ensas.securitywebapp.filter;



import com.ensas.securitywebapp.utility.JWTokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;


import static com.ensas.securitywebapp.constant.SecurityConstant.*;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.HttpStatus.*;
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private JWTokenProvider jwTokenProvider;

    public JwtAuthorizationFilter(JWTokenProvider jwTokenProvider) {
        this.jwTokenProvider = jwTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_METHOD)){
            response.setStatus(OK.value());
        }else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_PREFIX)){
                filterChain.doFilter(request, response);
                return;
            }
            String token = authorizationHeader.substring(TOKEN_PREFIX.length()).trim();
            String username = jwTokenProvider.getSubject(token);
            if(jwTokenProvider.isTokenValid(username, token) && SecurityContextHolder.getContext().getAuthentication() == null){
                List<GrantedAuthority> authorities = jwTokenProvider.getAuthorities(token);
                Authentication authentication = jwTokenProvider.getAuthentication(username, authorities, request);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }else {
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request,response);
    }
}
