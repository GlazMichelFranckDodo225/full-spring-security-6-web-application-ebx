package com.dgmf.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*
Filters Incoming Requests to
    - Check for a Valid JWT in the Header,
    - Setting the Authentication Context if the Token is Valid,
    - Extracts JWT from Request Header,
    - Validate the Token,
    - Configure the Spring Security Context with User Details if
    the Token is Valid.
*/
// OncePerRequestFilter ==> Filter base class that aims to
// guarantee a single execution per request dispatch, on
// any servlet container : AuthTokenFilter will Be Executed
// Only Once Per Request
@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserDetailsService userDetailsService;
    private final static Logger LOGGER = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException
        {
            LOGGER.debug("AuthTokenFilter Called for URI : {}", request.getRequestURI());

            try {
                String jwt = parseJwt(request);
                // Beginning of the Validation Process
                if(jwt != null && jwtUtils.validateJwtToken(jwt)) {
                    String username = jwtUtils.getUserNameFromJwtToken(jwt);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    null, userDetails.getAuthorities()
                            );
                    LOGGER.debug("Roles from JWT : {}", userDetails.getAuthorities());
                    // Enhancing Authentication Object with Additional Details from the Request (SessionId, ...)
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch(Exception e) {
                LOGGER.error("Cannot Set User Authentication : {}", e);
            }

            // Hand Over the Request to Next Filter
            filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        LOGGER.debug("AuthTokenFilter.java : {}", jwt);

        return jwt;
    }
}
