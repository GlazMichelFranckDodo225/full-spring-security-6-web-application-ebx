package com.dgmf.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/*
Provides Custom Handling for Unauthorized Requests, Typically when Authentication
is Required but not Supplied or Valid :
When an Unauthorized Request is Detected, this Class Logs the Error and Returns
a JSON with :
    - Error Message,
    - Status Code,
    - The Path Attempted.
*/
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {
    private final static Logger LOGGER =
            LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException, ServletException
        {
            LOGGER.error("Unauthorized Error : {}", authException.getMessage());
            // System.out.println(authException);

            // Set Content Type and the Authorization
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            final Map<String, Object> body = new HashMap<>();
            body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            body.put("error", "Unauthorized");
            body.put("message", authException.getMessage());
            // Url the User tries to Access
            body.put("path", request.getServletPath());

            // Send Back the Response
            final ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(response.getOutputStream(), body);
    }
}
