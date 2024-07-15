package com.dgmf.controller;

import com.dgmf.dto.LoginRequest;
import com.dgmf.dto.LoginResponse;
import com.dgmf.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello User !";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Hello Admin !";
    }

    @PostMapping({"/signin", "/login"})
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        // Authentication Object
        Authentication authentication;
        try {
            // A Authentication Token is Created using Username and Password
            // and Try to Authenticate the User using AuthenticationManager
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                                    loginRequest.getUsername(), loginRequest.getPassword()
                            )
                    );
        } catch(AuthenticationException exception) {
            // Format the Error Response
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad Credentials");
            map.put("status", false);

            // Send Back the Error Response
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        // Set the User Authentication in the Security Context for the Session
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // Generate the JWT Token for the Authenticated User using the User Details
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
        // Get Roles of the Authenticated User in Order to Pass Them to the Response
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        LoginResponse response = new LoginResponse(
                jwtToken, userDetails.getUsername(), roles
        );

        // Send Back the Response
        return ResponseEntity.ok(response);
    }

}
