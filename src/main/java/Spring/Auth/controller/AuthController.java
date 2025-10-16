package Spring.Auth.controller;

import Spring.Auth.dtos.LoginRequestDto;
import Spring.Auth.dtos.LoginResponseDto;
import Spring.Auth.dtos.RegisterUserDto;
import Spring.Auth.entity.UserEntity;
import Spring.Auth.repository.UserRepository;
import Spring.Auth.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public AuthController(JwtUtil jwtUtil, UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterUserDto> registerUser(@RequestBody UserEntity user) {
        System.out.println("registerUserDto" + user);
        UserEntity isUserExist = userRepository.findByUsername(user.getUsername());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (isUserExist != null) {
            ResponseEntity.status(401).body("Username already taken");
        }
        UserEntity registeredUser = userRepository.save(user);
        return ResponseEntity.status(200).body(RegisterUserDto.builder().id(registeredUser.getId()).username(registeredUser.getUsername()).build());
    }

    @PostMapping("/sign-in")
    public ResponseEntity<LoginResponseDto> signInUser(@RequestBody LoginRequestDto loginPayload) throws Exception {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginPayload.getUsername(), loginPayload.getPassword())
        );
        System.out.println(authentication);
        System.out.println(authentication.isAuthenticated());
        String accessToken = jwtUtil.generateJwtToken(loginPayload.getUsername(), 5);
        String RefreshToken = jwtUtil.generateJwtToken(loginPayload.getUsername(), 60 * 24 * 7);
        if (!authentication.isAuthenticated()) {
            throw new RuntimeException("User authentication failed....!");
        }
        UserEntity user = (UserEntity) authentication.getPrincipal();
        if (user != null) {
            user.setRefreshToken(RefreshToken);
            userRepository.save(user);
        }
        return ResponseEntity
                .status(201)
                .header("Authorization", "Bearer " + accessToken)
                .body(new LoginResponseDto(authentication.getName(), accessToken, RefreshToken));
    }
}
