package Spring.Auth.controller;

import Spring.Auth.dtos.LoginRequestDto;
import Spring.Auth.dtos.LoginResponseDto;
import Spring.Auth.dtos.RegisterUserDto;
import Spring.Auth.entity.UserEntity;
import Spring.Auth.repository.UserRepository;
import Spring.Auth.util.JwtUtil;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class UserController {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    public UserController(JwtUtil jwtUtil, UserRepository userRepository, PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
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
        UserEntity user = (UserEntity) userDetailsService.loadUserByUsername(loginPayload.getUsername());
        if (user == null) {
            throw new Exception("user not found");
        }
        String accessToken = jwtUtil.generateJwtToken(user.getUsername(), 5);
        String RefreshTokenToken = jwtUtil.generateJwtToken(user.getUsername(), 60 * 24 * 7);
        user.setRefreshToken(RefreshTokenToken);
        userRepository.save(user);
        return ResponseEntity
                .status(201)
                .header("Authorization", "Bearer " + accessToken)
                .body(new LoginResponseDto(user.getId(), accessToken, user.getRefreshToken()));
    }
}
