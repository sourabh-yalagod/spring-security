package Spring.Auth.filter;

import Spring.Auth.types.AuthUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final AuthUtil authUtil;

    public JwtAuthFilter(AuthUtil authUtil) {
        this.authUtil = authUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getServletPath();
        if (path.startsWith("/api/auth/")
                || path.startsWith("/login")
                || path.startsWith("/oauth2/")
                || path.startsWith("/error")) {
            filterChain.doFilter(request, response);
            return;
        }
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.split("Bearer ")[1].isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
                        {
                          "status": 401,
                          "error": "Unauthorized",
                          "message": "Invalid or expired token"
                        }
                    """);
            response.getWriter().flush();
            return;
        }
        String token = authorization.split("Bearer ")[1];
        boolean isValidToken = authUtil.validateToken(token);
        if (!isValidToken) {
            if (!isValidToken) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("""
                            {
                              "status": 401,
                              "error": "Unauthorized",
                              "message": "Invalid or expired token"
                            }
                        """);
                response.getWriter().flush();
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
