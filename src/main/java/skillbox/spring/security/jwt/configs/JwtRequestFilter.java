package skillbox.spring.security.jwt.configs;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import skillbox.spring.security.jwt.utils.CookieTokenExtractor;
import skillbox.spring.security.jwt.utils.JwtTokenUtils;

import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtTokenUtils jwtTokenUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = CookieTokenExtractor.extractToken(request);
        String username = null;

        if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtTokenUtils.validateToken(jwt)) {
                username = jwtTokenUtils.getUsername(jwt);

                Collection<? extends GrantedAuthority> authorities = jwtTokenUtils.getRoles(jwt).stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(username, jwt, authorities);
                authenticationToken.setAuthenticated(true); // обязательно установить
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
