package payroll.auth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Verifies the bearer token in the request header
 * and updates the SecurityContext accordingly.
 */
@Component
public class RestOAuth2AuthorizationFilter extends GenericFilterBean {

    private final String authenticationHeader = "Authorization";
    private final String authenticationScheme = "Bearer";
    
    @Autowired
    private TokenManager tokenManager;
    
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        var token = extractToken((HttpServletRequest)request);
        if (token != null && StringUtils.hasText(token)) {
            var authentication = tokenManager.get(token);
            if (authentication != null) {
                // Received valid token, set the security context and allow user
                //
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }

    // Extracts the bearer token from the request header
    //
    private String extractToken(HttpServletRequest request) {
        var bearerToken = request.getHeader(authenticationHeader);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(authenticationScheme)) {
            return bearerToken.substring(authenticationScheme.length() + 1);
        }
        return null;
    }
}
