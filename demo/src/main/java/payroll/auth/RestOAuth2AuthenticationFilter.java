package payroll.auth;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * First security filter in the chain
 * 
 * Checks if request is received for /auth/google endpoint for code authorization,
 * if not just passes the request to next filter in the chain
 * 
 * If request is for /auth/google: does the following
 * 
 * Extracts the code from the request
 * 
 * Exchanges access token with code from Google
 * 
 * If token exchange is successful, generates the JWT token from Google auth result and
 * saves it into Token cache and passes the request to next filter in the chain
 * 
 * If token exchange is not successful, returns unauthorized response.
 * 
 */
@Component
public class RestOAuth2AuthenticationFilter extends GenericFilterBean {

    private AntPathRequestMatcher requestMatcher
        = new AntPathRequestMatcher("/auth/google", HttpMethod.POST.name());
        
    private final String baseUri = "/auth";
    // For now defaulting to google.
    private final String registrationId = "google";

    private final String nonceParameterName = "nonce";
    private final String contentTypeHeader = "Content-Type";

    // This doesn't matter as we are using JS/Mobile clients instead of redirect flow
    private final String redirectUri = "postmessage";

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Autowired
    private UserService appUserService;

    @Autowired
    private TokenManager tokenManager;

    private DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver;
    private AuthenticationManager authenticationManager;

    @PostConstruct
    public void PostConstruct()
    {
        var accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        var userService = new OidcUserService();

        authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, baseUri);
        
        var authenticationProvider = new OidcAuthorizationCodeAuthenticationProvider(accessTokenResponseClient, userService);

        authenticationManager = new ProviderManager(authenticationProvider);

        authorizationRequestResolver.setAuthorizationRequestCustomizer(
            builder ->
            builder
                .redirectUri(redirectUri)
                .additionalParameters(params -> { params.remove(nonceParameterName);})
                .attributes(attrs -> { attrs.remove(nonceParameterName);})
                .build()
        );
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;

        if (!requireAuthentication(request)) {
            // This request is not for OAuth access token exchange, i.e: /oauth/google
            // Proceeding to next filter in the chain
            chain.doFilter(request, response);
            return;
        }

        // We have received request for access token exchange(/oauth/google)
        //
        try {
            OAuth2AuthenticationToken authentication = authenticate(request, response);

            successfulAuthentication(response, authentication);
        } catch (Exception e) {
            unsuccessfulAuthentication(response, e);
        }
    }

    private boolean requireAuthentication(HttpServletRequest request)
    {
        return requestMatcher.matches(request);
    }

    private OAuth2AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response) {
        var code = readCode(request);

        System.out.println("received code: " + code);
        if (code == null || code.isEmpty()) {
            throw new OAuth2AuthenticationException(new OAuth2Error("authentication_code_missing"));
        }
        // var registrationId = requestMatcher.matcher(request).variables[registrationIdUriVariableName]
        //         ?: throw OAuth2AuthenticationException(OAuth2Error("client_registration_not_found"))
        var clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("client_registration_not_found"));
        }

        var authorizationRequest = authorizationRequestResolver.resolve(request, registrationId);

        var authorizationResponse = OAuth2AuthorizationResponse
                .success(code)
                .redirectUri(redirectUri)
                .state(authorizationRequest.getState())
                .build();

        var authenticationRequest = new OAuth2LoginAuthenticationToken(
                clientRegistration,
                new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));

        // This sends request to google for exchanging Access/Refresh tokens.
        var authenticationResult = (OAuth2LoginAuthenticationToken)authenticationManager.authenticate(authenticationRequest);

        // Received auth result, create user profile from the auth result
        var user = appUserService.findOrCreateUser(authenticationResult);

        var authorities = mergeAuthorities(authenticationResult, user);

        // This code is for spring auth management
        // from google result
        var oauth2Authentication = new OAuth2AuthenticationToken(
                authenticationResult.getPrincipal(),
                authorities,
                authenticationResult.getClientRegistration().getRegistrationId());

        var authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(),
                oauth2Authentication.getName(),
                authenticationResult.getAccessToken(),
                authenticationResult.getRefreshToken());

        authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);

        return oauth2Authentication;
    }

    // Read authorization code from http request.
    private String readCode(HttpServletRequest request) {
        try {
            var requestContent = request.getReader().lines().collect(Collectors.joining());
            JsonParser jsonParser = JsonParserFactory.getJsonParser();
            Map<String, Object> map = jsonParser.parseMap(requestContent);

            if (map.containsKey("code")) {
                return (String)map.get("code");
            }

            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private  Collection<GrantedAuthority> mergeAuthorities(OAuth2LoginAuthenticationToken authentication, UserDetails user) {
        var authorities = new HashSet<GrantedAuthority>();
        authorities.addAll(authentication.getAuthorities());
        authorities.addAll(user.getAuthorities());
        return authorities;
    }

    private void successfulAuthentication(HttpServletResponse response, OAuth2AuthenticationToken authentication) throws JsonProcessingException, IOException {

        // Set the authentication token to spring security context.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // On successful auth, generate JWT token using token manager.
        // JWT token is formed by hashing the authentication object by signing it with secret key
        // This will be secure and used as bearer token for further api calls
        //
        var token = tokenManager.generate(authentication);
        tokenManager.set(token, authentication);

        response.addHeader(contentTypeHeader, MediaType.APPLICATION_JSON_VALUE);
        ObjectMapper mapper = new ObjectMapper();
        
        // Write the JWT token to the response.
        response.getWriter().println(
            mapper.writerWithDefaultPrettyPrinter().writeValueAsString(new TokenResponse(token)));
    }

    private void unsuccessfulAuthentication(HttpServletResponse response, Exception exception) throws IOException {
        SecurityContextHolder.clearContext();
        // Auth failed, return unauthorized response.
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, exception.getMessage());
    }

    private class TokenResponse
    {
        public String token;
        
        public TokenResponse(String token) {
            this.token = token;
        }
    }
}
