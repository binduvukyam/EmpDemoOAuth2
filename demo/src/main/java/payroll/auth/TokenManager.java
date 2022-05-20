package payroll.auth;

import java.util.Date;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.Cache.ValueWrapper;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 * Generates JWT token 
 */
@Component
public class TokenManager {
    private final String claimAuthorities = "authorities";
    private final String claimName = "name";
    private final String claimEmail = "email";
    // This will be the secret to sign the JWT token, should be saved to properties/env config.
    private final String secret = "qsbWaaBHBN/I7FYOrev4yQFJm60sgZkWIEDlGtsRl7El/k+DbUmg8nmWiVvEfhZ91Y67Sc6Ifobi05b/XDwBy4kXUcKTitNqocy7rQ9Z3kMipYjbL3WZUJU2luigIRxhTVNw8FXdT5q56VfY0LcQv3mEp6iFm1JG43WyvGFV3hCkhLPBJV0TWnEi69CfqbUMAIjmymhGjcbqEK8Wt10bbfxkM5uar3tpyqzp3Q==";
    private final SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    
    @Autowired
    private CacheManager cacheManager;

    private Cache cache;

    @PostConstruct
    public void PostConstruct() {
        cache = cacheManager.getCache("tokenManager");
    }
    
    public OAuth2AuthenticationToken get(String token)  {
        if (validate(token)) {
            ValueWrapper cachedToken = cache.get(token);
            if (cachedToken != null) {
                return (OAuth2AuthenticationToken)cachedToken.get();
            }
        } else {
            cache.evict(token);
        }
        return null;
    }

    public void set(String token, OAuth2AuthenticationToken authentication) {
        // For now save token to in-memory cache, can be moved to db/redis
        // for distributed setup.
        cache.put(token, authentication);
    }

    public String generate(OAuth2AuthenticationToken authentication) {
        var subject = authentication.getName();
        var name = authentication.getPrincipal().getAttributes().get("name");
        var email = authentication.getPrincipal().getAttributes().get("email");

        String authorities = "";
        if (authentication.getAuthorities() != null) {
            authentication.getAuthorities().stream().map(x -> x.getAuthority())
                .collect(Collectors.toList()).stream().collect(Collectors.joining(""));
        }
        var expiration = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
        return Jwts.builder()
                .setSubject(subject)
                .claim(claimAuthorities, authorities)
                .claim(claimName, name)
                .claim(claimEmail, email)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(expiration)
                .compact();
    }

    private boolean validate(String token) {
        System.out.println("******************************************");
        System.out.println(token);
        try {
            var jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
            jwtParser.parse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}