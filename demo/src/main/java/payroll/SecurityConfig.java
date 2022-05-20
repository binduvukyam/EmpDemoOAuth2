package payroll;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.config.http.SessionCreationPolicy;

import payroll.auth.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private RestOAuth2AuthenticationFilter authenticationFilter;

    @Autowired
    private RestOAuth2AuthorizationFilter authorizationFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .cors().and()
            .csrf().disable()

            // Filter Gates for auth
            .addFilterBefore(authorizationFilter, BasicAuthenticationFilter.class)
            .addFilterBefore(authenticationFilter, BasicAuthenticationFilter.class)

            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            .and()
            .exceptionHandling()
            // .authenticationEntryPoint(RestOAuth2AuthenticationEntryPoint())
            // .accessDeniedHandler(RestOAuth2AccessDeniedHandler())

            .and()
            .authorizeRequests()
            .anyRequest().authenticated(); // Forces auth for all endpoints.
    }
}
