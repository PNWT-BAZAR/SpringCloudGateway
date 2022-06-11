package etf.unsa.ba.SpringCloudGateway.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private @Lazy
    JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors().and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .and()
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()

                //Identity Service
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
                .antMatchers(HttpMethod.GET, "/identity/roles").permitAll()
                .antMatchers(HttpMethod.POST, "/identity/users/signup").permitAll()
                .antMatchers(HttpMethod.POST, "/identity/users").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/identity/users").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/identity/users/**").hasRole("ADMIN")

                //Inventory Service
                .antMatchers(HttpMethod.GET, "/inventory/**").permitAll()
                .antMatchers(HttpMethod.POST, "/inventory/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/inventory/reviewProduct/**").hasRole("USER")
                .antMatchers(HttpMethod.PUT, "/inventory/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/inventory/**").hasRole("ADMIN")

                //Order Service
                .antMatchers(HttpMethod.GET, "/order/orders/**").permitAll()
                .antMatchers(HttpMethod.PUT, "/order/orders").permitAll()
                .antMatchers(HttpMethod.POST, "/order/orders").permitAll()
                .antMatchers(HttpMethod.DELETE, "/order/orders/**").permitAll()

                .antMatchers(HttpMethod.GET, "/order/orderItems/**").hasRole("ADMIN")

                .anyRequest().authenticated();
    }

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setExposedHeaders(Arrays.asList("Authorization"));
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"));
        configuration.setAllowCredentials(false);
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
