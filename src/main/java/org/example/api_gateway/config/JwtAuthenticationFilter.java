package org.example.api_gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Optional;

@Component
@Order(1)
public class JwtAuthenticationFilter implements GlobalFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // skip login or register
        if (request.getURI().getPath().contains("/api/auth/") || request.getURI().getPath().contains("/api/orders/stripe")) {
            return chain.filter(exchange);
        }
        System.out.println(request.getURI().getPath());
        // get JWT token from header
        String token = request.getHeaders().getFirst("Authorization");
        String urlToken = Optional.ofNullable(request.getQueryParams().getFirst("token")).orElse(null);
        if ((token == null || !token.startsWith("Bearer ")) && urlToken == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        if (token != null && token.startsWith("Bearer ")){
            token = token.substring(7); // 去掉 "Bearer " 前缀
        } else if (urlToken != null) {
            token = urlToken;
        }

        try {
            // check JWT token and claims
            Claims claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody();

            // add user information into header
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("userId", claims.getSubject())
                    .build();
            System.out.println(claims.getSubject());
            exchange = exchange.mutate().request(modifiedRequest).build();
        } catch (Exception e) {
            // if check token failed return 401 unauthenticated
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }
}
