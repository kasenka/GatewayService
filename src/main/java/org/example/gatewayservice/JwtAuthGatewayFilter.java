package org.example.gatewayservice;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class JwtAuthGatewayFilter implements GlobalFilter, Ordered {

    private final WebClient webClient;

    // строим базовый WebClient, чтобы понимать куда проксировать запросы
    public JwtAuthGatewayFilter(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("http://localhost:8082").build(); // тут AuthService
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // исключаем login, register, refresh, logout
        if (path.contains("/login") ||
                path.contains("/register") ||
                path.contains("/refresh") ||
                path.contains("/logout")) {
            return chain.filter(exchange);
        }

        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (token == null || token.isEmpty()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Проверяем токен через /validate
        Mono<Void> authorization = webClient.post()
                .uri("/api/auth/validate")
                .header("Authorization", token)
                .retrieve()
                .onStatus(status -> status.isError(),
                        response ->
                        response.bodyToMono(String.class)
                                .flatMap(errorBody -> Mono.error(new RuntimeException(errorBody)))
                )
                .bodyToMono(Map.class)
                .flatMap(response -> {
                    // создаем новый запрос с добавленным заголовком
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("X-User-Username", String.valueOf(response.get("username")))
                            .build();

                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(mutatedRequest)
                            .build();

                    return chain.filter(mutatedExchange);
                })
                .onErrorResume(e -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);

                    byte[] bytes = e.getMessage().getBytes(StandardCharsets.UTF_8);
                    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

                    return exchange.getResponse().writeWith(Mono.just(buffer));
                });
        return authorization;
    }

    @Override
    public int getOrder() {
        return -1; // важен порядок фильтра, чтобы он срабатывал первым
    }
}

