## WebFlux Security

Spring Security의 WebFlux 지원은 `WebFilter`에 의존합니다.  
해당 지원은 Spring WebFlux 및 Spring WebFlux.Fn에서도 동일하게 작동합니다.

### WebFlux Security 최소 구성
다음은 WebFlux Security에 대한 최소 구성(Configuration)입니다.
```java
@EnableWebFluxSecurity
public class HelloWebfluxSecurityConfig {

	@Bean
	public MapReactiveUserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
			.username("user")
			.password("user")
			.roles("USER")
			.build();
		return new MapReactiveUserDetailsService(user);
	}
}
```

이 구성은 다음과 같은 사항을 제공합니다.
- `form`과 `http` 기본 인증을 제공합니다.
- 인증된 사용자가 페이지에 접근할 수 있도록 권한 부여를 설정합니다.
- 기본 로그인 페이지 및 기본 로그아웃 페이지를 설정합니다.
- 보안 관련 `HTTP 헤더`, `CSRF 보호` 등을 설정합니다.

### 명시적 WebFlux Security 구성
다음은 명시적 WebFlux Security 구성의 최소 사항입니다.
```java
@Configuration
@EnableWebFluxSecurity
public class HelloWebfluxSecurityConfig {

	@Bean
	public MapReactiveUserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
			.username("user")
			.password("user")
			.roles("USER")
			.build();
		return new MapReactiveUserDetailsService(user);
	}

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		http
			.authorizeExchange(exchanges -> exchanges
			    .anyExchange().authenticated()
			)
			.httpBasic(withDefaults())
			.formLogin(withDefaults());
		return http.build();
	}
}
```
이 구성은 최소 구성과 동일한 모든 항목을 명시적으로 설정합니다.   
여기서 기본값을 쉽게 변경할 수 있습니다.  

다음 링크에서 명시적 구성에 대한 단위 테스트 예시를 확인할 수 있습니다.
- [EnableWebFluxSecurity in the config/src/test/](https://github.com/spring-projects/spring-security/search?q=path%3Aconfig%2Fsrc%2Ftest%2F+EnableWebFluxSecurity)

### 다중 SecurityWebFilterChain 지원
`RequestMatchers` 별로 여러 `SecurityWebFilterChain` 인스턴스를 구성할 수 있습니다.

```java
@Configuration
@EnableWebFluxSecurity
static class MultiSecurityHttpConfig {

    @Order(Ordered.HIGHEST_PRECEDENCE)  // 1.                                               
    @Bean
    SecurityWebFilterChain apiHttpSecurity(ServerHttpSecurity http) {
        http.securityMatcher(
                new PathPatternParserServerWebExchangeMatcher("/api/**") // 2.
            )
            .authorizeExchange(
                (exchanges) -> exchanges.anyExchange().authenticated()
            )
            .oauth2ResourceServer(OAuth2ResourceServerSpec::jwt); // 3.

        return http.build();
    }

    @Bean
    SecurityWebFilterChain webHttpSecurity(ServerHttpSecurity http) {  // 4.                      
        http.authorizeExchange(
                (exchanges) -> exchanges.anyExchange().authenticated()
            )
            .httpBasic(withDefaults()); // 5.

        return http.build();
    }

    @Bean
    ReactiveUserDetailsService userDetailsService() {
        return new MapReactiveUserDetailsService(
            PasswordEncodedUser.user(), 
            PasswordEncodedUser.admin());
    }
}
```
1. `@Order`로 `SecurityWebFilterChain`을 구성합니다.  
`@Order`는 Spring Security가 우선할 `SecurityWebFilterChain`를 설정합니다.

2. `PathPatternParserServerWebExchangeMatcher`를 사용합니다.  
이 `SecurityWebFilterChain`이 `/api/`로 시작하는 URL 경로에만 적용됨을 나타냅니다.

3. `/api/**` 엔드포인트에 사용할 인증 메커니즘을 지정합니다.

4. 낮은 우선 순위를 가진 `SecurityWebFilterChain`의 다른 인스턴스를 만듭니다.  
이 `SecurityWebFilterChain`은 다른 모든 URL과 일치하도록 합니다.

5. 애플리케이션의 나머지 부분에 사용할 인증 메커니즘을 지정합니다.


Spring Security는 각 요청에 대해 하나의 `SecurityWebFilterChain` `@Bean`을 선택합니다.  
이 선택은 `securityMatcher` 정의에 따라 요청을 순서대로 일치시킵니다.

위의 경우 URL 경로가 `/api`로 시작하면 Spring Security에서 `apiHttpSecurity`를 사용합니다.   
URL이 `/api`로 시작하지 않으면 Spring Security는 기본적으로 `webHttpSecurity`로 설정됩니다.  
여기에는 모든 요청과 일치하는 암시적인 `securityMatcher`가 있습니다.

### 참고
[WebFlux Security 5.6](https://docs.spring.io/spring-security/reference/5.6/reactive/configuration/webflux.html#_explicit_webflux_security_configuration)