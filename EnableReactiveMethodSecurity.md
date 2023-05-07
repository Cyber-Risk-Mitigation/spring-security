## @EnableReactiveMethodSecurity

Spring Security는 [Reactor의 Context](#reactive-sequence에-context-추가하기)를 통한 메서드 보안을 지원합니다.  
- Reactor의 Context는 `ReactiveSecurityContextHolder`를 통해 설정됩니다.
- 예를 들어, 현재 로그인한 사용자의 메시지를 검색하는 방법을 보여줍니다.
- 이 방식은 메서드 반환 타입을 `Mono`나 `Flux`와 같은 스트림으로 지정해야 합니다.
- 코틀린의 경우 `coroutine` 함수 또한 반환할 수 있습니다.

```java
Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");

Mono<String> messageByUsername = ReactiveSecurityContextHolder.getContext()
	.map(SecurityContext::getAuthentication)
	.map(Authentication::getName)
	.flatMap(this::findMessageByUsername)
	// WebFlux 앱에서 `subscriberContext`는 `ReactorContextWebFilter`를 통해 자동 설정됩니다.
	.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

StepVerifier.create(messageByUsername)
	.expectNext("Hi user")
	.verifyComplete();

```

```java
Mono<String> findMessageByUsername(String username) {
	return Mono.just("Hi " + username);
}
```

<br>

Reactive 앱에서 메서드 보안을 위한 최소 보안 구성은 다음과 같습니다.
```java
@EnableReactiveMethodSecurity
public class SecurityConfig {
	@Bean
	public MapReactiveUserDetailsService userDetailsService() {
		User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
		UserDetails rob = userBuilder.username("rob")
			.password("rob")
			.roles("USER")
			.build();
		UserDetails admin = userBuilder.username("admin")
			.password("admin")
			.roles("USER","ADMIN")
			.build();
		return new MapReactiveUserDetailsService(rob, admin);
	}
}
```

-----
다음 클래스를 살펴봅시다.

```java
@Component
public class HelloWorldMessageService {
	@PreAuthorize("hasRole('ADMIN')")
	public Mono<String> findMessage() {
		return Mono.just("Hello World!");
	}
}
```

위의 구성과 함께 확인해봅시다.
- `@PreAuthorize("hasRole('ADMIN'))`는 `findByMessage()`의 호출 권한을 `ADMIN`으로 한정합니다.
- `@EnableReactiveMethodSecurity`는 모든 표준 메서드 보안 표현식에 사용할 수 있습니다. 
- 그러나 현재는 식의 부울 또는 부울 반환 타입만 지원하며 표현식이 block되지 않아야 함을 의미합니다.

[WebFlux Security](https://docs.spring.io/spring-security/reference/5.6/reactive/configuration/webflux.html#jc-webflux)와 통합하면 인증된 사용자에 따라 Spring Security에서 Reactor Context가 자동으로 설정됩니다.


```java
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

	@Bean
	SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) throws Exception {
		return http
			// 메서드 보안 구성이 동작하는 것을 확인할 수 있습니다.
			// Best practice to use both for defense in depth
			.authorizeExchange(exchanges -> exchanges
				.anyExchange().permitAll()
			)
			.httpBasic(withDefaults())
			.build();
	}

	@Bean
	MapReactiveUserDetailsService userDetailsService() {
		User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
		UserDetails rob = userBuilder.username("rob")
			.password("rob")
			.roles("USER")
			.build();
		UserDetails admin = userBuilder.username("admin")
			.password("admin")
			.roles("USER","ADMIN")
			.build();
		return new MapReactiveUserDetailsService(rob, admin);
	}
}
```


-----
### Reactive Sequence에 Context 추가하기
명령형 프로그래밍에서 반응형(Reactive) 프로그래밍으로 관점을 전환할 때 마주치는 큰 기술적 과제 중 하나는 스레드를 처리하는 방법에 있습니다.
- 반응형 프로그래밍에서는 스레드를 사용하여 거의 동시에 실행되는 여러 비동기 시퀀스를 처리할 수 있습니다
- 논블로킹 락스텝에서 실행됩니다. 
- 시퀀스의 실행은 한 스레드에서 다른 스레드로 쉽게 이동할 수도 있습니다.

```
락스텝(Lockstep)은 동일한 작업 세트를 동시에 병렬로 실행하는 내결함성 컴퓨터 시스템입니다. 이중화는 오류 감지 및 오류 수정을 허용합니다.
```

이런 형태는 `ThreadLocal`과 같이 스레드 모델에 의존하는 기능을 안정적으로 사용하는 개발자에게 문제가 됩니다.

이에 대한 `ThreadLocal` 사용에 대한 일반적인 해결 방법 사례는 다음과 같습니다.
- Tuple2<T, C>
- 비즈니스 데이터 T
- 컨텍스트 데이터 C

```java
String key = "message";

Mono<String> r = Mono.just("Hello")
    .flatMap(s -> Mono.deferContextual(
            ctx -> Mono.just(s + " " + ctx.get(key))
        )
    ).contextWrite(ctx -> ctx.put(key, "World"));

StepVerifier.create(r)
            .expectNext("Hello World")
            .verifyComplete();
```



### 참고
[EnableReactiveMethodSecurity](https://docs.spring.io/spring-security/reference/5.6/reactive/authorization/method.html)   
[Subscription의 생명주기에 대한 이해](https://github.com/reactive-streams/reactive-streams-jvm/blob/master/README.md#3-subscription-code)
