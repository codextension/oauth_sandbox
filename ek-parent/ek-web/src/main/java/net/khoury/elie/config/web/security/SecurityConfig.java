package net.khoury.elie.config.web.security;

import net.khoury.elie.jwe.JweAccessTokenConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.util.MultiValueMap;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by eelkhour on 03.11.2015.
 */
@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2ClientContextFilter oAuth2ClientContextFilter;
    @Autowired
    private LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint;
    @Autowired
    private OAuth2ClientAuthenticationProcessingFilter oAuth2ClientAuthenticationProcessingFilter;
    @Autowired
	@Qualifier("userInfoRestTemplate")
	private OAuth2RestOperations restTemplate;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication();
    }

	@Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/webjars/**", "/static/**");
    }

	@Override
	public void configure(HttpSecurity http) throws Exception {
		//@formatter:off

	 	http.sessionManagement().sessionFixation().newSession();

		http
				.logout().invalidateHttpSession(true).addLogoutHandler(logoutHandler())
				.and()
			.anonymous().disable()
			.antMatcher("/**").authorizeRequests()
				.antMatchers("/user").authenticated()
			.and()
				.httpBasic().authenticationEntryPoint(loginUrlAuthenticationEntryPoint)
			.and()
        .requiresChannel().anyRequest().requiresSecure()
                .and()
                        .addFilterAfter(oAuth2ClientContextFilter, ExceptionTranslationFilter.class)
				.addFilterBefore(oAuth2ClientAuthenticationProcessingFilter, FilterSecurityInterceptor.class)
			.csrf()
				.csrfTokenRepository(csrfTokenRepository())
				.and()
				.addFilterAfter(csrfHeaderFilter(), OAuth2ClientAuthenticationProcessingFilter.class);
		//@formatter:on
	}


    private LogoutHandler logoutHandler() {
        LogoutHandler handler = new LogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response,
                               Authentication authentication) {
                restTemplate.getOAuth2ClientContext().setAccessToken(null);
                String redirect = request.getRequestURL().toString()
                        .replace("/logout", "/");
                try {
                    response.sendRedirect("https://localhost:8443/ek-auth-server/logout?redirect=" + redirect);
                } catch (IOException e) {
                    throw new IllegalStateException("Cannot logout remote server", e);
                }
            }
        };
        return handler;
    }

    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }

	private Filter csrfHeaderFilter() {
		return new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
					FilterChain filterChain) throws ServletException, IOException {
				CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				if (csrf != null) {
					Cookie cookie = new Cookie("XSRF-TOKEN", csrf.getToken());
                    cookie.setHttpOnly(true);
                    cookie.setSecure(true);
                    response.addCookie(cookie);
				}
				filterChain.doFilter(request, response);
			}
		};
	}

    @Configuration
    @EnableOAuth2Client
    protected static class ClientSecurityConfig {

        private static final AuthorizationCodeResourceDetails DEFAULT_RESOURCE_DETAILS = new AuthorizationCodeResourceDetails();

        private String baseResUrl = "https://localhost:8443/ek-res-server/";

        private String redirectUrl = "https://localhost:8443/ek-web/";

        private String authorizeUrl = "https://localhost:8443/ek-auth-server/oauth/authorize";

        private String tokenUrl = "https://localhost:8443/ek-auth-server/oauth/token";

        @Autowired
        private OAuth2ClientContext oAuth2ClientContext;

        @Resource
        @Qualifier("accessTokenRequest")
        private AccessTokenRequest accessTokenRequest;

        @Bean
        public OAuth2ClientContextFilter oauth2ClientContextFilter() {
            EKOAuth2ClientContextFilter filter = new EKOAuth2ClientContextFilter();
            return filter;
        }


        @Autowired
        private OAuth2RestOperations userInfoRestTemplate;

        @Autowired
        private ResourceServerTokenServices resourceServerTokenServices;

        @Bean
        public LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint() {
            LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint("/login");
            return entryPoint;
        }

        @Bean
        public OAuth2ClientAuthenticationProcessingFilter oAuth2ClientAuthenticationProcessingFilter() {
            OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
                    "/login");
            filter.setRestTemplate(userInfoRestTemplate);
            filter.setTokenServices(resourceServerTokenServices);
            return filter;
        }

        @Bean
        public ResourceServerTokenServices resourceServerTokenServices() {
            DefaultTokenServices services = new DefaultTokenServices();
            services.setTokenStore(jwtTokenStore());
            return services;
        }

        @Bean
        public TokenStore jwtTokenStore() {
            JwtTokenStore jwtTokenStore = new JwtTokenStore((JwtAccessTokenConverter) accessTokenConverter());

            return jwtTokenStore;
        }

        @Bean
        public AccessTokenConverter accessTokenConverter() {
            JweAccessTokenConverter accessTokenConverter = new JweAccessTokenConverter();

            KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("khoury.jks"), "changeit".toCharArray())
                    .getKeyPair("client");
            accessTokenConverter.setKeyPair(keyPair);
            return accessTokenConverter;
        }

        @Bean(name = "userInfoRestTemplate")
        @Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
        public OAuth2RestOperations userInfoRestTemplate() {
            OAuth2RestTemplate template;
            AuthorizationCodeResourceDetails details = (AuthorizationCodeResourceDetails) resource();

            if (details == null) {
                details = DEFAULT_RESOURCE_DETAILS;
            }
            if (oAuth2ClientContext == null) {
                template = new OAuth2RestTemplate(details);
            } else {
                template = new OAuth2RestTemplate(details, new DefaultOAuth2ClientContext(accessTokenRequest));
            }
            template.setInterceptors(Arrays.<ClientHttpRequestInterceptor>asList(new ClientHttpRequestInterceptor() {
                @Override
                public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                                                    ClientHttpRequestExecution execution) throws IOException {
                    request.getHeaders().setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                    return execution.execute(request, body);
                }
            }));
            AuthorizationCodeAccessTokenProvider accessTokenProvider = new AuthorizationCodeAccessTokenProvider();
            accessTokenProvider.setTokenRequestEnhancer(new RequestEnhancer() {
                @Override
                public void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                    MultiValueMap<String, String> form, HttpHeaders headers) {
                    headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                }
            });
            template.setAccessTokenProvider(accessTokenProvider);

            return template;
        }

        @Bean
        @Scope("session")
        protected OAuth2ProtectedResourceDetails resource() {
            AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
            List<String> scopes = new ArrayList<String>(2);
            scopes.add("photos");
            scopes.add("account_info");
            resource.setId("client");
            resource.setAccessTokenUri(tokenUrl);
            resource.setClientId("client");
            resource.setClientSecret("elie");
            resource.setScope(scopes);
            resource.setUserAuthorizationUri(authorizeUrl);
            resource.setPreEstablishedRedirectUri(redirectUrl);
            resource.setUseCurrentUri(true);
            resource.setAuthenticationScheme(AuthenticationScheme.header);
            resource.setClientAuthenticationScheme(AuthenticationScheme.form);

            return resource;
        }

	}
}
