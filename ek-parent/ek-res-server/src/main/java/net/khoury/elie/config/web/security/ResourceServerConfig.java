package net.khoury.elie.config.web.security;

import java.io.IOException;
import java.security.KeyPair;

import net.khoury.elie.jwe.JweAccessTokenConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.FileCopyUtils;

/**
 * Created by Elie on 25.10.2015.
 */
@Configuration
@EnableWebSecurity
@PropertySource("classpath:application.properties")
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}

	@Value("${resource.id}")
	private String RESOURCE_ID;

	@Autowired
	private TokenStore tokenStore;

	@Bean
	public AccessTokenConverter accessTokenConverter() throws IOException {
		JweAccessTokenConverter accessTokenConverter = new JweAccessTokenConverter();

        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("khoury.jks"), "changeit".toCharArray())
                .getKeyPair("client");
		accessTokenConverter.setKeyPair(keyPair);
		return accessTokenConverter;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
        http.requiresChannel().antMatchers("/**").requiresSecure();
		http.authorizeRequests().anyRequest().authenticated();
	}

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.resourceId(RESOURCE_ID).tokenStore(tokenStore).tokenServices(getResourceServerTokenServices())
				.authenticationManager(getAuthenticationManager());
	}

	@Bean
	public AuthenticationManager getAuthenticationManager() {
		OAuth2AuthenticationManager auth2AuthenticationManager = new OAuth2AuthenticationManager();
		auth2AuthenticationManager.setResourceId(RESOURCE_ID);
		auth2AuthenticationManager.setTokenServices(getResourceServerTokenServices());
		return auth2AuthenticationManager;
	}

	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return new BCryptPasswordEncoder(10);
	}

	@Bean
	public ResourceServerTokenServices getResourceServerTokenServices() {
		DefaultTokenServices resourceServerTokenServices = new DefaultTokenServices();
		resourceServerTokenServices.setTokenStore(tokenStore);

		return resourceServerTokenServices;
	}

	@Bean
	public TokenStore jwtTokenStore(AccessTokenConverter accessTokenConverter) throws IOException {
		JwtTokenStore jwtTokenStore = new JwtTokenStore((JwtAccessTokenConverter) accessTokenConverter);

		return jwtTokenStore;
	}
}
