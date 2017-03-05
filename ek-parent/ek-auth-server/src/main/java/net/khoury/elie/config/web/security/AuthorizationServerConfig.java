package net.khoury.elie.config.web.security;

import net.khoury.elie.jwe.JweAccessTokenConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;

/**
 * Created by Elie on 25.10.2015.
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("anotherH2DataSource")
    private DataSource datasource;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JdbcApprovalStore approvalStore;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("hasRole('ROLE_TRUSTED_CLIENT')")
                .allowFormAuthenticationForClients().passwordEncoder(passwordEncoder);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(datasource).passwordEncoder(passwordEncoder);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //@formatter:off
        endpoints
                .allowedTokenEndpointRequestMethods(HttpMethod.POST)
                .approvalStore(approvalStore)
                .accessTokenConverter(accessTokenConverter())
                .authenticationManager(authenticationManager)
                .setClientDetailsService(clientDetailsService());
        //@formatter:on

    }

    @Bean
    public AccessTokenConverter accessTokenConverter() {
        JweAccessTokenConverter accessTokenConverter = new JweAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("khoury.jks"), "changeit".toCharArray())
                .getKeyPair("client");
        accessTokenConverter.setKeyPair(keyPair);

        return accessTokenConverter;
    }

    @Bean
    public ClientDetailsService clientDetailsService() {
        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(datasource);
        return clientDetailsService;
    }

    @Bean
    public JdbcApprovalStore jdbcApprovalStore() {
        JdbcApprovalStore approvalStore = new JdbcApprovalStore(datasource);

        return approvalStore;
    }
}
