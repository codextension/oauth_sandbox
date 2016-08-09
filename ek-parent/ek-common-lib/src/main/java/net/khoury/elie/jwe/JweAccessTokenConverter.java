package net.khoury.elie.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.util.Assert;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

/**
 * Created by eelkhour on 10.11.2015.
 */
public class JweAccessTokenConverter extends JwtAccessTokenConverter {

    public static final String USER_NAME = "user_name";
    private PublicKey publicKey;
    private PrivateKey privateKey;

    @Override
    public void setKeyPair(KeyPair keyPair) {
        super.setKeyPair(keyPair);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    @Override
    protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .notBeforeTime(new Date())
                .issueTime(new Date()).build();

        Map<String, Object> response = jwtClaims.toJSONObject();
        OAuth2Request clientToken = authentication.getOAuth2Request();

        if (!authentication.isClientOnly()) {
            response.put(USER_NAME, authentication.getName());
            if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
                response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
            }
        } else {
            if (clientToken.getAuthorities() != null && !clientToken.getAuthorities().isEmpty()) {
                response.put(UserAuthenticationConverter.AUTHORITIES,
                        AuthorityUtils.authorityListToSet(clientToken.getAuthorities()));
            }
        }

        if (accessToken.getScope() != null) {
            response.put(SCOPE, accessToken.getScope());
        }
        if (accessToken.getAdditionalInformation().containsKey(JTI)) {
            response.put(JTI, accessToken.getAdditionalInformation().get(JTI));
        }

        if (accessToken.getExpiration() != null) {
            response.put(EXP, accessToken.getExpiration().getTime() / 1000);
        }

        if (authentication.getOAuth2Request().getGrantType() != null) {
            response.put(GRANT_TYPE, authentication.getOAuth2Request().getGrantType());
        }

        response.putAll(accessToken.getAdditionalInformation());

        response.put(CLIENT_ID, clientToken.getClientId());

        if (clientToken.getResourceIds() != null && !clientToken.getResourceIds().isEmpty()) {
            response.put(AUD, clientToken.getResourceIds());
        }

        try {
            jwtClaims = JWTClaimsSet.parse(new JSONObject(response));
        } catch (ParseException e) {
            throw new IllegalStateException("Cannot parse the claim.", e);
        }

        JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                jwtClaims);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign the JWT.", e);
        }

        JWEObject jwt = new JWEObject(header, new Payload(signedJWT));

        RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
        try {
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot encrypt the JWT.", e);
        }
        return jwt.serialize();
    }

    @Override
    protected Map<String, Object> decode(String token) {
        try {
            EncryptedJWT jwt = EncryptedJWT.parse(token);
            RSADecrypter decrypter = new RSADecrypter((RSAPrivateKey) privateKey);
            jwt.decrypt(decrypter);

            SignedJWT signedJWT = jwt.getPayload().toSignedJWT();
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

            Assert.notNull(signedJWT);

            Assert.isTrue(signedJWT.verify(verifier));

            Map<String, Object> map = signedJWT.getJWTClaimsSet().toJSONObject();
            if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
                Integer intValue = (Integer) map.get(EXP);
                map.put(EXP, new Long(intValue));
            }
            return map;
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Cannot convert access token to JSON", e);
        }
    }
}
