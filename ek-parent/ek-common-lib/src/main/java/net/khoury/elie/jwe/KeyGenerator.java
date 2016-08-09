package net.khoury.elie.jwe;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by eelkhour on 11.11.2015.
 */
public class KeyGenerator {

    public static final String RSA = "RSA";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(RSA);
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

//        try {
//            Provider p[] = Security.getProviders();
//
//            for (int i = 0; i < p.length; i++) {
//                System.out.println(p[i]);
//                for (Enumeration e = p[i].keys(); e.hasMoreElements();)
//                    System.out.println("\t" + e.nextElement());
//            }
//        } catch (Exception e) {
//            System.out.println(e);
//        }
    }
}
