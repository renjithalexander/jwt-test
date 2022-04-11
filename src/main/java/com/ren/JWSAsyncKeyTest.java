/**
 * 
 */
package com.ren;

import static com.ren.Common.strPayload;
import static com.ren.Common.timedRunE;

import java.io.UnsupportedEncodingException;

import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

/**
 * 
 * 
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 */
public class JWSAsyncKeyTest {

    public static void main(String[] args) throws Exception {
        testJavaJWT(false);
        testJavaJWT(true);
        testJose4j(false);
        testJose4j(true);
        testJasonWebToken(false);
        testJasonWebToken(true);
        testNimbusJose(false);
        testNimbusJose(true);

    }

    public static void testJose4j() throws JoseException, MalformedClaimException, UnsupportedEncodingException {
    }

    public static void testJavaJwt() throws Exception {
    }

    public static void testJavaJWT(boolean hmac512) throws Exception {
    }

    private static void testJose4j(boolean hmac512) throws Exception {
    }

    private static void testJasonWebToken(boolean hmac512) throws Exception {
    }

    private static void testNimbusJose(boolean rsa2048) throws Exception {

        String print = "nimbus-jose " + (rsa2048 ? "RSA2048" : "RSA4096") + " ";

        // RSA signatures require a public and private RSA key pair,
        // the public key must be made known to the JWS recipient to
        // allow the signatures to be verified
        RSAKey rsaJWK = new RSAKeyGenerator(rsa2048 ? 2048 : 4096).keyID("123").generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        JWSHeader header = new JWSHeader.Builder(rsa2048 ? JWSAlgorithm.RS512 : JWSAlgorithm.RS256)
                .keyID(rsaJWK.getKeyID()).build();
        String jws = timedRunE(() -> {
            // Prepare JWS object with simple string as payload
            JWSObject jwsObject = new JWSObject(header, new Payload(strPayload));

            // Compute the RSA signature
            jwsObject.sign(signer);

            // To serialize to compact form, produces something like
            // eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
            // mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
            // maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
            // -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
            return jwsObject.serialize();
        }, print + "TE", 1000);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
        // String payload =
        timedRunE(() -> {
            JWSObject jwsObject = JWSObject.parse(jws);

            boolean valid = jwsObject.verify(verifier);
            if (!valid) {
                throw new RuntimeException("Invalid token");
            }
            return jwsObject.getPayload().toString();

        }, print + "TD", 1000);

        // System.out.println("Payload = " + payload);

    }

}
