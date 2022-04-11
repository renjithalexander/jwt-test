/**
 * 
 */
package com.ren;

import static com.ren.Common.getPayload;
import static com.ren.Common.getSecret;
import static com.ren.Common.issuer;
import static com.ren.Common.later;
import static com.ren.Common.name;
import static com.ren.Common.now;
import static com.ren.Common.roles;
import static com.ren.Common.secret;
import static com.ren.Common.strPayload;
import static com.ren.Common.timedRunE;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.ren.Common.Decoder;
import com.ren.Common.Encoder;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * 
 * 
 * 
 *
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 *
 * 
 */
public class JWEAsyncKeyTest {

    

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

    public static void testJavaJwt() throws Exception {}

    public static void testJavaJWT(boolean hmac512) throws Exception {}

 

    public static void testJose4j(boolean hmac512) throws Exception {}

    public static void testJasonWebToken(boolean hmac512) throws Exception {}

    public static void testNimbusJose(boolean rsa2048) throws Exception {

        String print = "nimbus-jose " + (rsa2048 ? "RSA2048" : "RSA4096") + " ";

        // The JWE alg and enc
        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
        EncryptionMethod enc = EncryptionMethod.A128CBC_HS256;

        // Generate an RSA key pair
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(rsa2048 ? 2048 : 4096);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        // Generate the Content Encryption Key (CEK)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        String jws = timedRunE(() -> {
            // Encrypt the JWE with the RSA public key + specified AES CEK
            JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(strPayload));
            jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));
            return jwe.serialize();
        }, print + "TE", 1000);

        // String payload =
        timedRunE(() -> {
            // Decrypt the JWE with the RSA private key
            JWEObject jwe = JWEObject.parse(jws);
            jwe.decrypt(new RSADecrypter(rsaPrivateKey));

            return jwe.getPayload().toString();
        }, print + "TD Private key decrypt", 1000);
        
        // String payload =
        timedRunE(() -> {
            // Decrypt with the actual encryption key.
            JWEObject jwe = JWEObject.parse(jws);
            jwe.decrypt(new DirectDecrypter(cek, true));
            return jwe.getPayload().toString();
        }, print + "TD Symmetric key decrypt", 1000);

        // System.out.println("Payload = " + payload);

    }

    
}
