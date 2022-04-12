/**
 * 
 */
package com.ren;

import static com.ren.Common.getSecret;
import static com.ren.Common.later;
import static com.ren.Common.now;
import static com.ren.Common.strPayload;
import static com.ren.Common.timedRunE;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEHeader.Builder;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * 
 * 
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 */
public class TestNimbusJose {

    private static final AtomicInteger counter = new AtomicInteger(123);

    public static void main(String[] args) throws Exception {
        testJWSSymmetric(32, JWSAlgorithm.HS256);
        testJWSSymmetric(48, JWSAlgorithm.HS384);
        testJWSSymmetric(64, JWSAlgorithm.HS512);
        testJWSRSA(2048, JWSAlgorithm.RS256);
        testJWSRSA(4096, JWSAlgorithm.RS256);
        testJWSRSA(2048, JWSAlgorithm.RS384);
        testJWSRSA(4096, JWSAlgorithm.RS384);
        testJWSRSA(2048, JWSAlgorithm.RS512);
        testJWSRSA(4096, JWSAlgorithm.RS512);
        testJWSEC(Curve.P_256, JWSAlgorithm.ES256);
        testJWSEC(Curve.P_384, JWSAlgorithm.ES384);
        testJWSEC(Curve.P_521, JWSAlgorithm.ES512);
        testJWSOctetKeyPair(Curve.Ed25519, JWSAlgorithm.EdDSA);

        testJWERSA(2048, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
        // testJWERSA(4096,JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
        // testJWERSA(4096,JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A192GCM);

        testJWEJWSAES();
    }

    public static String getKeyId() {
        return String.valueOf(counter.incrementAndGet());
    }

    public static void testJWSSymmetric(int key_len, JWSAlgorithm jwsAlgo) throws Exception {

        String print = "nimbus-jose JWS HMAC" + key_len + " with JWSAlgorithm " + jwsAlgo + " ";

        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[key_len];
        random.nextBytes(sharedSecret);

        // Create HMAC signer
        JWSSigner signer = new MACSigner(sharedSecret);
        JWSVerifier verifier = new MACVerifier(sharedSecret);

        String jws = timedRunE(() -> {
            JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlgo), new Payload(strPayload));// JWSAlgorithm.HS256

            // Compute the signature
            jwsObject.sign(signer);

            return jwsObject.serialize();
        }, print + "[Generate]", 100);

        String payload = timedRunE(() -> {
            JWSObject jwsObject = JWSObject.parse(jws);

            boolean valid = jwsObject.verify(verifier);
            if (!valid) {
                throw new RuntimeException("Invalid token");
            }
            return jwsObject.getPayload().toString();

        }, print + "[Validate]", 100);
        if (!strPayload.equals(payload)) {
            throw new RuntimeException("Invalid verification");
        }

    }

    public static void testJWSRSA(int key_len, JWSAlgorithm jwsAlgo) throws Exception {

        String print = "nimbus-jose JWS RSA" + key_len + " with JWSAlgorithm " + jwsAlgo + " ";

        // RSA signatures require a public and private RSA key pair,
        // the public key must be made known to the JWS recipient to
        // allow the signatures to be verified
        RSAKey rsaJWK = new RSAKeyGenerator(key_len).keyID(getKeyId()).generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);

        testJWS(print, rsaPublicJWK, jwsAlgo, signer, verifier);

    }

    public static void testJWSEC(Curve curve, JWSAlgorithm jwsAlgo) throws Exception {

        String print = "nimbus-jose JWS ECDSA Curve " + curve + " with JWSAlgorithm " + jwsAlgo + " ";

        // Generate an EC key pair
        ECKey ecJWK = new ECKeyGenerator(curve).keyID(getKeyId()).generate();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(ecJWK);

        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);

        testJWS(print, ecPublicJWK, jwsAlgo, signer, verifier);

    }

    public static void testJWSOctetKeyPair(Curve curve, JWSAlgorithm jwsAlgo) throws Exception {

        String print = "nimbus-jose JWS Octet key pair Curve " + curve + " with JWSAlgorithm " + jwsAlgo + " ";

        // Generate a key pair with Ed25519 curve
        OctetKeyPair jwk = new OctetKeyPairGenerator(curve).keyID(getKeyId()).generate();
        OctetKeyPair publicJWK = jwk.toPublicJWK();

        // Create the EdDSA signer
        JWSSigner signer = new Ed25519Signer(jwk);

        JWSVerifier verifier = new Ed25519Verifier(publicJWK);

        testJWS(print, jwk, jwsAlgo, signer, verifier);

    }

    public static void testJWS(String print, JWK jwk, JWSAlgorithm jwsAlgo, JWSSigner signer, JWSVerifier verifier)
            throws Exception {

        JWSHeader header = new JWSHeader.Builder(jwsAlgo).keyID(jwk.getKeyID()).build();
        String jws = timedRunE(() -> {
            // Prepare JWS object with simple string as payload
            JWSObject jwsObject = new JWSObject(header, new Payload(strPayload));

            // Compute the signature
            jwsObject.sign(signer);

            return jwsObject.serialize();
        }, print + "[Generate]", 100);

        String payload = timedRunE(() -> {
            JWSObject jwsObject = JWSObject.parse(jws);

            boolean valid = jwsObject.verify(verifier);
            if (!valid) {
                throw new RuntimeException("Invalid token");
            }
            return jwsObject.getPayload().toString();

        }, print + "[Validate]", 100);
        if (!strPayload.equals(payload)) {
            throw new RuntimeException("Invalid verification");
        }

        // System.out.println("Payload = " + payload);
    }

    public static void testJWERSA(int keyLen, JWEAlgorithm alg, EncryptionMethod enc) throws Exception {

        String print = "nimbus-jose JWE RSA" + keyLen + " JWEAlgorithm " + alg + " EncryptionMethod " + enc + " ";

        // Generate an RSA key pair
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(keyLen);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        // Generate the Content Encryption Key (CEK)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        testJWE(print, new RSAEncrypter(rsaPublicKey, cek), new RSADecrypter(rsaPrivateKey), cek, alg, enc);

    }

    public static void testJWE(String print, JWEEncrypter encryptor, JWEDecrypter decryptor, SecretKey cek,
            JWEAlgorithm alg, EncryptionMethod enc) throws Exception {

        String jws = timedRunE(() -> {
            JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(strPayload));
            jwe.encrypt(encryptor);
            return jwe.serialize();
        }, print + "[Generate]", 1000);

        String payload = timedRunE(() -> {
            JWEObject jwe = JWEObject.parse(jws);
            jwe.decrypt(decryptor);

            return jwe.getPayload().toString();
        }, print + "[Validate] Private key decrypt", 100);

        if (!strPayload.equals(payload)) {
            throw new RuntimeException("Invalid decryption");
        }

        payload = timedRunE(() -> {
            // Decrypt with the actual encryption key.
            JWEObject jwe = JWEObject.parse(jws);
            jwe.decrypt(new DirectDecrypter(cek, true));
            return jwe.getPayload().toString();
        }, print + "[Validate] Symmetric key decrypt", 100);

        if (!strPayload.equals(payload)) {
            throw new RuntimeException("Invalid decryption");
        }

    }

    /**
     * Signed encrypted token with 32 bit key used for both signing and encrypting
     * the encryption token.
     * 
     * @throws Exception
     */
    public static void testJWEJWSAES() throws Exception {
        String print = "nimbus-jose JWS&JWE RAS256 JWSAlgorithm HS256 JWEAlgorithm DIR EncryptionMethod A128CBC_HS256 ";
        byte[] decoded = getSecret(false);
        String tok = timedRunE(() -> {
            JWSSigner signer = new MACSigner(decoded);

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), buildJWTClaimsSet(strPayload));
            signedJWT.sign(signer);
            Builder jweHeader = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
            Payload payload = new Payload(signedJWT);

            JWEObject jweObject = new JWEObject(jweHeader.contentType("JWT").build(), payload);
            jweObject.encrypt(new DirectEncrypter(decoded));
            return jweObject.serialize();

        }, print + "[Generate] ");

        String payload = timedRunE(() -> {
            JWEObject jweObject = JWEObject.parse(tok);
            jweObject.decrypt(new DirectDecrypter(decoded));
            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
            signedJWT.verify(new MACVerifier(decoded));
            return signedJWT.getJWTClaimsSet().getSubject();
        }, print + "[Validate]");

        if (!strPayload.equals(payload)) {
            throw new RuntimeException("Invalid decryption/signing");
        }

    }

    private static JWTClaimsSet buildJWTClaimsSet(String sub) {
        String tokenJSON = sub;
        Date currentTime = now();
        Date expiryTime = later();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(tokenJSON).issuer("somecompany.com")
                .issueTime(currentTime).jwtID("1b0e1c9797ad4d1bcc97c98a90b7b060952fa81a").expirationTime(expiryTime)
                .build();
        return claimsSet;
    }

}
