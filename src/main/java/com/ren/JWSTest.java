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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import com.ren.Common.Decoder;
import com.ren.Common.Encoder;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * 
 * 
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 */
public class JWSTest {

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
        Key key = new HmacKey((secret).getBytes("UTF-8"));

        long t = System.nanoTime();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("someissuer.company.com"); // who creates the token and
                                                   // signs it
        claims.setExpirationTimeMinutesInTheFuture(10); // time when the token
                                                        // will expire (10
                                                        // minutes from now)
        claims.setIssuedAtToNow(); // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(2); // time before which the token
                                                // is not yet valid (2 minutes
                                                // ago)
        claims.setSubject("subject"); // the subject/principal is whom the token
                                      // is about
        claims.setClaim("email", "mail@example.com"); // additional
                                                      // claims/attributes about
                                                      // the subject can be
                                                      // added
        List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
        claims.setStringListClaim("groups", groups); // multi-valued claims work
                                                     // too and will end up as a
                                                     // JSON array

        // A JWT is a JWS and/or a JWE with JSON claims as the payload.
        // In this example it is a JWS so we create a JsonWebSignature object.
        JsonWebSignature jws = new JsonWebSignature();

        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // The JWT is signed using the private key
        jws.setKey(key);

        // Set the Key ID (kid) header because it's just the polite thing to do.
        // We only have one key in this example but a using a Key ID helps
        // facilitate a smooth key rollover process
        // jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());

        // Set the signature algorithm on the JWT/JWS that will integrity
        // protect the claims
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);

        // Sign the JWS and produce the compact serialization or the complete
        // JWT/JWS
        // representation, which is a string consisting of three dot ('.')
        // separated
        // base64url-encoded parts in the form Header.Payload.Signature
        // If you wanted to encrypt it, you can simply set this jwt as the
        // payload
        // of a JsonWebEncryption object and set the cty (Content Type) header
        // to "jwt".
        String jwt = jws.getCompactSerialization();
        t = System.nanoTime() - t;
        System.out.println("TE " + t);

        // Now you can do something with the JWT. Like send it to some other
        // party
        // over the clouds and through the interwebs.
        System.out.println("JWT: " + jwt);

        // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which
        // will
        // be used to validate and process the JWT.
        // The specific validation requirements for a JWT are context dependent,
        // however,
        // it typically advisable to require a (reasonable) expiration time, a
        // trusted issuer, and
        // and audience that identifies your system as the intended recipient.
        // If the JWT is encrypted too, you need only provide a decryption key
        // or
        // decryption key resolver to the builder.
        t = System.nanoTime();
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime() // the
                                                                                      // JWT
                                                                                      // must
                                                                                      // have
                                                                                      // an
                                                                                      // expiration
                                                                                      // time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in
                                                  // validating time based
                                                  // claims to account for clock
                                                  // skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("someissuer.company.com") // whom the JWT
                                                            // needs to have
                                                            // been issued by
                .setExpectedAudience("everyone") // to whom the JWT is
                                                       // intended for
                .setVerificationKey(key) // verify the signature with the public
                                         // key
                .setJwsAlgorithmConstraints( // only allow the expected
                                             // signature algorithm(s) in the
                                             // given context
                        ConstraintType.PERMIT, AlgorithmIdentifiers.HMAC_SHA256) // which
                                                                                 // is
                                                                                 // only
                                                                                 // RS256
                                                                                 // here
                .build(); // create the JwtConsumer instance

        try {
            // Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            t = System.nanoTime() - t;
            System.out.println("TD " + t);
            System.out.println("JWT validation succeeded! " + jwtClaims);
        } catch (InvalidJwtException e) {
            // InvalidJwtException will be thrown, if the JWT failed processing
            // or validation in anyway.
            // Hopefully with meaningful explanations(s) about what went wrong.
            System.out.println("Invalid JWT! " + e);

            // Programmatic access to (some) specific reasons for JWT invalidity
            // is also possible
            // should you want different error handling behavior for certain
            // conditions.

            // Whether or not the JWT has expired being one common reason for
            // invalidity
            if (e.hasExpired()) {
                System.out.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
            }

            // Or maybe the audience was invalid
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
                System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
            }
        }
    }

    public static void testJavaJwt() throws Exception {
        int count = 1;

        Runnable[] runners = new Runnable[count];

        Thread[] ts = new Thread[count];

        Encoder[] encoders = new Encoder[count];

        for (int i = 0; i < count; ++i) {
            final int ii = i + 1001001;
            encoders[i] = new Encoder(ii);
            final int ij = i;
            runners[i] = () -> {
                encoders[ij].run();

            };
        }
        long t = System.currentTimeMillis();
        for (int i = 0; i < runners.length; ++i) {
            ts[i] = new Thread(runners[i]);
        }
        for (int i = 0; i < runners.length; ++i) {
            ts[i].start();
        }
        for (int i = 0; i < runners.length; ++i) {
            ts[i].join();
        }
        t = System.currentTimeMillis() - t;
        System.out.println(t);

        Decoder[] decoders = new Decoder[count];

        for (int i = 0; i < count; ++i) {
            final int ii = i + 1001001;
            decoders[i] = new Decoder(ii, encoders[i].token);
            final int ij = i;
            runners[i] = () -> {
                decoders[ij].run();

            };
        }
        t = System.currentTimeMillis();
        for (int i = 0; i < runners.length; ++i) {
            ts[i] = new Thread(runners[i]);
        }
        for (int i = 0; i < runners.length; ++i) {
            ts[i].start();
        }
        for (int i = 0; i < runners.length; ++i) {
            ts[i].join();
        }
        t = System.currentTimeMillis() - t;
        System.out.println(t);

    }

    public static void testJavaJWT(boolean hmac512) throws Exception {
        String secret = getSecret(hmac512);
        Algorithm jwtAlgorithm = hmac512 ? Algorithm.HMAC512(secret) : Algorithm.HMAC256(secret);
        String print = "java jwt " + (hmac512 ? "HS512" : "HS256") + " ";
        final String token = timedRunE(() -> getPayload(Integer.parseInt(name)).sign(jwtAlgorithm), print + "TE", 1000);

        timedRunE(() -> {
            JWTVerifier jwtVerifier = JWT.require(jwtAlgorithm).withIssuer(issuer)
                    .withClaim("name", String.valueOf(name)).withArrayClaim("roles", roles).build();
            return jwtVerifier.verify(token);
        }, print + "TD", 1000);
    }


    private static void testJose4j(boolean hmac512) throws Exception {
        String secret = getSecret(hmac512);
        Key key = new HmacKey((secret).getBytes("UTF-8"));

        RunnableWithException<String> encode = () -> {

            JwtClaims claims = new JwtClaims();
            claims.setIssuer(issuer);
            claims.setExpirationTimeMinutesInTheFuture(30);
            claims.setIssuedAtToNow();
            claims.setClaim("name", name);
            claims.setStringListClaim("roles", roles);

            JsonWebSignature jws = new JsonWebSignature();

            jws.setPayload(claims.toJson());

            jws.setKey(key);

            jws.setAlgorithmHeaderValue(hmac512 ? AlgorithmIdentifiers.HMAC_SHA512 : AlgorithmIdentifiers.HMAC_SHA256);

            return jws.getCompactSerialization();
        };

        String print = "jose " + (hmac512 ? "HS512" : "HS256") + " ";
        String token = timedRunE(encode, print + "TE", 1000);

        JwtClaims claims = timedRunE(() -> {
            JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime()
                    .setAllowedClockSkewInSeconds(30).setExpectedIssuer(issuer).setVerificationKey(key).build();
            return jwtConsumer.processToClaims(token);
        }, print + "TD", 1000);
        assert claims.getClaimValue("name").equals(name);

    }

    private static void testJasonWebToken(boolean hmac512) throws Exception {
        String secret = getSecret(hmac512);
        Key key = Keys.hmacShaKeyFor(secret.getBytes());
        String print = "jasonwebtoken " + (hmac512 ? "HS512" : "HS256") + " ";

        String jws = timedRunE(() -> {
            Map<String, Object> claims = new HashMap<>();
            claims.put("name", name);
            claims.put("roles", roles);
            return Jwts.builder().setIssuer(issuer).setExpiration(later()).setIssuedAt(now()).signWith(key)
                    .addClaims(claims).compact();
        }, print + "TE", 1000);

        Jws<Claims> claims = timedRunE(() -> Jwts.parserBuilder().require("name", name).requireIssuer(issuer)
                .setSigningKey(key).build().parseClaimsJws(jws), print + "TD", 1000);
        assert !claims.toString().isEmpty();
    }

    private static void testNimbusJose(boolean rsa512) throws Exception {

        String print = "nimbus-jose " + (rsa512 ? "RSA512" : "RSA256") + " ";

        // RSA signatures require a public and private RSA key pair,
        // the public key must be made known to the JWS recipient to
        // allow the signatures to be verified
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        JWSHeader header = new JWSHeader.Builder(rsa512 ? JWSAlgorithm.RS512 : JWSAlgorithm.RS256)
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
        //String payload = 
                timedRunE(() -> {
            JWSObject jwsObject = JWSObject.parse(jws);

            boolean valid = jwsObject.verify(verifier);
            if (!valid) {
                throw new RuntimeException("Invalid token");
            }
            return jwsObject.getPayload().toString();

        }, print + "TD", 1000);

        //System.out.println("Payload = " + payload);

    }


}
