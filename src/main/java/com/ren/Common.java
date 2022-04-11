package com.ren;


import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

/**
 * 
 * 
 * 
 * 
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 */
public class Common {
    
    static String issuer = "issuer.company.com";
    static String name = "renjithalexander";
    static String[] roles = { "Software Developer", "Lead" };

    static void p(String str) {
        System.out.println(str);
    }

    static Date now() {
        return new Date();
    }

    static Date later() {
        return new Date(System.currentTimeMillis() + 8 * 60 * 60 * 1000);
    }

    
    public static String secret = "abcdefghijklmnopqrstuvwxyz123456";
    
    public static String strPayload = "{\n" + "   \"scope\":\n" + "   [\n" + "      \"all_applications\",\n"
            + "      \"any_application\"\n" + "   ],\n" + "   \"realm\":\"renjith.com\",\n"
            + "   \"role\":[\"software developer\", \"Lead\"],\n" + "   \"user_id\":\"renjith\",\n"
            + "   \"auth-type\":\"Bearer\",\n" + "   \"iss\": \"someissuer.company.com\",\n" + "   \"exp\": 1649317309,\n"
            + "   \"iat\": 1649310109,\n" + "   \"user_id\":\"renjithalexander@gmail.com\",\n" + "}";
    
    public static Algorithm jwtAlgorithm;
    public static JWTVerifier jwtVerifier;

    

    static {
        jwtAlgorithm = Algorithm.HMAC256(secret);
        jwtVerifier = JWT.require(jwtAlgorithm).withIssuer("issuer.company.com").build();
    }

    
    public static String getSecret(boolean fiveTwelve) {
        if (fiveTwelve) {
            return secret + secret;
        }
        return secret;
    }
    
    
    public static <T> T timedRun(TimedRunnable<T> r, String text) {
        try {
            return timedRunE(r::run, text);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static <T> T timedRunE(RunnableWithException<T> r, String text, int count) throws Exception {
        r.run();// warm up
        T result = null;
        long t = System.nanoTime();
        for (int i = 0; i < count; ++i)
            result = r.run();
        t = (System.nanoTime() - t) / count;
        System.out.println(text + " - " + (t / 1000) + " micros");
        return result;
    }

    public static <T> T timedRunE(RunnableWithException<T> r, String text) throws Exception {
        r.run();// warm up
        T result = null;
        long t = System.nanoTime();
        result = r.run();
        t = System.nanoTime() - t;
        System.out.println(text + " - " + (t / 1000) + " micros");
        return result;
    }
    
    
    public static Builder getPayload(int userId) {
        return JWT.create().withIssuer(issuer).withClaim("name", String.valueOf(userId)).withIssuedAt(now())
                .withExpiresAt(later()).withArrayClaim("roles", roles);
    }

    static class Encoder implements Runnable {
        int userId;
        String token;

        Encoder(int userId) {
            this.userId = userId;
        }

        @Override
        public void run() {
            token = timedRun(() -> getPayload(userId).sign(jwtAlgorithm), "jwt TE");
        }

    };

    static class Decoder implements Runnable {
        private String token;
        private int id;
        private int iddecoded;

        Decoder(int id, String token) {
            this.token = token;
            this.id = id;
        }

        @Override
        public void run() {
            try {
                jwtVerifier.verify(token);
                iddecoded = timedRunE(() -> {
                    DecodedJWT jwt = jwtVerifier.verify(token);
                    return Integer.parseInt(jwt.getClaim("name").asString());

                }, "jwt TD");
                validate();

            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }

        public void validate() {
            if (this.id != iddecoded) {
                throw new RuntimeException(id + " not equal to " + iddecoded);
            }
        }

    };

}
