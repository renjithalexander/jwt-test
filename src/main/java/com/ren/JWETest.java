/**
 * 
 */
package com.ren;

import java.io.UnsupportedEncodingException;

import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

/**
 * 
 * 
 *
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 * 
 */
public class JWETest {

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


    public static void testJose4j() throws JoseException, MalformedClaimException, UnsupportedEncodingException {}

    public static void testJavaJwt() throws Exception {}

    public static void testJavaJWT(boolean hmac512) throws Exception {}

    private static void testJose4j(boolean hmac512) throws Exception {}

    private static void testJasonWebToken(boolean hmac512) throws Exception {}

    private static void testNimbusJose(boolean hmac512) throws Exception {}

    

}
