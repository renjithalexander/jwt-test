/**
 * 
 */
package com.ren;

/**
 * 
 * 
 * 
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 */
public class Main {
    
    public static void main(String[] args) throws Exception{
        String execute = "nimbusjose";
        
        if (args.length != 0) {
            execute = args[0].toLowerCase(); 
        }
        
        switch(execute) {
        case "nimbusjose":
            TestNimbusJose.main(args);
            break;
        case "jwe":
            JWETest.main(args);
            break;
        case "jweasync":
            JWEAsyncKeyTest.main(args);
            break;
        case "jws":
            JWSTest.main(args);
        case "jwsasync":
            JWSAsyncKeyTest.main(args);
            break;
        default: System.out.println("Invalid argument: " + execute);
        }
        
    }

}
