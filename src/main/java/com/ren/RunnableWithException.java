/**
 * 
 */
package com.ren;

/**
 * 
 * 
 * @author <a href="mailto:renjithalexander@gmail.com">Renjith Alexander</a>
 */
@FunctionalInterface
public interface RunnableWithException <T> {
    
    T run() throws Exception;

}
