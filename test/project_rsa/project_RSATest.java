/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package project_rsa;

import java.math.BigInteger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author sylvain
 */
public class project_RSATest {
    
    public project_RSATest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of isPrime method, of class project_RSA.
     */
    @Test
    public void testIsPrime() {
        System.out.println("isPrime");
        int randNum = 239;
        Boolean expResult = true;
        Boolean result = project_RSA.isPrime(randNum);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
    }

    /**
     * Test of randomPrime method, of class project_RSA.
     */
    @Test
    public void testRandomPrime() {
        int bits = 8;
        project_RSA instance = new project_RSA();
        int range = instance.random(bits);
        boolean inRange;
        if(range >= 128 && range <= 255 && instance.isPrime(range) == true)
            inRange = true;
        else inRange = false;
        System.out.println("randomPrime " + range);
        boolean expResult = true;
        boolean result = inRange;
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
    }

    /**
     * Test of generate method, of class project_RSA.
     */
    /*@Test
    public void testGenerate() {
        System.out.println("generate");
        int bits = 8;
        project_RSA instance = new project_RSA();
        instance.generate(bits);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }*/

    /**
     * Test of cypher method, of class project_RSA.
     */
    @Test
    public void testCypher() {
        System.out.println("cypher");
        String messageIn = "524";
        BigInteger exponent = BigInteger.valueOf(239);
        BigInteger n = BigInteger.valueOf(22499);
        project_RSA instance = new project_RSA();
        BigInteger expResult = BigInteger.valueOf(960);
        BigInteger result = instance.cypher(messageIn, exponent, n);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
    }

    /**
     * Test of testKeys method, of class project_RSA.
     */
    /*@Test
    public void testTestKeys() {
        System.out.println("testKeys");
        project_RSA instance = new project_RSA();
        Boolean expResult = true;
        Boolean result = instance.testKeys();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
    }*/

    
}
