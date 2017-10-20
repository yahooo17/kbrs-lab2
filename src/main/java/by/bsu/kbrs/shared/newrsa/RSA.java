package by.bsu.kbrs.shared.newrsa;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

@Getter
@Setter
public class RSA implements Serializable
{
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger publicKey;
    private BigInteger privateKey;
    private int        bitlength = 1024;

    private static Random     r;

    public RSA()
    {
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        publicKey = BigInteger.probablePrime(bitlength / 2, r);
        while (phi.gcd(publicKey).compareTo(BigInteger.ONE) > 0 && publicKey.compareTo(phi) < 0)
        {
            publicKey.add(BigInteger.ONE);
        }
        privateKey = publicKey.modInverse(phi);
    }

    public RSA(BigInteger publicKey, BigInteger privateKey, BigInteger N)
    {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.N = N;
    }

    private static String bytesToString(byte[] encrypted)
    {
        String test = "";
        for (byte b : encrypted)
        {
            test += Byte.toString(b);
        }
        return test;
    }

    // Encrypt message
    public byte[] encrypt(byte[] message)
    {
        return (new BigInteger(message)).modPow(publicKey, N).toByteArray();
    }

    // Decrypt message
    public byte[] decrypt(byte[] message)
    {
        return (new BigInteger(message)).modPow(privateKey, N).toByteArray();
    }

//    @SuppressWarnings("deprecation")
//    public static void main(String[] args)
//    {
//        String teststring = "ALOHA still stop not go -----,,, */*/* 46572134";
//        RSA rsa = new RSA();
//        System.out.println("Encrypting String: " + teststring);
//        System.out.println("String in Bytes: "
//                + bytesToString(teststring.getBytes()));
//        // encrypt
//        byte[] encrypted = rsa.encrypt(teststring.getBytes());
//        // decrypt
//        byte[] decrypted = rsa.decrypt(encrypted);
//        System.out.println("Decrypting Bytes: " + bytesToString(decrypted));
//        System.out.println("Decrypted String: " + new String(decrypted));
//    }
}
