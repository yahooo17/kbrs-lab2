package by.bsu.kbrs.shared.rsa;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RSAPublicKey extends RSAKey implements Serializable
{
    /** The public exponent. */
    private BigInteger e;

    /** Default constructor. */
    public RSAPublicKey() {
        super(null);
        setPubExp(null);
        return;
    }

    /** Main constructor. */
    public RSAPublicKey(BigInteger modulus, BigInteger pubExp)
    {
        super(modulus);
        setPubExp(pubExp);
        return;
    }

    /** Performs the classical RSA computation. */
    protected BigInteger encrypt(BigInteger m) {
        return m.modPow(getPubExp(), getModulus());
    }

    /** Returns the public exponent. */
    public BigInteger getPubExp() {
        return e;
    }

    /** Sets the public exponent. */
    public void setPubExp(BigInteger pubExp)
    {
        e = weedOut(pubExp);
        return;
    }

    /** Uses the key and returns true if encryption was successful. */
    public List<Byte> use(String source, String destination) {
        List<Byte> res = new ArrayList<>();
//        byte[] sourceBytes = getBytes(source);
//        if (isNull(sourceBytes)) {
//            System.err.println(String.format("%s contained nothing.", source));
//            return Collections.EMPTY_LIST;
//        }

        byte[] sourceBytes = source.getBytes();
        int k = getModulusByteSize();
        byte BT = 0x02;
        byte[] C, M;
        byte[][] D = reshape(sourceBytes, k - 11);
        ByteArrayOutputStream EB = new ByteArrayOutputStream(k);
        FileOutputStream out = null;
        BigInteger m, c;

        try {
            out = new FileOutputStream(destination);
            for (int i = 0; i < D.length; i++) {
                EB.reset();
                EB.write(0x00); EB.write(BT); EB.write(makePaddingString(k - D[i].length - 3));
                EB.write(0x00); EB.write(D[i]);
                M = EB.toByteArray();
                m = new BigInteger(M);
                c = encrypt(m);
                C = toByteArray(c, k);
                for (byte b : C) {
                    res.add(b);
                }
                out.write(C);
            }
            out.close();
        } catch (Exception e) {
            String errMsg = "An exception occured!%n%s%n%s%n%s";
            System.err.println(String.format(errMsg, e.getClass(), e.getMessage(), e.getStackTrace()));
            return Collections.EMPTY_LIST;
        }

        return res;
    }
}
