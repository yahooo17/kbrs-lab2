package by.bsu.kbrs.shared.rsa;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RSAPrivateKey extends RSAKey
{
    /** The private exponent. */
    private BigInteger d;

    /** Default constructor. */
    public RSAPrivateKey() {
        super();
        setPriExp(null);
        return;
    }

    /** Main constructor. */
    public RSAPrivateKey(BigInteger modulus, BigInteger priExp) {
        super(modulus);
        setPriExp(priExp);
        return;
    }

    /** Performs the classical RSA computation. */
    protected BigInteger decrypt(BigInteger c) {
        return c.modPow(getPriExp(), getModulus());
    }

    /** Extracts the data portion of the byte array. */
    protected byte[] extractData(byte[] EB) {
        if (EB.length < 12 ) {
            return new byte[0];
        }
        int index = 2;
        do {} while (EB[index++] != 0x00 && index < EB.length);

        return getSubArray(EB, index, EB.length);
    }

    /** Returns the private exponent. */
    public BigInteger getPriExp() {
        return d;
    }

    /** Sets the private exponent. */
    public void setPriExp(BigInteger priExp)
    {
        d = weedOut(priExp);
        return;
    }

    /** Uses key and returns true if decryption was successful. */
    public List<Byte> use(String source, String destination) {
        List<Byte> res = new ArrayList<>();
        byte[] sourceBytes = source.getBytes();
//        byte[] sourceBytes = getBytes(source);
//        if (isNull(sourceBytes)) {
//            return Collections.EMPTY_LIST;
//        }

        int k = getModulusByteSize();
        BigInteger c, m;
        byte[] EB, M;
        byte[][] C = reshape(sourceBytes, k);
        BufferedOutputStream out = null;

        try {
            out = new BufferedOutputStream(new FileOutputStream(destination));
            for (int i = 0; i < C.length; i++) {
//                if (C[i].length != k) return Collections.EMPTY_LIST;
                c = new BigInteger(C[i]);
                m = decrypt(c);
                EB = toByteArray(m, k);
                M = extractData(EB);
                for (byte b : M) {
                    res.add(b);
                }
                out.write(M);
            }
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
//            return Collections.EMPTY_LIST;
        } finally {
            try {
                if (isNull(out)) out.close();
            } catch (IOException e) {
                e.printStackTrace();
//                return Collections.EMPTY_LIST;
            }
        }

        return res;
    }
}
