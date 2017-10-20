package by.bsu.kbrs.shared;


import by.bsu.kbrs.shared.newrsa.RSA;
import by.bsu.kbrs.shared.rsa.RSAPublicKey;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;
import java.security.PublicKey;

@Data
@AllArgsConstructor
public class RequestObject implements Serializable {
    private RSA rsaKey;
    private String filename;
}
