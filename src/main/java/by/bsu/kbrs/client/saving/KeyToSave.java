package by.bsu.kbrs.client.saving;


import by.bsu.kbrs.shared.newrsa.RSA;
import lombok.Data;

import java.io.Serializable;

@Data
public class KeyToSave implements Serializable{
    private RSA rsa;
    private String username;
}
