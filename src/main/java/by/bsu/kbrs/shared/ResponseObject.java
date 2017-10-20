package by.bsu.kbrs.shared;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class ResponseObject implements Serializable{
    private byte[] sessionKey;
    private byte[] text;
}
