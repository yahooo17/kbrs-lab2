package by.bsu.kbrs.server.controller;

import by.bsu.kbrs.shared.RequestObject;
import by.bsu.kbrs.shared.ResponseObject;
import by.bsu.kbrs.shared.aes.AESEncrypt;
import by.bsu.kbrs.shared.aes.AESKeyGen;
import by.bsu.kbrs.shared.newrsa.RSA;
import by.bsu.kbrs.shared.rsa.RSAPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RestController
public class ServerController {

    @Autowired
    private ResourcePatternResolver resourcePatternResolver;

    @RequestMapping("/files")
    public List<String> getFileNames() {
        try {
            Resource[] resources = resourcePatternResolver.getResources("classpath:static/*.txt");
            List<String> list = new ArrayList<>();
            for (Resource r : resources) {
                list.add(r.getFile().getName());
            }

            return list;
        } catch (Exception e) {
            e.printStackTrace();
            return Collections.EMPTY_LIST;
        }
    }

    @RequestMapping("/encrypt")
    public ResponseObject getEncryptedFile(@RequestBody RequestObject obj) throws Exception {
        Resource resource = resourcePatternResolver.getResource("classpath:static/" + obj.getFilename());
        StringBuilder text = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(resource.getFile()));
        String tmp;
        while ((tmp = br.readLine()) != null) {
            text.append(tmp);
        }
        RSA rsa = obj.getRsaKey();
        String mode = "OFB";
        mode = mode.toUpperCase();
        AESKeyGen keyGen = new AESKeyGen();
        AESEncrypt aes = new AESEncrypt(mode);
        File keyFile = new File("AESkey.txt");
        File textFile = resource.getFile();
        File cipherFile = new File("AESciphertext.txt");
        FileReader keyFileReader = new FileReader(keyFile);
        BufferedReader bufferedReader = new BufferedReader(keyFileReader);
        FileInputStream textFileInputStream = new FileInputStream(textFile);
        FileOutputStream cipherFileOutputStream = new FileOutputStream(cipherFile);
        byte[] key = new byte[(int) keyFile.length()];
        String keyString = bufferedReader.readLine();
        key = aes.hexStringToByteArray(keyString);
        byte[] message = new byte[(int) textFile.length()];
        textFileInputStream.read(message);
        byte[] cipher = aes.encrypt(message, key);
        String s = new String(cipher);
        byte[] keyEnc = rsa.encrypt(key);
        cipherFileOutputStream.write(cipher);
        cipherFileOutputStream.flush();
        cipherFileOutputStream.close();
        bufferedReader.close();
        textFileInputStream.close();
        System.out.println("Encryption done! Please check AESciphertext.txt for output!");

        return new ResponseObject(keyEnc, cipher);
    }
}
