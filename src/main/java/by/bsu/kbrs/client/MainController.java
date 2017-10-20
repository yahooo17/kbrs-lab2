package by.bsu.kbrs.client;

import by.bsu.kbrs.shared.RequestObject;
import by.bsu.kbrs.shared.ResponseObject;
import by.bsu.kbrs.shared.aes.AESDecrypt;
import by.bsu.kbrs.shared.aes.AESEncrypt;
import by.bsu.kbrs.shared.newrsa.RSA;
import by.bsu.kbrs.shared.rsa.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("SpringJavaAutowiringInspection")
public class MainController {


    @FXML
    private TextField txtName;
    @FXML
    private TextField username;
    @FXML
    private TextField table;
    @FXML
    private ListView<String> listView;
    private ObservableList<String> data = FXCollections.observableArrayList();
    private RSA rsa;

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    @FXML
    public void initialize() {
        RestTemplate restTemplate = new RestTemplate();
        String fooResourceUrl
                = "http://localhost:8080/files";
        List response = restTemplate.getForObject(fooResourceUrl, ArrayList.class);
        data.addAll(response);
        listView.setItems(data);
        if (!data.isEmpty()) {
            listView.getSelectionModel().select(0);
        }
    }


    @SuppressWarnings("unchecked")
    @PostConstruct
    public void init() {

    }


    @FXML
    public void getFile() throws Exception{
        if (!checkNotEmpty()) {
            return;
        }
        RestTemplate restTemplate = new RestTemplate();
        String fooResourceUrl = "http://localhost:8080/encrypt";
        ResponseObject response = restTemplate.postForObject(fooResourceUrl, new RequestObject(rsa, listView.getSelectionModel().getSelectedItem()), ResponseObject.class);
        byte[] key = rsa.decrypt(response.getSessionKey());
        String sK = AESEncrypt.bytesToHex(key);
        String mode = "OFB";
        mode = mode.toUpperCase();
        AESDecrypt aes = new AESDecrypt(mode);
        File keyFile = new File("AESkey.txt");
        File textFile = new File("text2.txt");
        File cipherFile = new File("AESciphertext.txt");
        FileReader keyFileReader = new FileReader(keyFile);
        BufferedReader bufferedReader = new BufferedReader(keyFileReader);
        FileInputStream cipherFileInputStream = new FileInputStream(cipherFile);
        FileOutputStream textFileOutputStream = new FileOutputStream(textFile);
        byte[] key1 = new byte[(int) keyFile.length()];
        String keyString = bufferedReader.readLine();
        key1 = aes.hexStringToByteArray(keyString);
        byte[] cipher = new byte[(int) cipherFile.length()];
        cipherFileInputStream.read(cipher);
        byte[] message = aes.decrypt(cipher, key1);
        textFileOutputStream.write(message);
        textFileOutputStream.flush();
        textFileOutputStream.close();
        bufferedReader.close();
        cipherFileInputStream.close();
        table.setText(new String(message));
        System.out.println("Decryption done! Please check AESplaintext.txt for output!");

    }

    @FXML
    public void generateOpenKey() throws Exception {
        rsa = new RSA();
    }

    @FXML
    public void saveKey() {
        if (!checkNotEmpty()) {
            return;
        }

    }

    private boolean checkNotEmpty() {
        if (rsa == null || username.getText() == null || username.getText().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Information");
            alert.setHeaderText(null);
            alert.setContentText("rsa key and username must not be empty");
            alert.showAndWait();
            return false;
        }
        return true;
    }
}
