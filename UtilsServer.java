//Grupo 15: Tiago Almeida (58161), Manuel Campos (58166), Tiago Rocha (58242)

// Classe para colocar funções úteis que podem ser usadas em várias partes do código

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

public class UtilsServer {

    //Inicializa o server
    public static SSLServerSocket initializeServer(String keyStorePath, String keyStorePassword, int port){
        SSLServerSocket socket = null;
        try {
            // TLS/SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // Inicializa o contexto com a chave do servidor
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance("JCEKS");

            keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
    
            socket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(port);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

    //Gera code C2FA
    public static String generateC2FA() {
        Random random = new Random();
        int randomNumber = random.nextInt(100000);
        String fiveDigits = String.format("%05d", randomNumber);

        return fiveDigits;
    }

    public static byte[] encryptUsersFile(String filePath, String pass_cypher, byte[] salt) {
        try {
            //Ler o content do arquivo de users
            byte[] fileContent = Files.readAllBytes(Paths.get(filePath));
    
            //Gerar a chave de encrypt
            PBEKeySpec keySpec = new PBEKeySpec(pass_cypher.toCharArray(), salt, 1000, 128);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
    
            //Iniciar cipher
            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    
            //Cifrar o content
            byte[] encryptedContent = cipher.doFinal(fileContent);
    
            //Substituir o conteudo do file pelo cifrado
            try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                outputStream.write(encryptedContent);
            }

            //Parametros para decrypt
            byte[] params = cipher.getParameters().getEncoded();

            //Guardar os parametros para persistencia
            try (FileOutputStream fos = new FileOutputStream("txtFiles/lastParams.txt")) {
                fos.write(params);
            } catch (Exception e2) {
                e2.printStackTrace();
            }

            return params;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void decryptUsersFile(String filePath, String pass_cypher, byte[] salt, byte[] params) {
        try {
            byte[] fileContent = null;

            //Ler o conteudo do users file
            try (FileInputStream fis = new FileInputStream("txtFiles/users.txt")) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;

                while ((length = fis.read(buffer)) != -1) {
                    bos.write(buffer, 0, length);
                }

                fileContent = bos.toByteArray();
            } catch (Exception e) {
                e.printStackTrace();
            }
    
            //Gerar a chave de encrypt
            PBEKeySpec keySpec = new PBEKeySpec(pass_cypher.toCharArray(), salt, 1000, 128);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
    
            //Iniciar parametros para decrypt
            AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
            p.init(params);

            //Iniciar cipher com os params
            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, p);
    
            //Decrypt do content
            byte[] decryptedContent = cipher.doFinal(fileContent);
    
            //Substituir o conteudo cifrado pelo em claro (apenas para o usar, depois vai ser logo cifrado outra vez)
            try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                outputStream.write(decryptedContent);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] calculateHMAC(String filePath, String pass_cypher, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException {
        //Ler conteudo do ficheiro
        FileInputStream fis = new FileInputStream(filePath);
        byte[] fileContent = fis.readAllBytes();
        fis.close();

        //Gerar a chave secreta para a classe Mac
        PBEKeySpec keySpec = new PBEKeySpec(pass_cypher.toCharArray(), salt, 1000, 128);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        //Gerar o HMAC e retornar
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        mac.update(fileContent);

        return mac.doFinal();
    }
}
