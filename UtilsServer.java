// Classe para colocar funções úteis que podem ser usadas em várias partes do código


import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

public class UtilsServer {
    
    // // Função para inicializar a conexão com o servidor
    // public static SSLServerSocket initializeServer(String keyStorePath, String keyStorePassword, int port) {
    //     SSLServerSocket socket = null;

    //     System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
    //     System.setProperty("javax.net.ssl.keyStore", keyStorePath);
    //     System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

    //     SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
    //     try {
    //         socket = (SSLServerSocket) factory.createServerSocket(port);
    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }

    //     return socket;
    // }
    public static SSLServerSocket initializeServer(String keyStorePath, String keyStorePassword, int port){
        SSLServerSocket socket = null;
        try {
            // TLS/SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            // Inicializa o contexto com a chave do servidor
            // Substitua "server_keystore.jks" e "password" pelos seus valores
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

    public static String generateC2FA() {
        Random random = new Random();
        int randomNumber = random.nextInt(100000);
        String fiveDigits = String.format("%05d", randomNumber);

        return fiveDigits;
    }

    public static byte[] encryptUsersFile(String filePath, String pass_cypher, byte[] salt) {
        try {
            // Ler o conteúdo do arquivo de usuários
            byte[] fileContent = Files.readAllBytes(Paths.get(filePath));
    
            // Derivar a chave de cifração a partir da senha usando PBE
            PBEKeySpec keySpec = new PBEKeySpec(pass_cypher.toCharArray(), salt, 1000, 128);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
    
            // Inicializar cifra
            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    
            // Cifrar o conteúdo do arquivo
            byte[] encryptedContent = cipher.doFinal(fileContent);
    
            // Escrever o conteúdo cifrado para um novo arquivo
            try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                outputStream.write(encryptedContent);
            }

            byte[] params = cipher.getParameters().getEncoded();

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
    
            // Derivar a chave de cifração a partir da senha usando PBE
            PBEKeySpec keySpec = new PBEKeySpec(pass_cypher.toCharArray(), salt, 1000, 128);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
    
            // Inicializar cifra
            AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
            p.init(params);

            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, p);
    
            // Decifrar o conteúdo do arquivo
            byte[] decryptedContent = cipher.doFinal(fileContent);
    
            // Escrever o conteúdo cifrado para um novo arquivo
            try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
                outputStream.write(decryptedContent);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] calculateHMAC(String filePath, String pass_cypher, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException {
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));

        // Derivar a chave de cifração a partir da senha usando PBE
        PBEKeySpec keySpec = new PBEKeySpec(pass_cypher.toCharArray(), salt, 1000, 128);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);
        mac.update(fileBytes);

        byte[] ret = mac.doFinal();

        if (filePath.equals("txtFiles/clientProgram.txt")) {
            // Escrever o conteúdo cifrado para um novo arquivo
            try (FileOutputStream outputStream = new FileOutputStream("txtFiles/progDataHMAC.txt")) {
                outputStream.write(ret);
            }
        }
        else
        {
            // Escrever o conteúdo cifrado para um novo arquivo
            try (FileOutputStream outputStream = new FileOutputStream("txtFiles/domainsInfoHMAC.txt")) {
                outputStream.write(ret);
            }
        }

        return ret;
    }
}
