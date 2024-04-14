// Classe para colocar funções úteis que podem ser usadas em várias partes do código


import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Random;
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

}
