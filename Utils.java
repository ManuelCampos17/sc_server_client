// Classe para colocar funções úteis que podem ser usadas em várias partes do código

import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Utils {
    
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

    

    // public static SSLSocket initializeClient(String trusStrorePath, String trustStorePassword, String serverAddress, int port){
    //     SSLSocket s = null;

    //     System.setProperty("javax.net.ssl.trustStore", trusStrorePath);
    //     System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

    //     try{
    //         SocketFactory sf = SSLSocketFactory.getDefault();
    //         s = (SSLSocket) sf.createSocket(serverAddress, port);
    //     }catch(Exception e){
    //         e.printStackTrace();
    //     }

    //     return s;        
    // }

    public static SSLSocket initializeClient(String trustStorePath, String trustStorePassword, String serverAddress, int port) {
        SSLSocket socket = null;
        try {
            // TLS/SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            // Load the truststore
            KeyStore trustStore = KeyStore.getInstance("JCEKS");
            trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
            
            // Initialize trust manager factory with the truststore
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            
            // Initialize SSL context with the trust managers
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
    
            // Create the SSLSocket using the SSLContext
            SSLSocketFactory factory = sslContext.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(serverAddress, port);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    
        return socket;
    }
}
