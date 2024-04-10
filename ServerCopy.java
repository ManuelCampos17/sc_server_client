import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class ServerCopy {
    
    private static final String[] protocols = new String[] {"TLSv1.3"};
    private static final String[] cipher_suites = new String[] {"TLS_AES_128_GCM_SHA256"};

    public static void main(String[] args) throws IOException {
        System.out.println("Hello, World!");

        try {
            // TLS/SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            // Inicializa o contexto com a chave do servidor
            // Substitua "server_keystore.jks" e "password" pelos seus valores
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream("serverKeys"), "grupo15".toCharArray());
            keyManagerFactory.init(keyStore, "grupo15".toCharArray());
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            SSLServerSocket socket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(12345);
            socket.setEnabledProtocols(protocols);
            socket.setEnabledCipherSuites(cipher_suites);

            SSLSocket client = (SSLSocket) socket.accept();

            System.out.println("Connection established!");

            client.close();
            socket.close();
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }
        
    }
}
