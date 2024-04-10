import java.io.IOException;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Server {
    
    private static final String[] protocols = new String[] {"TLSv1.3"};
    private static final String[] cipher_suites = new String[] {"TLS_AES_128_GCM_SHA256"};

    public static void main(String[] args) throws IOException {
        System.out.println("Hello, World!");

        // TLS/SSL
        System.setProperty("javax.net.ssl.keyStore", "C:/Manel/sc_server_client/serverKeys");
        System.setProperty("javax.net.ssl.keyStorePassword", "grupo15");
        SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

        SSLServerSocket socket = (SSLServerSocket) factory.createServerSocket(12345);
        socket.setEnabledProtocols(protocols);
        socket.setEnabledCipherSuites(cipher_suites);

        SSLSocket client = (SSLSocket) socket.accept();

        System.out.println("Connection established!");

        client.close();
        socket.close();
        
    }
}
