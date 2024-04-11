// Classe para colocar funções úteis que podem ser usadas em várias partes do código

import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Utils {
    
    // Função para inicializar a conexão com o servidor
    public static SSLServerSocket initializeServer(String keyStorePath, String keyStorePassword, int port) {
        SSLServerSocket socket = null;
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

        SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        try {
            socket = (SSLServerSocket) factory.createServerSocket(port);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

    public static SSLSocket initializeClient(String trusStrorePath, String trustStorePassword, String serverAddress, int port){
        SSLSocket s = null;

        System.setProperty("javax.net.ssl.trustStore", trusStrorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

        try{
            SocketFactory sf = SSLSocketFactory.getDefault();
            s = (SSLSocket) sf.createSocket(serverAddress, port);
        }catch(Exception e){
            e.printStackTrace();
        }

        return s;        
    }
}
