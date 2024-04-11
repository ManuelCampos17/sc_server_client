import java.io.IOException;
import java.io.ObjectInputStream;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class Server {
    
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        System.out.println("Hello, World!");

        SSLServerSocket socket = Utils.initializeServer("serverstore.jks", "grupoquinze", 12345);

        SSLSocket client = (SSLSocket) socket.accept();


        System.out.println("Connection established!");

        // receber uma string do cliente´
        ObjectInputStream in = new ObjectInputStream(client.getInputStream());
        String msg =  (String) in.readObject();
        System.out.println("Received: " + msg);

     
    }
}
