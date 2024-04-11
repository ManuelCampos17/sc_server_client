import java.io.IOException;
import java.io.ObjectOutputStream;

import javax.net.ssl.SSLSocket;

public class Client {
    
    public static void main(String[] args) throws IOException {
        System.out.println("Hello, World!");

        SSLSocket client = Utils.initializeClient("cliTruststore.jks", "grupoquinze", "127.0.0.1", 12345);

        System.out.println("Connection established!");

        // enviar uma string para o servidor
        ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());

        out.writeObject("Hello, Server!");
    }
}
