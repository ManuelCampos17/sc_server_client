import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

// IoTServer [port]
// • [port] identifica o porto (TCP) para aceitar ligações de clientes. Por omissão, o servidor
// deve usar o porto 12345 e aceitar ligações em qualquer interface.


public class IoTServer {
    private static final int DEFAULT_PORT = 12345;

    //User -> Password
    private Map<String, String> userCredentials = new HashMap<>();
    
    //Domains
    private Map<String, Domain> domains = new HashMap<>();

    //Dev-id connected
    private Map<String, Domain> connected = new HashMap<>();

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server initialized on port: " + port);

            File userFile = new File("userCredentials.txt");
            if (userFile.createNewFile()) {
                System.out.println("Users file created");
            } else {
                System.out.println("Users file already exists.");
            }

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleClient(Socket clientSocket) {
        try (
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
        ) {
            String login = (String) in.readObject();
            String[] temp = login.split(":");

            if (!users.containsKey(temp[0])) {
                //Novo user

                //Escrever no credentials file
                FileWriter myWriter = new FileWriter("userCredentials.txt");
                myWriter.write(login);
                myWriter.close();
                userCredentials.put(temp[0], temp[1])

                out.writeObject("OK-NEW-USER");
                out.flush();
            }
            else
            {
                //User existe

                //Auth password
                String currPass = (String) in.readObject();
                while (!userCredentials.get(temp[0]).equals(currPass)) {
                    out.writeObject("WRONG-PWD");
                    out.flush();
                    currPass = (String) in.readObject();
                }

                out.writeObject("OK-USER");
                out.flush();
                
                //Auth dev-id (LISTA NO VALUE)
                String dev_id = (String) in.readObject();
                while (connected.get(temp[0]).equals(dev_id)) {
                    out.writeObject("NOK-DEVID");
                    out.flush();
                    dev_id = (String) in.readObject();
                }

                connected.put(temp[0], dev_id)

                out.writeObject("OK-DEVID");
                out.flush();
            }

            // Grande switch case

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class Domain {
        private String name;
        private Map<String, Boolean> readPerms = new HashMap<>();

        public Domain(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public Map<String, Boolean> getReadPermissions() {
            return readPermissions;
        }
    }
}