import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.LinkedList;

// IoTServer [port]
// • [port] identifica o porto (TCP) para aceitar ligações de clientes. Por omissão, o servidor
// deve usar o porto 12345 e aceitar ligações em qualquer interface.


public class IoTServer {
    private static final int DEFAULT_PORT = 12345;

    //User -> Password
    private static Map<String, String> userCredentials = new HashMap<>();
    
    //Nome do domain -> Tipo que ainda vou definir (maybe lista de users q la tao)
    private Map<String, Domain> domains = new HashMap<>();

    //Dev-id connected
    private static Map<String, LinkedList<String>> connected = new HashMap<String, LinkedList<String>>();

    //Usernames e passwords
    private static File userFile;

    //App name e size
    private static File clientProgramData;

    //Domain names e devices associados, tambem user read perms por domain
    private static File domainsAndPermsFile;

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }

        //Criar size e nome do client executable
        clientProgramData = new File("clientProgram.txt");
        try {
            if (clientProgramData.createNewFile()) {
                System.out.println("Client file data created");
            } else 
            {
                System.out.println("Client file data already exists.");
            }

            //Escrever nome e size
            BufferedWriter myWriterClient = new BufferedWriter(new FileWriter("clientProgram.txt", true));
            myWriterClient.write("IoTDevice:13000");
            myWriterClient.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server initialized on port: " + port);

            userFile = new File("userCredentials.txt");
            if (userFile.createNewFile()) {
                System.out.println("Users file created");
            } else {
                System.out.println("Users file already exists.");
            }

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> {
                    try {
                        handleClient(clientSocket);
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket clientSocket) throws ClassNotFoundException {
        try (
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
        ) {
            String login = (String) in.readObject();
            String[] temp = login.split(":");

            //Handle Auth
            handleAuth(in, out, login, temp[0], temp[1]);

            //Handle Auth Dev-id
            String dev_id = (String) in.readObject();
            handleDevId(in, out, temp[0], dev_id);

            //Handle file size
            String programInfo = (String) in.readObject();
            boolean fileCheck = handleFileSize(in, out, programInfo);

            if (!fileCheck) {
                out.close();
                in.close();
                clientSocket.close();
            }

            // Grande switch case
            String request = (String) in.readObject();
            String[] reqSplit = request.split(" ");

            switch(reqSplit[0]){    
                case "CREATE":    
                    //Create
                case "ADD":    
                    //Add
                case "RD":
                    //Rd
                case "ET":
                    //Et
                case "EI":
                    //Ei
                case "RT":
                    //Rt
                case "RI":
                    //Ri
                default:     
                  out.writeObject("Pedido Invalido!");
                  out.flush();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleAuth(ObjectInputStream in, ObjectOutputStream out, String login, String user, String password) throws IOException, ClassNotFoundException {
        if (!userCredentials.containsKey(user)) {
            //Novo user

            LinkedList<String> newUserDevIds = new LinkedList<>();

            //Escrever no credentials file
            BufferedWriter myWriterUsers = new BufferedWriter(new FileWriter("userCredentials.txt", true));
            myWriterUsers.write(login);
            myWriterUsers.close();
            userCredentials.put(user, password);

            out.writeObject("OK-NEW-USER");
            out.flush();

            connected.put(user, newUserDevIds);
        }
        else
        {
            //User existe

            //Auth password
            String currPass = (String) in.readObject();
            while (!userCredentials.get(user).equals(currPass)) {
                out.writeObject("WRONG-PWD");
                out.flush();
                currPass = (String) in.readObject();
            }

            out.writeObject("OK-USER");
            out.flush();
        }
    }

    private static void handleDevId(ObjectInputStream in, ObjectOutputStream out, String user, String dev_id) throws IOException, ClassNotFoundException {
        while (connected.get(user).contains(dev_id)) {
            out.writeObject("NOK-DEVID");
            out.flush();
            dev_id = (String) in.readObject();
        }

        LinkedList<String> appendUserDevId = connected.get(user);
        appendUserDevId.add(dev_id);

        connected.put(user, appendUserDevId);

        out.writeObject("OK-DEVID");
        out.flush();
    }

    private static boolean handleFileSize(ObjectInputStream in, ObjectOutputStream out, String progInfo) {
        boolean retval = false;

        try {
            BufferedReader progInfoReader = new BufferedReader(new FileReader("clientProgram.txt"));
            String line = progInfoReader.readLine();
            String[] serverProgDataSplit = line.split(":");
            String[] userProgDataSplit = progInfo.split(":");

            if ((serverProgDataSplit[0].equals(userProgDataSplit[0])) && (Integer.parseInt(serverProgDataSplit[0]) == Integer.parseInt(userProgDataSplit[0]))) {
                out.writeObject("OK-TESTED");
                out.flush();
                progInfoReader.close();
                retval = true;
            }
            else 
            {
                out.writeObject("NOK-TESTED");
                out.flush();
                progInfoReader.close();
                retval = false;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return retval;
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
            return null;
            // return readPermissions;
        }
    }
}