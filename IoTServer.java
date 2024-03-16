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
    private static LinkedList<Domain> domains = new LinkedList<Domain>();

    //Dev-id connected
    private static Map<String, LinkedList<String>> connected = new HashMap<String, LinkedList<String>>();

    //Last device temp
    private static Map<String, Float> temps = new HashMap<String, Float>();

    //Last device img
    private static Map<String, String> imgs = new HashMap<String, String>();

    //Usernames e passwords
    private static File userFile;

    //App name e size
    private static File clientProgramData;

    //Domain file
    private static File domainsInfo;

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

        //Criar file com info dos domains (vazio por agora)
        domainsInfo = new File("domainsInfo.txt");
        try {
            if (domainsInfo.createNewFile()) {
                System.out.println("Domains file created");
            } else 
            {
                System.out.println("Domains file already exists.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (ServerSocket srvSocket = new ServerSocket(port)) {
            System.out.println("Server initialized on port: " + port);

            userFile = new File("userCredentials.txt");
            if (userFile.createNewFile()) {
                System.out.println("Users file created");
            } else {
                System.out.println("Users file already exists.");
            }

            while (true){
                Socket cliSocket = srvSocket.accept();
                ClientHandler ch = new ClientHandler(cliSocket);
                new Thread(ch).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class ClientHandler implements Runnable {
        private Socket clientSocket;
        
        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
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
                String currDevId = handleDevId(in, out, temp[0], dev_id);

                //Handle file size
                String programName = (String) in.readObject();
                long programSize = (long) in.readObject();
                boolean fileCheck = handleFileSize(in, out, programName, programSize);

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
                        if (domains.isEmpty()) {
                            Domain newDomain = new Domain(reqSplit[1], temp[0]);
                            domains.add(newDomain);
                            out.writeObject("OK");
                            out.flush();
                            break;
                        }
                        
                        for (Domain dom : domains) {
                            if (dom.getName().equals(reqSplit[1])) {
                                out.writeObject("NOK");
                                out.flush();
                                break;
                            }
                        }

                        Domain newDomain = new Domain(reqSplit[1], temp[0]);
                        domains.add(newDomain);

                        //Escrever no domains file
                        BufferedWriter myWriterDomainsCR = new BufferedWriter(new FileWriter("domainsInfo.txt", true));
                        myWriterDomainsCR.write(reqSplit[1] + ":");
                        myWriterDomainsCR.close();

                        out.writeObject("OK");
                        out.flush();
                        break;
                    case "ADD":
                        if (!userCredentials.containsKey(reqSplit[1])) {
                            out.writeObject("NOUSER # o utilizador nao existe");
                            out.flush();
                            break;
                        }

                        if (domains.isEmpty()) {
                            out.writeObject("NODM # esse dominio nao existe");
                            out.flush();
                            break;
                        }
                        
                        Domain selectedDomADD = null;
                        boolean domainExists = false;

                        for (Domain dom : domains) {
                            if (dom.getName().equals(reqSplit[2])) {
                                domainExists = true;
                                selectedDomADD = dom;
                                domains.remove(dom);
                            }
                        }

                        if (!domainExists) {
                            out.writeObject("NODM # esse dominio nao existe");
                            out.flush();
                            break;
                        }

                        if (!selectedDomADD.getCreator().equals(temp[0])) {
                            out.writeObject("NOPERM # sem permissoes");
                            out.flush();
                            domains.add(selectedDomADD);
                            break;
                        }

                        deleteLineDomain(reqSplit[1] + " (Users)");

                        selectedDomADD.addUser(reqSplit[1]);
                        domains.add(selectedDomADD);

                        //Escrever no domains file a nova linha com devices updated
                        BufferedWriter myWriterDomainsADD = new BufferedWriter(new FileWriter("domainsInfo.txt", true));
                        LinkedList<String> usersDomADD = selectedDomADD.getUsers();

                        StringBuilder stringBuilderADD = new StringBuilder();

                        for (String s : usersDomADD) {
                            stringBuilderADD.append(s + " ");
                        }

                        myWriterDomainsADD.write(reqSplit[1] + " (Users):" + stringBuilderADD.toString() + System.getProperty("line.separator"));
                        myWriterDomainsADD.close();

                        out.writeObject("OK");
                        out.flush();
                        break;
                    case "RD":
                        Domain selectedDomRD = null;
                        boolean exists = false;

                        for (Domain dom : domains) {
                            if (dom.getName().equals(reqSplit[2])) {
                                exists = true;
                                selectedDomRD = dom;
                                domains.remove(dom);
                            }
                        }

                        if (!exists) {
                            out.writeObject("NODM # esse dominio nao existe");
                            out.flush();
                            break;
                        }

                        if (!selectedDomRD.getUsers().contains(temp[0])) {
                            out.writeObject("NOPERM # sem permissoes");
                            out.flush();
                            domains.add(selectedDomRD);
                            break;
                        }

                        selectedDomRD.addDevice(temp[0] + ":" + currDevId);;
                        domains.add(selectedDomRD);

                        //Dar replace a linha no domains file
                        deleteLineDomain(reqSplit[1] + " (Devices)");

                        //Escrever no domains file a nova linha com devices updated
                        BufferedWriter myWriterDomainsRD = new BufferedWriter(new FileWriter("domainsInfo.txt", true));
                        LinkedList<String> selectedDomDevicesRD = selectedDomRD.getDevices();

                        StringBuilder stringBuilderRD = new StringBuilder();

                        for (String s : selectedDomDevicesRD) {
                            stringBuilderRD.append(s + " ");
                        }

                        myWriterDomainsRD.write(reqSplit[1] + " (Devices):" + stringBuilderRD.toString() + System.getProperty("line.separator"));
                        myWriterDomainsRD.close();

                        out.writeObject("OK");
                        out.flush();
                        break;
                    case "ET":
                        try {
                            Float.parseFloat(reqSplit[1]);
                        } catch(NumberFormatException e) {
                            out.writeObject("NOK");
                            out.flush();
                            break;
                        }
                        
                        out.writeObject("OK");
                        out.flush();

                        temps.put(temp[0] + ":" + currDevId, Float.parseFloat(reqSplit[1]));
                        break;
                    case "EI":
                        boolean eiCond = reqSplit[1].endsWith(".jpg");

                        if (eiCond) {
                            out.writeObject("OK");
                            out.flush();
                            imgs.put(temp[0] + ":" + currDevId, reqSplit[1]);
                            break;
                        }

                        out.writeObject("NOK");
                        out.flush();
                        break;
                    case "RT":
                        //Primeiro criar o file para enviar
                        File rtFile = new File("tempFile.txt");
                        BufferedWriter rtFileWriter = new BufferedWriter(new FileWriter(rtFile, true));
                        Domain rtDomain = null;

                        for (Domain dom : domains) {
                            
                            if (dom.getName().equals(reqSplit[1])) {
                                //Check read perms
                                if (!dom.getUsers().contains(temp[0])) {
                                    out.writeObject("NOPERM # sem permissoes de leitura");
                                    out.flush();
                                    break;
                                }

                                rtDomain = dom;
                            }
                        }

                        if (rtDomain == null) {
                            out.writeObject("NODM # esse dominio nao existe");
                            out.flush();
                            break;
                        }

                        if (temps.isEmpty()) {
                            out.writeObject("NODATA # nao existem dados de temperatura publicados");
                            out.flush();
                            break;
                        }

                        for (String currId : rtDomain.getDevices()) {
                            if (temps.containsKey(currId)) {
                                rtFileWriter.write(currId + ":" + temps.get(currId) + " ");
                            }
                        }

                        //Enviar o filesize e o file
                        FileInputStream finRT = new FileInputStream(rtFile);
                        InputStream inputRT = new BufferedInputStream(finRT);
                        byte[] bufferRT = new byte[(int)rtFile.length()];
                        long bytesReadRT = inputRT.read(bufferRT,0,bufferRT.length);

                        out.writeObject("OK");
                        out.writeObject(bytesReadRT);
                        out.flush();
                        out.write(bufferRT);
                        out.flush();
                        break;
                    case "RI":
                        String[] userDataRI = reqSplit[1].split(":");

                        if (!connected.get(userDataRI[0]).contains(reqSplit[1])) {
                            out.writeObject("NOID # esse device id não existe");
                            out.flush();
                            break;
                        }

                        if (!imgs.containsKey(reqSplit[1])) {
                            out.writeObject("NODATA # nao existem dados de imagem publicados");
                            out.flush();
                            break;
                        }

                        for (Domain dom : domains) {
                            if (dom.getDevices().contains(reqSplit[1])) {
                                //Check read perms
                                if (!dom.getUsers().contains(temp[0])) {
                                    out.writeObject("NOPERM # sem permissoes de leitura");
                                    out.flush();
                                    break;
                                }
                            }
                        }

                        //Enviar o filesize e o file
                        File riFile = new File(imgs.get(reqSplit[1]));
                        FileInputStream finRI = new FileInputStream(riFile);
                        InputStream inputRI = new BufferedInputStream(finRI);
                        byte[] bufferRI = new byte[(int)riFile.length()];
                        long bytesReadRI = inputRI.read(bufferRI,0,bufferRI.length);

                        out.writeObject("OK");
                        out.writeObject(bytesReadRI);
                        out.flush();
                        out.write(bufferRI);
                        out.flush();
                        break;
                    default:     
                        out.writeObject("Pedido Invalido!");
                        out.flush();
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }

        private static void deleteLineDomain(String domainName) {
            try {
                File tempFile = new File("myTempFile.txt");
                BufferedReader reader = new BufferedReader(new FileReader("domainsInfo.txt"));
                BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));

                String lineToRemove = domainName;
                String currentLine;

                while((currentLine = reader.readLine()) != null) {
                    String domainNameInFile = currentLine.split(":")[0];

                    if(domainNameInFile.equals(lineToRemove)){
                        continue;
                    }

                    writer.write(currentLine + System.getProperty("line.separator"));
                }

                writer.close();
                reader.close();

                tempFile.renameTo(new File("domainsInfo.txt"));
                domainsInfo.delete();
                domainsInfo = tempFile;

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
                myWriterUsers.write(login + System.getProperty("line.separator"));
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
                String currPass = password;
                while (!userCredentials.get(user).equals(currPass)) {
                    out.writeObject("WRONG-PWD");
                    out.flush();
                    currPass = (String) in.readObject();
                }

                out.writeObject("OK-USER");
                out.flush();
            }
        }

        private static String handleDevId(ObjectInputStream in, ObjectOutputStream out, String user, String dev_id) throws IOException, ClassNotFoundException {
            while (connected.containsKey(user) && connected.get(user).contains(dev_id)) {
                out.writeObject("NOK-DEVID");
                out.flush();
                dev_id = (String) in.readObject();
            }

            if (connected.containsKey(user)) {
                LinkedList<String> appendUserDevId = connected.get(user);
                appendUserDevId.add(dev_id);
                connected.put(user, appendUserDevId);
            }
            else 
            {
                LinkedList<String> appendUserDevIdEmpty = new LinkedList<String>();
                appendUserDevIdEmpty.add(dev_id);
                connected.put(user, appendUserDevIdEmpty);
            }

            out.writeObject("OK-DEVID");
            out.flush();

            return dev_id;
        }

        private static boolean handleFileSize(ObjectInputStream in, ObjectOutputStream out, String progName, long progSize) {
            boolean retval = false;

            try {
                BufferedReader progInfoReader = new BufferedReader(new FileReader("clientProgram.txt"));
                String line = progInfoReader.readLine();
                String[] serverProgDataSplit = line.split(":");

                if ((serverProgDataSplit[0].equals(progName)) && (Long.parseLong(serverProgDataSplit[1]) == progSize)) {
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
    }

    private static class Domain {
        private String name;
        private String creator;
        private LinkedList<String> devices;
        private LinkedList<String> users;

        public Domain(String name, String creator) {
            this.name = name;
            this.creator = creator;
            this.devices = new LinkedList<String>();
            this.users = new LinkedList<String>();
        }

        public String getName() {
            return name;
        }

        public String getCreator() {
            return creator;
        }

        public LinkedList<String> getDevices() {
            return devices;
        }

        public LinkedList<String> getUsers() {
            return users;
        }

        public void addDevice(String devId) {
            devices.add(devId);
        }

        public void addUser(String user) {
            users.add(user);
        }
    }
}