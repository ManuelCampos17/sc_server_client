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
    private static Map<String, LinkedList<Integer>> connected = new HashMap<String, LinkedList<Integer>>();

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

                //Escrever nome e size
                BufferedWriter myWriterClient = new BufferedWriter(new FileWriter("clientProgram.txt", true));
                myWriterClient.write("IoTDevice.class:6390");
                myWriterClient.close();
            } else 
            {
                System.out.println("Client file data already exists.");
            }
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

            //Ir buscar as credentials que ja estao no file
            Map<String, String> users = new HashMap<String, String>();
            try {
                BufferedReader rb = new BufferedReader(new FileReader("userCredentials.txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] user = line.split(":");
                    users.put(user[0], user[1]);
                    line = rb.readLine();
                }

                rb.close();
                userCredentials = users;
            } catch (Exception e) {
                System.out.println("Error: " + e);
            }

            //Ir buscar os dominios que ja estao no file
            try {
                BufferedReader rbDevices = new BufferedReader(new FileReader("domainsInfo.txt"));
                String lineDevices = rbDevices.readLine();
                Map<String, LinkedList<String>> devicesListByDomain = new HashMap<String, LinkedList<String>>();

                while (lineDevices != null){
                    String[] dom = lineDevices.split(":");
                    String[] domType = dom[0].split(" ");

                    if (domType[1].equals("(Devices)")) {
                        LinkedList<String> devices = new LinkedList<String>();

                        for (String dev : dom[1].split(" ")) {
                            devices.add(dev);
                        }

                        devicesListByDomain.put(domType[0], devices);
                    }

                    lineDevices = rbDevices.readLine();
                }

                rbDevices.close();

                LinkedList<String> domainsList = new LinkedList<String>();

                BufferedReader rbUsers = new BufferedReader(new FileReader("domainsInfo.txt"));
                String lineUsers = rbUsers.readLine();
                Map<String, LinkedList<String>> usersListByDomain = new HashMap<String, LinkedList<String>>();

                while (lineUsers != null){
                    String[] dom = lineUsers.split(":");
                    String[] domType = dom[0].split(" ");

                    if (domType[1].equals("(Users)")) {
                        LinkedList<String> usersSplit = new LinkedList<String>();

                        for (String us : dom[1].split(" ")) {
                            usersSplit.add(us);
                        }

                        usersListByDomain.put(domType[0], usersSplit);
                        domainsList.add(domType[0]);
                    }

                    lineUsers = rbUsers.readLine();
                }

                for (String dom : domainsList) {
                    Domain currDom = new Domain(dom, usersListByDomain.get(dom).get(0), devicesListByDomain.get(dom), usersListByDomain.get(dom));
                    domains.add(currDom);
                }

                rbUsers.close();

            } catch (Exception e) {
                System.out.println("Error: " + e);
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
                System.out.println("Client connected família");
                String login = (String) in.readObject();
                String[] temp = login.split(":");

                //Handle Auth
                handleAuth(in, out, login, temp[0], temp[1]);

                //Handle Auth Dev-id
                int dev_id = (int) in.readObject();
                int currDevId = handleDevId(in, out, temp[0], dev_id);

                //Handle file size
                String programName = (String) in.readObject();
                long programSize = (long) in.readObject();
                boolean fileCheck = handleFileSize(in, out, programName, programSize);

                if (!fileCheck) {
                    out.close();
                    in.close();
                    clientSocket.close();
                    System.out.println("User " + temp[0] + ":" + currDevId + " disconnected.");
                    return;
                }
                

                // Fazer varias operacoes
                while (true){
                    // Grande switch case
                    String request = (String) in.readObject();
                    String[] reqSplit = request.split(" ");

                    switch(reqSplit[0]){    
                        case "CREATE":
                            if (domains.isEmpty()) {
                                Domain newDomain = new Domain(reqSplit[1], temp[0]);
                                newDomain.addUser(temp[0]);
                                domains.add(newDomain);

                                //Escrever no domains file
                                BufferedWriter myWriterDomainsCR = new BufferedWriter(new FileWriter("domainsInfo.txt", true));
                                myWriterDomainsCR.write(reqSplit[1] + " (Users):" + temp[0] + System.getProperty("line.separator"));
                                myWriterDomainsCR.close();

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
                            newDomain.addUser(temp[0]);
                            domains.add(newDomain);
                            

                            //Escrever no domains file
                            BufferedWriter myWriterDomainsCR = new BufferedWriter(new FileWriter("domainsInfo.txt", true));
                            //O primeiro user é o creator
                            myWriterDomainsCR.write(reqSplit[1] + " (Users):" + temp[0]);
                            myWriterDomainsCR.write(reqSplit[1] + " (Devices):");
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

                            //Escrever no domains file a nova linha com devices updated

                            LinkedList<String> keptLines = deleteLineDomain(reqSplit[2] + " (Users)");
                            domainsInfo.delete();
                            File newDomainsInfo = new File("domainsInfo.txt");

                            domains.remove(selectedDomADD);
                            selectedDomADD.addUser(reqSplit[1]);
                            domains.add(selectedDomADD);

                            BufferedWriter myWriterDomainsADD = new BufferedWriter(new FileWriter(newDomainsInfo, true));

                            for (Domain d : domains) {
                                LinkedList<String> usersDomADD = d.getUsers();
                                LinkedList<String> devicesDomADD = d.getDevices();
                                StringBuilder stringBuilderADDUsers = new StringBuilder();
                                StringBuilder stringBuilderADDDevices = new StringBuilder();

                                for (String s : usersDomADD) {
                                    stringBuilderADDUsers.append(s + " ");
                                }

                                for (String s : devicesDomADD) {
                                    stringBuilderADDDevices.append(s + " ");
                                }

                                myWriterDomainsADD.write(d.getName() + " (Users):" + stringBuilderADDUsers.toString() + System.getProperty("line.separator"));
                                myWriterDomainsADD.write(d.getName() + " (Devices):" + stringBuilderADDDevices.toString() + System.getProperty("line.separator"));
                            }

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
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }

        private static LinkedList<String> deleteLineDomain(String domainName) {
            LinkedList<String> ret = new LinkedList<String>();
            try {
                BufferedReader reader = new BufferedReader(new FileReader("domainsInfo.txt"));

                String lineToRemove = domainName;
                String currentLine;

                while((currentLine = reader.readLine()) != null) {
                    String domainNameInFile = currentLine.split(":")[0];

                    if(domainNameInFile.equals(lineToRemove)){
                        continue;
                    }

                    ret.add(currentLine);
                }

                reader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            return ret;
        }

        private static void handleAuth(ObjectInputStream in, ObjectOutputStream out, String login, String user, String password) throws IOException, ClassNotFoundException {
            if (!userCredentials.containsKey(user)) {
                //Novo user

                LinkedList<Integer> newUserDevIds = new LinkedList<>();

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

        private static int handleDevId(ObjectInputStream in, ObjectOutputStream out, String user, int dev_id) throws IOException, ClassNotFoundException {
            while (connected.containsKey(user) && connected.get(user).contains(dev_id)) {
                out.writeObject("NOK-DEVID");
                out.flush();
                dev_id = (int) in.readObject();
            }

            if (connected.containsKey(user)) {
                LinkedList<Integer> appendUserDevId = connected.get(user);
                appendUserDevId.add(dev_id);
                connected.put(user, appendUserDevId);
            }
            else 
            {
                LinkedList<Integer> appendUserDevIdEmpty = new LinkedList<Integer>();
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

        public Domain(String name, String creator, LinkedList<String> devs, LinkedList<String> users) {
            this.name = name;
            this.creator = creator;
            this.devices = devs;
            this.users = users;
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