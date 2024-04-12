import java.io.*;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import java.util.LinkedList;

// IoTServer [port]
// • [port] identifica o porto (TCP) para aceitar ligações de clientes. Por omissão, o servidor
// deve usar o porto 12345 e aceitar ligações em qualquer interface.


public class IoTServer {
    private static final int DEFAULT_PORT = 12345;
    private static Lock serverLock = new ReentrantLock();

    private static int port;
    private static String pass_cypher;
    private static KeyPair sv_keys;
    private static String pass_keystore;
    private static String apiKey;

    //User -> Password
    private static volatile Map<String, String> userCredentials = new HashMap<>();
    
    //Nome do domain -> Tipo que ainda vou definir (maybe lista de users q la tao)
    private static volatile LinkedList<Domain> domains = new LinkedList<Domain>();

    //Dev-id connected
    private static volatile Map<String, LinkedList<Integer>> connected = new HashMap<String, LinkedList<Integer>>();

    //Last device temp
    private static volatile Map<String, Float> temps = new HashMap<String, Float>();

    //Usernames e passwords
    private static File userFile;

    //App name e size
    private static File clientProgramData;

    //Domain file
    private static File domainsInfo;

    //Temps
    private static File tempsFile;

    //Registered devices history
    private static File regHist;

    public static void main(String[] args) {
        port = DEFAULT_PORT;

        if (args.length != 5) {
            System.out.println("Formato: IoTServer <port> <password-cifra> <keystore> <password-keystore> <2FA-APIKey>");
            return;
        }

        // TLS/SSL
        String keyStore = args[2];

        port = Integer.parseInt(args[0]);
        pass_cypher = args[1];
        pass_keystore = args[3];

        try {
            FileInputStream kStoreFile = new FileInputStream(args[2]);
            KeyStore kstore = KeyStore.getInstance("JCEKS");
            kstore.load(kStoreFile, pass_keystore.toCharArray());           //password para aceder à keystore
        } catch (Exception e) {
            e.printStackTrace();
        }

        apiKey = args[4];



        //Criar size e nome do client executable caso nao exista
        serverLock.lock();
        clientProgramData = new File("clientProgram.txt");
        try {
            if (clientProgramData.createNewFile()) {
                System.out.println("Client file data created");

                //Escrever nome e size
                BufferedWriter myWriterClient = new BufferedWriter(new FileWriter("clientProgram.txt", true));
                myWriterClient.write("IoTDevice.class:9795");
                myWriterClient.close();
            } else 
            {
                System.out.println("Client file data already exists.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            serverLock.unlock();
        }

        serverLock.lock();
        //Criar file com info dos domains caso nao exista (vazio por agora)
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
        } finally {
            serverLock.unlock();
        }

        serverLock.lock();
        try (SSLServerSocket srvSocket = Utils.initializeServer(keyStore, pass_keystore, port)) {


            System.out.println("Server initialized on port: " + port);

            //Criar user file caso nao exista
            userFile = new File("users.txt");
            if (userFile.createNewFile()) {
                System.out.println("Users file created");
            } else {
                System.out.println("Users file already exists.");
            }
            
            //Criar temps file caso nao exista
            tempsFile = new File("tempsFile.txt");
            if (tempsFile.createNewFile()) {
                System.out.println("Temps file created");
            } else {
                System.out.println("Temps file already exists.");
            }

            //Ir buscar as credentials que ja estao no file
            try {
                BufferedReader rb = new BufferedReader(new FileReader("users.txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] user = line.split(":");
                    userCredentials.put(user[0], user[1]);
                    line = rb.readLine();
                }

                rb.close();
            } catch (Exception e) {
                System.out.println("Erro: " + e);
            }

            //Ir buscar os dominios que ja estao no file
            try {
                BufferedReader rbDevices = new BufferedReader(new FileReader("domainsInfo.txt"));
                String lineDevices = rbDevices.readLine();
                Map<String, LinkedList<String>> devicesListByDomain = new HashMap<String, LinkedList<String>>();

                while (lineDevices != null){
                    String[] dom = lineDevices.split(":");

                    if (dom.length > 1) {
                        String[] domType = dom[0].split(" ");

                        if (domType[1].equals("(Devices)")) {
                            LinkedList<String> devices = new LinkedList<String>();

                            for (String dev : dom[1].split(" ")) {
                                devices.add(dev);
                            }

                            devicesListByDomain.put(domType[0], devices);
                        }
                    }

                    lineDevices = rbDevices.readLine();
                }

                rbDevices.close();
                devicesListByDomain.remove(" ");

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

                usersListByDomain.remove(" ");
                rbUsers.close();

                for (String dom : domainsList) {
                    Domain currDom = new Domain(dom, usersListByDomain.get(dom).get(0), devicesListByDomain.get(dom), usersListByDomain.get(dom));
                    domains.add(currDom);
                }
            } catch (Exception e) {
                System.out.println("Erro: " + e);
            } finally {
                serverLock.unlock();
            }

            serverLock.lock();
            //Ir buscar as temps que ja estao no file
            try {
                BufferedReader rb = new BufferedReader(new FileReader("tempsFile.txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] userTemp = line.split(":");
                    temps.put(userTemp[0], Float.parseFloat(userTemp[1]));
                    line = rb.readLine();
                }

                rb.close();
            } catch (Exception e) {
                System.out.println("Erro: " + e);
            } finally {
                serverLock.unlock();
            }



            // Começa aqui a comunicação com os clientes
            while (true){
                SSLSocket cliSocket = (SSLSocket) srvSocket.accept();
                ClientHandler ch = new ClientHandler(cliSocket);
                new Thread(ch).start();
            }


        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class ClientHandler implements Runnable {
        private SSLSocket clientSocket;

        //Para remover do connected
        private String currUser;

        public ClientHandler(SSLSocket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try (
                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
            ) {
                System.out.println("Client connected");

                authOperations(in, out);

                //Handle Auth Dev-id (Later)
                int dev_id = (int) in.readObject();
                int currDevId = handleDevId(in, out, currUser, dev_id);

                //Handle file size
                String programName = (String) in.readObject();
                long programSize = (long) in.readObject();
                boolean fileCheck = handleFileSize(in, out, programName, programSize);

                if (!fileCheck) {
                    out.close();
                    in.close();
                    clientSocket.close();
                    System.out.println("User " + currUser + "_" + currDevId + " disconnected.");
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
                                serverLock.lock();
                                Domain newDomain = new Domain(reqSplit[1], currUser);
                                newDomain.addUser(currUser);
                                domains.add(newDomain);

                                
                                try{
                                    //Escrever no domains file
                                    BufferedWriter myWriterDomainsCR = new BufferedWriter(new FileWriter("domainsInfo.txt", true));
                                    myWriterDomainsCR.write(reqSplit[1] + " (Users):" + currUser + System.getProperty("line.separator"));
                                    myWriterDomainsCR.write(reqSplit[1] + " (Devices):" + System.getProperty("line.separator"));
                                    myWriterDomainsCR.close();

                                    out.writeObject("OK");
                                    out.flush();
                                } catch (IOException e) {
                                    e.printStackTrace();
                                } finally {
                                    serverLock.unlock();
                                }
                                break;
                            }
                            
                            boolean found = false;
                            for (Domain dom : domains) {
                                if (dom.getName().equals(reqSplit[1])) {
                                    found = true;
                                    out.writeObject("NOK");
                                    out.flush();
                                    break;
                                }
                            }

                            if (found) break;
                            
                            
                            serverLock.lock();
                            try{
                                Domain newDomain = new Domain(reqSplit[1], currUser);
                                newDomain.addUser(currUser);
                                domains.add(newDomain);
                                //Escrever no domains file
                                BufferedWriter myWriterDomainsCR = new BufferedWriter(new FileWriter("domainsInfo.txt", true));
                                //O primeiro user é o creator
                                myWriterDomainsCR.write(reqSplit[1] + " (Users):" + currUser + System.getProperty("line.separator"));
                                myWriterDomainsCR.write(reqSplit[1] + " (Devices):" + System.getProperty("line.separator"));
                                myWriterDomainsCR.close();

                                out.writeObject("OK");
                                out.flush();
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }
                            break;
                        case "ADD":
                            serverLock.lock();
                            try{
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
                                    }
                                }
    
                                if (!domainExists) {
                                    out.writeObject("NODM # esse dominio nao existe");
                                    out.flush();
                                    break;
                                }
    
                                if (!selectedDomADD.getCreator().equals(currUser)) {
                                    out.writeObject("NOPERM # sem permissoes");
                                    out.flush();
                                    break;
                                }
                                
                                if (selectedDomADD.getUsers().contains(reqSplit[1])) {
                                    out.writeObject("NOK # o user ja se encontra no dominio");
                                    out.flush();
                                    break;
                                }

                                domains.remove(selectedDomADD);
                                selectedDomADD.addUser(reqSplit[1]);
                                domains.add(selectedDomADD);
    
                                updateDomainsFile();
    
                                out.writeObject("OK");
                                out.flush();
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }

                            break;
                        case "RD":
                            serverLock.lock();
                            try{
                                Domain selectedDomRD = null;
                                boolean exists = false;

                                for (Domain dom : domains) {
                                    if (dom.getName().equals(reqSplit[1])) {
                                        exists = true;
                                        selectedDomRD = dom;
                                    }
                                }

                                if (!exists) {
                                    out.writeObject("NODM # esse dominio nao existe");
                                    out.flush();
                                    break;
                                }

                                if (!selectedDomRD.getUsers().contains(currUser)) {
                                    out.writeObject("NOPERM # sem permissoes");
                                    out.flush();
                                    break;
                                }

                                domains.remove(selectedDomRD);
                                selectedDomRD.addDevice(currUser + "_" + currDevId);;
                                domains.add(selectedDomRD);
                                
                                updateDomainsFile();

                                out.writeObject("OK");
                                out.flush();
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }
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

                            serverLock.lock();
                            try{
                                temps.put(currUser + "_" + currDevId, Float.parseFloat(reqSplit[1]));

                                //Write no temps file
                                tempsFile.delete();
                                tempsFile = new File("tempsFile.txt");

                                BufferedWriter etFileWriter = new BufferedWriter(new FileWriter(tempsFile, true));

                                for (Map.Entry<String, Float> set : temps.entrySet()) {
                                    etFileWriter.write(set.getKey() + ":" + set.getValue() + System.getProperty("line.separator"));
                                }

                                etFileWriter.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }

                            break;
                        case "EI":
                            ei(reqSplit[1], currUser, currDevId, in, out);
                            break;
                        case "RT":
                            serverLock.lock();
                            try {
                                //Primeiro criar o file para enviar
                                File rtFile = new File("tempsFileSend.txt");

                                BufferedWriter rtFileWriter = new BufferedWriter(new FileWriter(rtFile, true));
                                Domain rtDomain = null;

                                for (Domain dom : domains) {
                                    
                                    if (dom.getName().equals(reqSplit[1])) {
                                        //Check read perms
                                        if (!dom.getUsers().contains(currUser)) {
                                            out.writeObject("NOPERM # sem permissoes de leitura");
                                            out.flush();
                                            rtFileWriter.close();
                                            rtFile.delete();
                                            break;
                                        }

                                        rtDomain = dom;
                                    }
                                }

                                if (rtDomain == null) {
                                    out.writeObject("NODM # esse dominio nao existe");
                                    out.flush();
                                    rtFileWriter.close();
                                    rtFile.delete();
                                    break;
                                }

                                if (temps.isEmpty()) {
                                    out.writeObject("NODATA # nao existem dados de temperatura publicados");
                                    out.flush();
                                    rtFileWriter.close();
                                    rtFile.delete();
                                    break;
                                }

                                for (int i = 0; i < rtDomain.getDevices().size(); i++) {
                                    String currId = rtDomain.getDevices().get(i);

                                    if (temps.containsKey(currId)) {
                                        rtFileWriter.write(currId + ":" + temps.get(currId) + " ");
                                    }
                                }

                                rtFileWriter.close();

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
                                inputRT.close();
                                finRT.close();
                                rtFile.delete();
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }
                            break;
                        case "RI":
                            String[] userDataRI = reqSplit[1].split(":");

                            serverLock.lock();
                            try{
                                BufferedReader regReader = new BufferedReader(new FileReader("registeredDevices.txt"));
                                String regReaderLine = regReader.readLine();
                                LinkedList<String> devs = new LinkedList<String>();

                                while (regReaderLine != null){
                                    devs.add(regReaderLine);
                                    regReaderLine = regReader.readLine();
                                }

                                regReader.close();

                                if (!devs.contains(reqSplit[1])) {
                                    out.writeObject("NOID # esse device id não existe");
                                    out.flush();
                                    break;
                                }

                                if (!new File(userDataRI[0] + "_" + userDataRI[1] + ".jpg").exists()) {
                                    out.writeObject("NODATA # nao existem dados de imagem publicados");
                                    out.flush();
                                    break;
                                }
                                
                                boolean hasPerms = false;

                                if (reqSplit[1].equals(currUser + ":" + currDevId)) {
                                    hasPerms = true;
                                }
                                else 
                                {
                                    for (Domain dom : domains) {
                                        if (dom.getDevices().contains(userDataRI[0] + "_" + userDataRI[1])) {
                                            //Check read perms
                                            if (dom.getUsers().contains(currUser)) {
                                                hasPerms = true;
                                            }
                                        }
                                    }
                                }

                                if (!hasPerms) {
                                    out.writeObject("NOPERM # sem permissoes de leitura");
                                    out.flush();
                                    break;
                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }

                            serverLock.lock();

                            try {
                                ri(userDataRI[0] + "_" + userDataRI[1] + ".jpg", in, out);
                            } catch (Exception e) {
                                System.out.println("An error occurred: " + e.getMessage());
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }

                            break;
                        default:     
                            out.writeObject("Pedido Invalido!");
                            out.flush();
                    }
                }
            } catch (SocketException e) {
                System.out.println(("Client disconnected: " + e.getMessage()));
                
                serverLock.lock();
                try{
                    if (connected.containsKey(currUser)) {
                        connected.remove(currUser);
                    }
                } finally {
                    serverLock.unlock();
                }
                
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }

        private void authOperations(ObjectInputStream in, ObjectOutputStream out) {
            try {
                //4.2.1
                String userId = (String) in.readObject();

                byte[] nonce;
                boolean isRegistered = verifyUser(userId);

                try {
                    // Enviar nonce para o cliente
                    nonce = generateNonce();
                    out.writeObject(nonce);
                    out.flush();
                    
                    if (isRegistered) {
                        out.writeObject("registered");

                        byte[] signedNonce = (byte[]) in.readObject();

                        FileInputStream fis = new FileInputStream(userId.split("@")[0] + ".cer");
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        Certificate cert = cf.generateCertificate(fis);
                        PublicKey userPubKey = cert.getPublicKey();
                        fis.close();

                        Signature s = Signature.getInstance("MD5withRSA");
                        s.initVerify(userPubKey);
                        s.update(nonce);
                        boolean verifySig = s.verify(signedNonce);

                        if (verifySig) {
                            out.writeObject("checkedvalid");
                            out.flush();
                        }
                        else 
                        {
                            out.writeObject("checkedinvalid");
                            out.flush();
                        }
                    } else {
                        out.writeObject("notregistered");

                        byte[] recNonce = (byte[]) in.readObject();
                        byte[] recSignature = (byte[]) in.readObject();
                        Certificate recCertificate = (Certificate) in.readObject();
                        PublicKey recPubKey = recCertificate.getPublicKey();

                        //Criar certificate file do user
                        byte[] certBytes = recCertificate.getEncoded();
                        String[] splitEmail = userId.split("@");
                        FileOutputStream fos = new FileOutputStream(splitEmail[0] + ".cer");
                        fos.write(certBytes);
                        fos.close();

                        Signature s = Signature.getInstance("MD5withRSA");
                        s.initVerify(recPubKey);
                        s.update(recNonce);
                        boolean verifySig = s.verify(recSignature);

                        if (Arrays.equals(recNonce, nonce) && verifySig) {
                            out.writeObject("checkedvalid");
                            out.flush();

                            BufferedWriter myWriterUsers = new BufferedWriter(new FileWriter("users.txt", true));
                            myWriterUsers.write(userId + ":" + splitEmail[0] + ".cer" + System.getProperty("line.separator"));
                            myWriterUsers.close();
                            userCredentials.put(userId, splitEmail[0] + ".cer");

                            LinkedList<Integer> newUserDevIds = new LinkedList<>();

                            connected.put(userId.split("@")[0], newUserDevIds);
                        }
                        else 
                        {
                            out.writeObject("checkedinvalid");
                            out.flush();
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }

                String[] temp = userId.split("@");
                currUser = temp[0];

                //4.2.2
                String C2FA = Utils.generateC2FA();

                if (userId.equals("tjca2000@gmail.com") || userId.equals("mgacampos10@gmail.com")) {
                    out.writeObject("yes");
                    out.flush();

                    sendEmail(userId, C2FA);
                }
                else 
                {
                    boolean correctEmail = false;

                    while (!correctEmail) {
                        out.writeObject("no");
                        out.flush();

                        userId = (String) in.readObject();

                        if (userId.equals("tjca2000@gmail.com") || userId.equals("mgacampos10@gmail.com")) {
                            correctEmail = true;
                        }
                    }

                    out.writeObject("yes");
                    out.flush();

                    sendEmail(userId, C2FA);
                }

                String recCode = (String) in.readObject();

                if (!recCode.equals(C2FA)) {
                    out.writeObject("C2FA code incorrect.");
                    out.flush();

                    String userTryAgain = (String) in.readObject();

                    if (userTryAgain.equals("tryagain")) {
                        authOperations(in, out);
                    }
                }
                else 
                {
                    out.writeObject("C2FA code correct. User auth success.");
                    out.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void sendEmail(String userId, String C2FA) {
            String apiKey = "zWG5VYlpX9NwOWLvUqn1"; // Chave da API de dois fatores

            // Monta a URL com os parâmetros fornecidos
            String url = "https://lmpinto.eu.pythonanywhere.com/2FA?e=" + userId + "&c=" + C2FA + "&a=" + apiKey;

            try {
                // Cria um objeto URL a partir da string da URL
                URL requestUrl = new URI(url).toURL();
                
                // Abre a conexão HTTP
                HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
                
                // Define o método HTTP como GET
                connection.setRequestMethod("GET");
                
                // Lê a resposta da API
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();

                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                reader.close();
                
                // Imprime a resposta da API
                System.out.println("Response from API: " + response.toString());

                // Fecha a conexão
                connection.disconnect();
                
                // Espera 5 segundos entre as chamadas (conforme requisito da API)
                TimeUnit.SECONDS.sleep(5);
            } catch (IOException | InterruptedException | URISyntaxException e) {
                e.printStackTrace();
            }
        }

        private static byte[] generateNonce() throws NoSuchAlgorithmException {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            byte[] nonce = new byte[8];
            secureRandom.nextBytes(nonce);
            return nonce;
        }

        private static boolean verifyUser(String userId) {
            try {
                BufferedReader rb = new BufferedReader(new FileReader("users.txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] splitLine = line.split(":");

                    if (splitLine[0].equals(userId)) {
                        rb.close();
                        return true;
                    }
                }

                rb.close();
            } catch (Exception e) {
                System.out.println("Erro: " + e);
            }

            return false;
        }

        private static synchronized void handleAuth(ObjectInputStream in, ObjectOutputStream out, String login, String user, String password) throws IOException, ClassNotFoundException {
            if (!userCredentials.containsKey(user)) {
                //Novo user

                LinkedList<Integer> newUserDevIds = new LinkedList<>();

                serverLock.lock();
                try{
                    //Escrever no credentials file
                    BufferedWriter myWriterUsers = new BufferedWriter(new FileWriter("users.txt", true));
                    myWriterUsers.write(login + System.getProperty("line.separator"));
                    myWriterUsers.close();
                    userCredentials.put(user, password);

                    out.writeObject("OK-NEW-USER");
                    out.flush();

                    connected.put(user, newUserDevIds);
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    serverLock.unlock();
                }
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

        private static synchronized int handleDevId(ObjectInputStream in, ObjectOutputStream out, String user, int dev_id) throws IOException, ClassNotFoundException {
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

            //Criar registered devices history ou atualizar
            serverLock.lock();
            regHist = new File("registeredDevices.txt");
            try {
                if (regHist.createNewFile()) {
                    System.out.println("Registered devices history file created.");
                } else 
                {
                    System.out.println("Registered devices history already present, registering device...");
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }

            serverLock.lock();
            try{
                BufferedReader regReader = new BufferedReader(new FileReader("registeredDevices.txt"));
                String regReaderLine = regReader.readLine();
                LinkedList<String> devs = new LinkedList<String>();

                while (regReaderLine != null){
                    devs.add(regReaderLine);
                    regReaderLine = regReader.readLine();
                }

                regReader.close();

                if (!devs.contains(user + ":" + dev_id)) {
                    devs.add(user + ":" + dev_id);
                }
                else 
                {
                    System.out.println("Device already registered.");
                }

                regHist.delete();
                regHist = new File("registeredDevices.txt");

                BufferedWriter myWriterRegs = new BufferedWriter(new FileWriter(regHist, true));

                for (String s : devs) {
                    myWriterRegs.write(s + System.getProperty("line.separator"));
                }

                myWriterRegs.close();

                out.writeObject("OK-DEVID");
                out.flush();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }

            return dev_id;
        }

        private static synchronized boolean handleFileSize(ObjectInputStream in, ObjectOutputStream out, String progName, long progSize) {
            boolean retval = false;

            serverLock.lock();
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
            } finally {
                serverLock.unlock();
            }

            return retval;
        }

        private synchronized static void updateDomainsFile() throws IOException {
            serverLock.lock();
            try{
                domainsInfo.delete();
                domainsInfo = new File("domainsInfo.txt");
    
                BufferedWriter myWriterDomains = new BufferedWriter(new FileWriter(domainsInfo, true));
    
                for (Domain d : domains) {
                    LinkedList<String> usersDom = d.getUsers();
                    StringBuilder stringBuilderUsers = new StringBuilder();
                    StringBuilder stringBuilderDevices = new StringBuilder();
    
                    for (String s : usersDom) {
                        stringBuilderUsers.append(s + " ");
                    }
    
                    myWriterDomains.write(d.getName() + " (Users):" + stringBuilderUsers.toString() + System.getProperty("line.separator"));
    
                    if (d.getDevices() != null) {
                        LinkedList<String> devicesDom = d.getDevices();
    
                        for (String s : devicesDom) {
                            stringBuilderDevices.append(s + " ");
                        }
    
                        myWriterDomains.write(d.getName() + " (Devices):" + stringBuilderDevices.toString() + System.getProperty("line.separator"));
                    }
                    else 
                    {
                        myWriterDomains.write(d.getName() + " (Devices):" + System.getProperty("line.separator"));
                    }
                }
    
                myWriterDomains.close();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }
        }

        public synchronized void ei(String fileName, String name, int devid,ObjectInputStream in, ObjectOutputStream out){
            String destinationFileName = name + "_" + devid + ".jpg";

            String rec = null;
            try {
                rec = (String) in.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (!rec.equals("found")) {
                return;
            }


            serverLock.lock();
            try {
                // Receive file size from client
                int fileSize = in.readInt();
    
                // Create buffer to read file data
                byte[] buffer = new byte[fileSize];
                int totalBytesRead = 0;
                int bytesRead;
                while (totalBytesRead < fileSize && (bytesRead = in.read(buffer, totalBytesRead, fileSize - totalBytesRead)) != -1) {
                    totalBytesRead += bytesRead;
                }
    
                if (totalBytesRead != fileSize) {
                    throw new IOException("File size mismatch. Expected: " + fileSize + ", Received: " + totalBytesRead);
                }
                if (fileName.endsWith(".jpg")) {
                    // Write received file data to the destination file
                    FileOutputStream fileOutputStream = new FileOutputStream(destinationFileName);
                    fileOutputStream.write(buffer, 0, totalBytesRead);
                    fileOutputStream.close();

                    System.out.println("File received from client and saved successfully.");

                    out.writeObject("OK");
                    out.flush();
                }
                else 
                {
                    out.writeObject("NOK");
                    out.flush();
                }

                return;
            } catch (IOException e) {
                System.out.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }
        }

        public static void ri(String sourceFileName, ObjectInputStream in, ObjectOutputStream out){
            try (
                 FileInputStream fileInputStream = new FileInputStream(sourceFileName)) {
                
                out.writeObject("OK");
                out.flush();
    
                // Get the file size
                File file = new File(sourceFileName);
                int fileSize = (int) file.length();
                byte[] fileData = new byte[fileSize];
                // Read the entire file into memory
                int bytesRead = 0;
                while (bytesRead < fileSize) {
                    bytesRead += fileInputStream.read(fileData, bytesRead, fileSize - bytesRead);
                }
                // Write the file size to the output stream
                out.writeInt(fileSize);
                // Write the file data to the output stream
                out.write(fileData);
                out.flush(); // Ensure all data is sent
                //close
                fileInputStream.close();
    
                System.out.println("File sent to client successfully.");
            } catch (Exception e) {
                System.out.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
            }
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

        public synchronized LinkedList<String> getDevices() {
            return devices;
        }

        public synchronized LinkedList<String> getUsers() {
            return users;
        }

        public synchronized void addDevice(String devId) {
            devices.add(devId);
        }

        public synchronized void addUser(String user) {
            users.add(user);
        }
    }
}