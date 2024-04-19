import java.io.*;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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

    // Password a ser usada para gerar a chave simetrica que cifra os ficheiros da aplicacao
    private static String pass_cypher;

    //Par de chaves do server
    private static KeyStore sv_store;

    //Password da sv_store
    private static String pass_keystore;

    //Api-key grupo15
    private static String apiKey;

    // Username : Certificado com chave publica
    private static volatile Map<String, String> userCredentials = new HashMap<>();
    
    //Lista de domains do servidor
    private static volatile LinkedList<Domain> domains = new LinkedList<Domain>();

    //Dev-id connected - dispositivos que estao connected de momento ao server
    private static volatile Map<String, LinkedList<Integer>> connected = new HashMap<String, LinkedList<Integer>>();

    //Last device temp
    private static volatile Map<String, byte[]> tempsByDomain = new HashMap<String, byte[]>();
    private static volatile Map<String, byte[]> tempsByDomainParams = new HashMap<String, byte[]>();

    //Last device img
    private static volatile Map<String, byte[]> imgsByDomain = new HashMap<String, byte[]>();
    private static volatile Map<String, byte[]> imgsByDomainParams = new HashMap<String, byte[]>();

    //Ficheiro usado para ter persistencia de dados de login de users
    private static File userFile;

    //App name e size
    private static File clientProgramData;
    private static byte[] progDataHMAC;
    private static File progDataHMACFile;

    //Ficheiro usado para ter persistencia dos dominios e o seu estado
    private static File domainsInfo;
    private static byte[] domainsHMAC;
    private static File domainsHMACFile;

    //Ficheiro usado para ter persistencia das ultimas temperaturas enviadas
    private static File tempsFile;

    //Registered devices history
    private static File regHist;

    //Chaves de dominio no formato key -> <domainName_user> : value -> <chave cifrada em byte[]>
    private static volatile Map<String, byte[]> domainKeys = new HashMap<String, byte[]>();

    //Salt usado no encrypt e decrypt do users file
    private static byte[] sv_salt;

    //Params usados no decrypt do users file com o PBEWithHmacSHA256AndAES_128
    private static byte[] user_enc_params;

    //Ficheiro usado para ter persistencia do salt usado no encrypt e decrypt do users
    private static File sv_salt_file;

    //Ficheiro usado para ter persistencia dos ultimos params usados no encrypt do users
    private static File last_params;
 
    public static void main(String[] args) {
        //No caso de nao dar porta nos args
        port = DEFAULT_PORT;

        if (args.length != 5) {
            System.out.println("Formato: IoTServer <port> <password-cifra> <keystore> <password-keystore> <2FA-APIKey>");
            return;
        }

        // TLS/SSL
        String keyStore = args[2];

        port = Integer.parseInt(args[0]);

        pass_cypher = args[1];

        //Verificar se ja existe um salt para ser usado no encrypt e decrypt do users.txt
        //Não existe -> Gerar o salt e registar no file
        //Existe -> Ir buscar ao file e associar a variavel global
        sv_salt_file = new File("txtFiles/svSalt.txt");
        serverLock.lock();
        try {
            if (sv_salt_file.createNewFile()) {
                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[8];
                random.nextBytes(salt);

                try (FileOutputStream fos = new FileOutputStream("txtFiles/svSalt.txt")) {
                    fos.write(salt);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                
                sv_salt = salt;
            } else 
            {
                try (FileInputStream fis = new FileInputStream("txtFiles/svSalt.txt")) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int length;

                    while ((length = fis.read(buffer)) != -1) {
                        bos.write(buffer, 0, length);
                    }

                    sv_salt = bos.toByteArray();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            serverLock.unlock();
        }

        //Verificar se ja houve alguma encriptacao do users.txt
        //Se ja houve -> Ir buscar esses parametros e associar a variavel global user_enc_params
        last_params = new File("txtFiles/lastParams.txt");
        serverLock.lock();
        try {

            boolean existParams = last_params.createNewFile();
            if (!existParams) {
                try (FileInputStream fis = new FileInputStream("txtFiles/lastParams.txt")) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int length;

                    while ((length = fis.read(buffer)) != -1) {
                        bos.write(buffer, 0, length);
                    }

                    user_enc_params = bos.toByteArray();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            serverLock.unlock();
        }

        pass_keystore = args[3];

        //Load do objeto keystore do server com os dados do file
        try {
            FileInputStream kStoreFile = new FileInputStream(args[2]);
            sv_store = KeyStore.getInstance("JCEKS");
            sv_store.load(kStoreFile, pass_keystore.toCharArray());           //password para aceder à keystore
        } catch (Exception e) {
            e.printStackTrace();
        }

        apiKey = args[4];

        serverLock.lock();
        //Criar file com info do HMAC do domainsInfo caso nao exista
        domainsHMACFile = new File("txtFiles/domainsInfoHMAC.txt");
        try {
            boolean created = domainsHMACFile.createNewFile();
            
            if (!created) {
                try (FileInputStream fis = new FileInputStream("txtFiles/domainsInfoHMAC.txt")) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int length;

                    while ((length = fis.read(buffer)) != -1) {
                        bos.write(buffer, 0, length);
                    }

                    domainsHMAC = bos.toByteArray();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            serverLock.unlock();
        }

        serverLock.lock();
        //Criar file com info do HMAC do clientProgramData caso nao exista
        progDataHMACFile = new File("txtFiles/progDataHMAC.txt");
        try {
            boolean created = progDataHMACFile.createNewFile();
            
            if (!created) {
                try (FileInputStream fis = new FileInputStream("txtFiles/progDataHMAC.txt")) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int length;

                    while ((length = fis.read(buffer)) != -1) {
                        bos.write(buffer, 0, length);
                    }

                    progDataHMAC = bos.toByteArray();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            serverLock.unlock();
        }

        //Criar size e nome do client executable caso nao exista
        serverLock.lock();
        clientProgramData = new File("txtFiles/clientProgram.txt");
        try {
            if (clientProgramData.createNewFile()) {
                System.out.println("Client file data created");

                //Escrever nome e size
                BufferedWriter myWriterClient = new BufferedWriter(new FileWriter("txtFiles/clientProgram.txt", true));
                myWriterClient.write("IoTDeviceCopy.class");
                myWriterClient.close();

                progDataHMAC = UtilsServer.calculateHMAC("IoTDeviceCopy.class", pass_cypher, sv_salt);
            } else 
            {
                System.out.println("Client file data already exists.");

                if (UtilsServer.calculateHMAC("IoTDeviceCopy.class", pass_cypher, sv_salt) != progDataHMAC) {
                    System.out.println("Executable tampered with.");
                    System.exit(-1);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            serverLock.unlock();
        }

        serverLock.lock();
        //Criar file com info dos domains caso nao exista
        domainsInfo = new File("txtFiles/domainsInfo.txt");
        try {
            if (domainsInfo.createNewFile()) {
                System.out.println("Domains file created");
                domainsHMAC = UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt);
            } else 
            {
                System.out.println("Domains file already exists.");

                if (UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt) != domainsHMAC) {
                    System.out.println("Domains file tampered with.");
                    System.exit(-1);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            serverLock.unlock();
        }

        serverLock.lock();
        try (SSLServerSocket srvSocket = UtilsServer.initializeServer(keyStore, pass_keystore, port)) {


            System.out.println("Server initialized on port: " + port);

            //Criar user file caso nao exista
            userFile = new File("txtFiles/users.txt");
            if (userFile.createNewFile()) {
                System.out.println("Users file created");
            } else {
                System.out.println("Users file already exists.");
            }
            
            //Criar temps file caso nao exista
            tempsFile = new File("txtFiles/tempsFile.txt");
            if (tempsFile.createNewFile()) {
                System.out.println("Temps file created");
            } else {
                System.out.println("Temps file already exists.");
            }

            if (user_enc_params != null) {
                UtilsServer.decryptUsersFile("txtFiles/users.txt", pass_cypher, sv_salt, user_enc_params);
            }

            //Ir buscar as credentials que ja estao no file
            try {
                BufferedReader rb = new BufferedReader(new FileReader("txtFiles/users.txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] user = line.split(":");
                    userCredentials.put(user[0], user[1]);
                    line = rb.readLine();
                }

                rb.close();
            } catch (Exception e) {
                System.out.println("Erro (Search credentials): " + e);
                e.printStackTrace();
            }

            user_enc_params = UtilsServer.encryptUsersFile("txtFiles/users.txt", pass_cypher, sv_salt);

            
            //Ir buscar os dominios que ja estao no file
            try {
                if (UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt) != domainsHMAC) {
                    System.out.println("Domains file tampered with.");
                    System.exit(-1);
                }

                //Filtrar as linhas de devices e acrescentar a um mapa de devices por domain
                BufferedReader rbDevices = new BufferedReader(new FileReader("txtFiles/domainsInfo.txt"));
                String lineDevices = rbDevices.readLine();
                Map<String, LinkedList<String>> devicesListByDomain = new HashMap<String, LinkedList<String>>();

                while (lineDevices != null){
                    String[] dom = lineDevices.split(":");

                    if (dom.length > 1) {
                        String[] domType = dom[0].split(" ");

                        if (domType[1].equals("(Devices)")) {
                            LinkedList<String> devices = new LinkedList<String>();

                            if (dom.length == 2) {
                                for (String dev : dom[1].split(" ")) {
                                    devices.add(dev);
                                }
                            }

                            devicesListByDomain.put(domType[0], devices);
                        }
                    }

                    lineDevices = rbDevices.readLine();
                }

                rbDevices.close();

                //Tem sempre um espaço a mais -> remover
                devicesListByDomain.remove(" ");

                //Registar os nomes dos diferentes domains
                LinkedList<String> domainsList = new LinkedList<String>();

                //Filtrar as linhas de users e acrescentar a um mapa de users por domain
                BufferedReader rbUsers = new BufferedReader(new FileReader("txtFiles/domainsInfo.txt"));
                String lineUsers = rbUsers.readLine();
                Map<String, LinkedList<String>> usersListByDomain = new HashMap<String, LinkedList<String>>();

                while (lineUsers != null){
                    String[] dom = lineUsers.split(":");
                    String[] domType = dom[0].split(" ");

                    if (domType[1].equals("(Users)")) {
                        LinkedList<String> usersSplit = new LinkedList<String>();

                        if (dom.length == 2) {
                            for (String us : dom[1].split(" ")) {
                                usersSplit.add(us);
                            }
                        }

                        usersListByDomain.put(domType[0], usersSplit);
                        domainsList.add(domType[0]);
                    }

                    lineUsers = rbUsers.readLine();
                }

                //Tem sempre um espaço a mais -> remover
                usersListByDomain.remove(" ");
                rbUsers.close();

                //Filtrar as linhas que indicam o creator do domain e registar tambem num mapa
                Map<String, String> domainCreators = new HashMap<String, String>();
                BufferedReader rbCreators = new BufferedReader(new FileReader("txtFiles/domainsInfo.txt"));
                String lineCreators = rbCreators.readLine();

                while (lineCreators != null){
                    String[] dom = lineCreators.split(":");
                    String[] domType = dom[0].split(" ");

                    if (domType[1].equals("(CREATOR)")) {
                        domainCreators.put(domType[0], dom[1]);
                    }

                    lineCreators = rbCreators.readLine();
                }

                rbCreators.close();

                //Construir os domains que ja existiam por persistencia com a listas organizadas acima, e adicionar a lista de domains do server
                for (String dom : domainsList) {
                    Domain currDom = new Domain(dom, domainCreators.get(dom), devicesListByDomain.get(dom), usersListByDomain.get(dom));
                    domains.add(currDom);
                }

                domainsHMAC = UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt);
            } catch (Exception e) {
                System.out.println("Erro (Search domains): " + e);
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }

            serverLock.lock();
            //Ir buscar as temps que ja estao no file
            try {
                BufferedReader rb = new BufferedReader(new FileReader("txtFiles/tempsFile.txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] userTemp = line.split(":");
                    tempsByDomain.put(userTemp[0], userTemp[1].getBytes(StandardCharsets.UTF_8));
                    line = rb.readLine();
                }

                rb.close();
            } catch (Exception e) {
                System.out.println("Erro (Search temps): " + e);
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }

            serverLock.lock();
            //Ir buscar chaves de domain que ja existiam
            try {
                File domKeysFolder = new File("domKeys");

                for (File fileEntry : domKeysFolder.listFiles()) {
                    try (FileInputStream fis = new FileInputStream("domKeys/" + fileEntry.getName())) {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        byte[] buffer = new byte[1024];
                        int length;
    
                        while ((length = fis.read(buffer)) != -1) {
                            bos.write(buffer, 0, length);
                        }
    
                        domainKeys.put(fileEntry.getName().replace(".txt", ""), bos.toByteArray());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e) {
                System.out.println("Erro (Get dom keys): " + e);
                e.printStackTrace();
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

        //Para remover do connected em caso de desconexao
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

                //Handle Auth Dev-id
                int dev_id = (int) in.readObject();
                int currDevId = handleDevId(in, out, currUser, dev_id);

                if (currDevId == -1) {
                    out.close();
                    in.close();
                    clientSocket.close();
                    System.out.println();
                    System.out.println("-------|Attempted to connect with the same device id|-------");
                    System.out.println();
                    return;
                }

                // adicionar o nonce como verificação para o cliente
                byte[] nonce = generateNonce();

                out.writeObject(nonce);
                out.flush();

                //Handle file
                byte[] exeTest = (byte[]) in.readObject();
                int fileCheck = handleFile(in, out, nonce, exeTest);

                if (fileCheck == -1) {
                    out.close();
                    in.close();
                    clientSocket.close();
                    System.out.println("Tampered program data file, disconnecting...");
                    return;
                }

                if (fileCheck == 0) {
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
                                domains.add(newDomain);

                                try {
                                    if (UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt) != domainsHMAC) {
                                        System.out.println("Domains file tampered with.");
                                        System.exit(-1);
                                    }

                                    //Escrever no domains file
                                    BufferedWriter myWriterDomainsCR = new BufferedWriter(new FileWriter("txtFiles/domainsInfo.txt", true));

                                    //Lista de users
                                    myWriterDomainsCR.write(reqSplit[1] + " (Users):" + System.getProperty("line.separator"));

                                    //Lista de devices
                                    myWriterDomainsCR.write(reqSplit[1] + " (Devices):" + System.getProperty("line.separator"));

                                    //Criador
                                    myWriterDomainsCR.write(reqSplit[1] + " (CREATOR):" + currUser + System.getProperty("line.separator"));

                                    myWriterDomainsCR.close();

                                    domainsHMAC = UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt);

                                    out.writeObject("OK");
                                    out.flush();
                                } catch (IOException e) {
                                    e.printStackTrace();
                                } finally {
                                    serverLock.unlock();
                                }

                                break;
                            }
                            
                            //Verificar se o domain ja existe
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

                            try {
                                Domain newDomain = new Domain(reqSplit[1], currUser);
                                domains.add(newDomain);

                                if (UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt) != domainsHMAC) {
                                    System.out.println("Domains file tampered with.");
                                    System.exit(-1);
                                }

                                //Escrever no domains file
                                BufferedWriter myWriterDomainsCR = new BufferedWriter(new FileWriter("txtFiles/domainsInfo.txt", true));

                                myWriterDomainsCR.write(reqSplit[1] + " (Users):" + System.getProperty("line.separator"));
                                myWriterDomainsCR.write(reqSplit[1] + " (Devices):" + System.getProperty("line.separator"));
                                myWriterDomainsCR.write(reqSplit[1] + " (CREATOR):" + currUser + System.getProperty("line.separator"));
                                myWriterDomainsCR.close();

                                domainsHMAC = UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt);

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
                                
                                out.writeObject("OK");
                                out.flush();

                                //Receber a chave cifrada do user que se deu add para o domain e registar no mapa
                                byte[] cyDomainKey = (byte[]) in.readObject();
                                domainKeys.put(reqSplit[2] + "_" + reqSplit[1], cyDomainKey);

                                //Registar a nova key num file para persistencia
                                File newKeyFile = new File("domKeys/" + reqSplit[2] + "_" + reqSplit[1] + ".txt");
                                newKeyFile.createNewFile();

                                try (FileOutputStream fos = new FileOutputStream("domKeys/" + reqSplit[2] + "_" + reqSplit[1] + ".txt")) {
                                    fos.write(cyDomainKey);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }

                                domains.remove(selectedDomADD);
                                selectedDomADD.addUser(reqSplit[1]);
                                domains.add(selectedDomADD);
    
                                updateDomainsFile();

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

                                //Verificar se o domain existe
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

                                //Verificar se o user esta no domain
                                if (!selectedDomRD.getUsers().contains(currUser)) {
                                    out.writeObject("NOPERM # sem permissoes");
                                    out.flush();
                                    break;
                                }

                                //Remover para modificar
                                domains.remove(selectedDomRD);

                                //Criar a lista com o novo device no caso de ainda nao existir, adicionar o device caso exista
                                if (selectedDomRD.getDevices() == null) {
                                    LinkedList<String> addDevs = new LinkedList<String>();
                                    addDevs.add(currUser + "_" + currDevId);
                                    selectedDomRD.setDevices(addDevs);
                                }
                                else 
                                {   
                                    selectedDomRD.addDevice(currUser + "_" + currDevId);
                                }

                                //Voltar a dar add do domain e dar update no txt
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
                            //Verificar se a temp e um valor de float valido ("BANANA" nao daria nao e)
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
                                LinkedList<String> deviceDomains = getDeviceDomains(currUser, currDevId);

                                out.writeObject(deviceDomains.size());
                                out.flush();

                                //Enviar as keys do user de todos os seus domains
                                for (int i = 0; i < deviceDomains.size(); i++) {
                                    out.writeObject(domainKeys.get(deviceDomains.get(i) + "_" + currUser));
                                    out.flush();
                                }

                                //Registar as temps recebidas por domain, bem como os params para decrypt
                                for (int i = 0; i < deviceDomains.size(); i++) {
                                    byte[] ciphTemp = (byte[]) in.readObject();
                                    byte[] paramsTemp = (byte[]) in.readObject();
                                    tempsByDomain.put(currUser + "_" + currDevId + "_" + deviceDomains.get(i), ciphTemp);
                                    tempsByDomainParams.put(currUser + "_" + currDevId + "_" + deviceDomains.get(i), paramsTemp);
                                }

                                //Write no temps file
                                tempsFile.delete();
                                tempsFile = new File("txtFiles/tempsFile.txt");

                                BufferedWriter etFileWriter = new BufferedWriter(new FileWriter(tempsFile, true));

                                for (Map.Entry<String, byte[]> set : tempsByDomain.entrySet()) {
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
                            ei(reqSplit[1], currUser, currDevId, in, out, currDevId);
                            break;
                        case "RT":
                            serverLock.lock();
                            try {
                                Domain rtDomain = null;

                                for (Domain dom : domains) {
                                    //Ir buscar o domain
                                    if (dom.getName().equals(reqSplit[1])) {
                                        //Check read perms (se o user esta no domain)
                                        if (!dom.getUsers().contains(currUser)) {
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

                                if (tempsByDomain.isEmpty()) {
                                    out.writeObject("NODATA # nao existem dados de temperatura publicados");
                                    out.flush();
                                    break;
                                }

                                out.writeObject("OK");
                                out.flush();
                                
                                //Enviar a key do user correspondente ao domain
                                out.writeObject(domainKeys.get(reqSplit[1] + "_" + currUser));
                                out.flush();

                                int resSize = 0;

                                //Enviar o tamanho para o for loop do client
                                for (Map.Entry<String, byte[]> entry : tempsByDomain.entrySet()) {
                                    String key = entry.getKey();
                                    String[] splitKey = key.split("_");
                                    String entDom = splitKey[2];

                                    if (entDom.equals(reqSplit[1])) {
                                        resSize++;
                                    }
                                }

                                out.writeObject(resSize);
                                out.flush();

                                //Enviar as temps cifradas e os params para decrypt
                                for (Map.Entry<String, byte[]> entry : tempsByDomain.entrySet()) {
                                    String key = entry.getKey();

                                    //0 -> Username ; 1 -> DevId ; 2 -> DomainName
                                    String[] splitKey = key.split("_");

                                    String entUser = splitKey[0] + "_" + splitKey[1];
                                    String entDom = splitKey[2];

                                    byte[] value = entry.getValue();

                                    if (entDom.equals(reqSplit[1])) {
                                        out.writeObject(entUser);
                                        out.flush();

                                        out.writeObject(value);
                                        out.flush();

                                        out.writeObject(tempsByDomainParams.get(entUser + "_" + reqSplit[1]));
                                        out.flush();
                                    }
                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }
                            break;
                        case "RI":
                            //O 0 e o username e o 1 o device id
                            String[] userDataRI = reqSplit[1].split(":");

                            Domain chosenDom = null;
                            LinkedList<Domain> possibleDoms = new LinkedList<Domain>();

                            serverLock.lock();
                            try{
                                //Verificar se o dispositivo existe na base de dados
                                BufferedReader regReader = new BufferedReader(new FileReader("txtFiles/registeredDevices.txt"));
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
                                
                                //Verificar se o currentUser esta num dominio que contem o device
                                boolean hasPerms = false;

                                for (Domain dom : domains) {
                                    if (dom.getDevices().contains(userDataRI[0] + "_" + userDataRI[1]) && !hasPerms) {
                                        //Check read perms
                                        if (dom.getUsers().contains(currUser)) {
                                            //Guardar os domains que satisfacam as condicoes
                                            possibleDoms.add(dom);
                                            hasPerms = true;
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
                                for (Domain d : possibleDoms) {
                                    if (imgsByDomain.containsKey(userDataRI[0] + "_" + userDataRI[1] + "_" + d.getName())) {
                                        chosenDom = d;
                                    }
                                }

                                //Verificar se o user ja enviou a imagem para algum dos domains possiveis
                                if (chosenDom == null) {
                                    out.writeObject("NODATA # nao existem dados de imagem publicados");
                                    out.flush();
                                    break;
                                }

                                out.writeObject("OK");
                                out.flush();

                                //Enviar a chave do user correspondente ao domain
                                out.writeObject(domainKeys.get(chosenDom.getName() + "_" + currUser));
                                out.flush();
                                
                                //Enviar a imagem cifrada
                                out.writeObject(imgsByDomain.get(userDataRI[0] + "_" + userDataRI[1] + "_" + chosenDom.getName()));
                                out.flush();

                                //Enviar os params de decrypt
                                out.writeObject(imgsByDomainParams.get(userDataRI[0] + "_" + userDataRI[1] + "_" + chosenDom.getName()));
                                out.flush();
                            } catch (Exception e) {
                                e.printStackTrace();
                            } finally {
                                serverLock.unlock();
                            }

                            break;
                        case "MYDOMAINS":
                            LinkedList<String> deviceDomains = getDeviceDomains(currUser, currDevId);

                            out.writeObject(deviceDomains.size());
                            out.flush();

                            //Enviar a lista de domains 1 por 1
                            if (deviceDomains.size() > 0) {
                                for (String n : deviceDomains) {
                                    out.writeObject(n);
                                    out.flush();
                                }
                            }

                            break;
                        default:     
                            out.writeObject("Pedido Invalido!");
                            out.flush();
                    }
                }
            } catch (SocketException e) {
                System.out.println(("Client \"" + currUser + "\" disconnected"));
                
                //Em caso de desconexao, remover o device da lista de devices conectados
                serverLock.lock();
                try{
                    if (connected.containsKey(currUser)) {
                        connected.remove(currUser);
                    }
                } finally {
                    serverLock.unlock();
                }
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        //Retornar os domains em que o device esta presente (RD)
        private LinkedList<String> getDeviceDomains(String user, int devid) {
            LinkedList<String> ret = new LinkedList<String>();

            for (Domain d : domains) {
                if (d.getDevices().contains(user + "_" + devid)) {
                    ret.add(d.getName());
                }
            }

            return ret;
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

                        //Ir buscar a publicKey do user ao seu certificado
                        FileInputStream fis = new FileInputStream(userId.split("@")[0] + ".cer");
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        Certificate cert = cf.generateCertificate(fis);
                        PublicKey userPubKey = cert.getPublicKey();
                        fis.close();

                        //Verificar a assinatura do nonce
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

                        //Verificar a assinatura com a chave publica enviada
                        Signature s = Signature.getInstance("MD5withRSA");
                        s.initVerify(recPubKey);
                        s.update(recNonce);
                        boolean verifySig = s.verify(recSignature);

                        //Verificar se o nonce e o mesmo criado pelo server e se assinatura foi verificada com sucesso
                        if (Arrays.equals(recNonce, nonce) && verifySig) {
                            out.writeObject("checkedvalid");
                            out.flush();

                            UtilsServer.decryptUsersFile("txtFiles/users.txt", pass_cypher, sv_salt, user_enc_params);

                            //Registar o user no users.txt
                            BufferedWriter myWriterUsers = new BufferedWriter(new FileWriter("txtFiles/users.txt", true));
                            myWriterUsers.write(userId + ":" + splitEmail[0] + ".cer" + System.getProperty("line.separator"));
                            myWriterUsers.close();

                            user_enc_params = UtilsServer.encryptUsersFile("txtFiles/users.txt", pass_cypher, sv_salt);

                            userCredentials.put(userId, splitEmail[0] + ".cer");

                            LinkedList<Integer> newUserDevIds = new LinkedList<>();

                            connected.put(userId, newUserDevIds);
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

                //O user utilizado nas operacoes
                currUser = userId;

                //4.2.2
                String C2FA = UtilsServer.generateC2FA();

                //Emails pre definidos pelo grupo como users validos
                if (userId.equals("tjca2000@gmail.com") || userId.equals("mgacampos10@gmail.com")) {
                    out.writeObject("yes");
                    out.flush();

                    //Enviar o email ao user escolhido
                    sendEmail(userId, C2FA, apiKey);
                }
                else 
                {
                    boolean correctEmail = false;

                    //Verificar se o email enviado e valido
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

                    sendEmail(userId, C2FA, apiKey);
                }

                String recCode = (String) in.readObject();

                //Verificar se o codigo introduzido esta correto
                if (!recCode.equals(C2FA)) {
                    out.writeObject("C2FA code incorrect.");
                    out.flush();

                    String userTryAgain = (String) in.readObject();

                    //Se nao, voltar ao inicio da two-factor auth
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

        private void sendEmail(String userId, String C2FA, String apiKey) {
            //Montar URL para get
            String url = "https://lmpinto.eu.pythonanywhere.com/2FA?e=" + userId + "&c=" + C2FA + "&a=" + apiKey;

            try {
                //Objeto url
                URL requestUrl = new URI(url).toURL();
                
                //Abrir HTTP
                HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
                
                //Definir como get
                connection.setRequestMethod("GET");
                
                //Para ler a resposta da API
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();

                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                reader.close();
                
                //Imprimir a resposta para verificacao na consola do server
                System.out.println("Response from API: " + response.toString());

                //Desligar a connection
                connection.disconnect();
                
                //Esperar 5 secs -> Enunciado
                TimeUnit.SECONDS.sleep(5);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        //Gerar random nonce -> byte[]
        private static byte[] generateNonce() throws NoSuchAlgorithmException {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            byte[] nonce = new byte[8];
            secureRandom.nextBytes(nonce);
            return nonce;
        }

        //Verificar se o user existe na "base de dados" (txt file)
        private static boolean verifyUser(String userId) {
            UtilsServer.decryptUsersFile("txtFiles/users.txt", pass_cypher, sv_salt, user_enc_params);

            try {

                BufferedReader rb = new BufferedReader(new FileReader("txtFiles/users.txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] splitLine = line.split(":");

                    if (splitLine[0].equals(userId)) {
                        rb.close();
                        user_enc_params = UtilsServer.encryptUsersFile("txtFiles/users.txt", pass_cypher, sv_salt);
                        return true;
                    }

                    line = rb.readLine();
                }

                rb.close();
            } catch (Exception e) {
                System.out.println("Erro (Verify User): " + e);
                e.printStackTrace();
            }

            user_enc_params = UtilsServer.encryptUsersFile("txtFiles/users.txt", pass_cypher, sv_salt);

            return false;
        }

        private static synchronized int handleDevId(ObjectInputStream in, ObjectOutputStream out, String user, int dev_id) throws IOException, ClassNotFoundException {
            // se o user ja tiver um device com o mesmo id a ligacao termina
            if (connected.containsKey(user) && connected.get(user).contains(dev_id)) {
                out.writeObject("NOK-DEVID");
                out.flush();
                return -1;
            }

            //Se o user ja tem dispositivos conectados, adicionar, se nao, adicionar ao map
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
            regHist = new File("txtFiles/registeredDevices.txt");
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
                BufferedReader regReader = new BufferedReader(new FileReader("txtFiles/registeredDevices.txt"));
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
                regHist = new File("txtFiles/registeredDevices.txt");

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

        private static synchronized int handleFile(ObjectInputStream in, ObjectOutputStream out, byte [] nonce, byte[] exeTest) {
            int retval = 0;

            serverLock.lock();
            try {
                if (UtilsServer.calculateHMAC("IoTDeviceCopy.class", pass_cypher, sv_salt) != progDataHMAC) {
                    return -1;
                }

                BufferedReader progInfoReader = new BufferedReader(new FileReader("txtFiles/clientProgram.txt"));
                String flName = progInfoReader.readLine();

                File f = new File(flName);
                int flSize = (int) f.length();

                FileInputStream fis = new FileInputStream(f);
                BufferedInputStream bis = new BufferedInputStream(fis);
                byte[] bytesBuffer = new byte[flSize];
                long bytesRd = bis.read(bytesBuffer, 0, bytesBuffer.length);

                // Concatenar o nonce o conteudo do ficheiro
                byte[] concatNonceFl = new byte[nonce.length + bytesBuffer.length];
                System.arraycopy(nonce, 0, concatNonceFl, 0, nonce.length);
                System.arraycopy(bytesBuffer, 0, concatNonceFl, nonce.length, bytesBuffer.length);

                bis.close();

                // Calcular o hash do ficheiro
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(concatNonceFl);

                if ( Arrays.equals(hash, exeTest) ) {
                    out.writeObject("OK-TESTED");
                    out.flush();
                    retval = 1;
                }
                else 
                {
                    out.writeObject("NOK-TESTED");
                    out.flush();
                    retval = 0;
                }

                progInfoReader.close();
                progDataHMAC = UtilsServer.calculateHMAC("IoTDeviceCopy.class", pass_cypher, sv_salt);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }

            return retval;
        }

        //Adicionar novos domains ao file (Users, Devices, Creator)
        private synchronized static void updateDomainsFile() throws IOException {
            serverLock.lock();
            try{
                if (UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt) != domainsHMAC) {
                    System.out.println("Domains file tampered with.");
                    System.exit(-1);
                }

                domainsInfo.delete();
                domainsInfo = new File("txtFiles/domainsInfo.txt");
    
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

                    myWriterDomains.write(d.getName() + " (CREATOR):" + d.getCreator() + System.getProperty("line.separator"));
                }
    
                myWriterDomains.close();

                domainsHMAC = UtilsServer.calculateHMAC("txtFiles/domainsInfo.txt", pass_cypher, sv_salt);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                serverLock.unlock();
            }
        }

        public synchronized void ei(String fileName, String name, int devid, ObjectInputStream in, ObjectOutputStream out, int currDevId){
            try {
                //Verificar se a foto e JPG
                if (fileName.endsWith(".jpg")) {
                    System.out.println("File received from client and saved successfully.");
    
                    out.writeObject("OK");
                    out.flush();
                }
                else 
                {
                    out.writeObject("NOK");
                    out.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            //Verificar se a foto foi encontrada no lado do client, se nao, abortar
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

            //Guardar a imagem cifrada no map
            serverLock.lock();
            try {
                //Procurar os domains em que o device esta presente
                LinkedList<String> deviceDomains = getDeviceDomains(currUser, currDevId);
                
                //Enviar o size para for loop
                out.writeObject(deviceDomains.size());
                out.flush();
                
                //Enviar as keys correspondentes ao user de cada um dos seus domains
                for (int i = 0; i < deviceDomains.size(); i++) {
                    out.writeObject(domainKeys.get(deviceDomains.get(i) + "_" + currUser));
                    out.flush();
                }
                
                //Receber a imagem cifrada para cada um dos seus domains, e os parametros da cifra para depois decifrar
                for (int i = 0; i < deviceDomains.size(); i++) {
                    byte[] ciphImg = (byte[]) in.readObject();
                    byte[] paramsImg = (byte[]) in.readObject();

                    //Formato da key -> username_devId_domainName
                    imgsByDomain.put(currUser + "_" + currDevId + "_" + deviceDomains.get(i), ciphImg);
                    imgsByDomainParams.put(currUser + "_" + currDevId + "_" + deviceDomains.get(i), paramsImg);
                }
            } catch (Exception e) {
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
    
                //Tamanho do file
                File file = new File(sourceFileName);
                int fileSize = (int) file.length();
                byte[] fileData = new byte[fileSize];

                //Ler o ficheiro em memoria
                int bytesRead = 0;
                while (bytesRead < fileSize) {
                    bytesRead += fileInputStream.read(fileData, bytesRead, fileSize - bytesRead);
                }


                //Enviar o size e o conteudo
                out.writeInt(fileSize);
                out.write(fileData);
                out.flush();

                fileInputStream.close();
    
                System.out.println("File sent to client successfully.");
            } catch (Exception e) {
                System.out.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    //Custom class para domains
    private static class Domain {
        //Nome
        private String name;

        //Nome do user que criou
        private String creator;

        //Lista de devices pertencentes
        private LinkedList<String> devices;

        //Lista de users pertencentes
        private LinkedList<String> users;

        //Construtor basico
        public Domain(String name, String creator) {
            this.name = name;
            this.creator = creator;
            this.devices = new LinkedList<String>();
            this.users = new LinkedList<String>();
        }

        //Construtor completo
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

        public synchronized void setDevices(LinkedList<String> newDevs) {
            this.devices = newDevs;
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