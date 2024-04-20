//Grupo 15: Tiago Almeida (58161), Manuel Campos (58166), Tiago Rocha (58242)

// <serverAddress> identifica o servidor. O formato de serverAddress é o seguinte:
// <IP/hostname>[:Port]. O endereço IP/hostname do servidor é obrigatório e o
// porto é opcional. Por omissão, o cliente deve ligar-se ao porto 12345 do servidor.
// <dev-id> - número inteiro que identifica o dispositivo.
// <user-id> - string que identifica o (endereço de email do) utilizador local.

// IoTDevice <serverAddress> <truststore> <keystore> <passwordkeystore> <dev-id> <user-id>

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;

// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
// NOTA: COMPARAR OS OUT & IN do CLIENTE E DO SERVIDOR para garantir que não há falhas
// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
public class IoTDevice {

    private static SSLSocket clientSocket;
    private static ObjectOutputStream out;
    private static ObjectInputStream in;

    private static final int DEFAULT_PORT = 12345;
    private static KeyStore kstore;
    private static KeyStore tstore;

    private static final SecureRandom rd = new SecureRandom();

    private static Map<String, byte[]> saltsByDomain = new HashMap<String, byte[]>();
    private static Map<String, Integer> itersByDomain = new HashMap<String, Integer>();

    private static File itersFile;

    public static void main(String[] args) {
        try {
            System.out.println("Client Initializing...");
            Scanner sc = new Scanner(System.in);

            // Verificar o numero de argumentos
            if (!argsCheck(args)) {
                sc.close();
                return;
            }

            // Iniciar a ligação ao servidor
            String serverAddress;
            int port = DEFAULT_PORT;
            String[] addr = args[0].split(":");
            int devId = Integer.parseInt(args[4]);
            String userId = args[5];

            FileInputStream tfile = new FileInputStream(args[1]);  //truststore
            FileInputStream kfile = new FileInputStream(args[2]);  //keystore

            kstore = KeyStore.getInstance("JCEKS");
            tstore = KeyStore.getInstance("JCEKS");

            char[] kstorepass = args[3].toCharArray();

            kstore.load(kfile, kstorepass);                  //password para aceder à keystore
            tstore.load(tfile, "grupoquinze".toCharArray()); //password para aceder à truststore

            if (addr.length == 1) {
                serverAddress = addr[0];
            } else {
                serverAddress = addr[0];
                port = Integer.parseInt(addr[1]);
            }

            //Setup do TLS/SSL
            String trustStore = args[1];
            String trustStorePassword = args[3];

            clientSocket = UtilsClient.initializeClient(trustStore, trustStorePassword, serverAddress, port);
            clientSocket.startHandshake();

            // Inicializar os streams
            out = new ObjectOutputStream(clientSocket.getOutputStream());
            in = new ObjectInputStream(clientSocket.getInputStream());

            //4.2
            boolean twoFactorSucc = twoFactorAuth(sc, out, userId, in, tstore, kstore, kstorepass);

            if (!twoFactorSucc) {
                return;
            }

            // Enviar o devId
            out.writeObject(devId);
            out.flush();

            // Receber resposta
            String msgDevId = (String) in.readObject();
            if (msgDevId.equals("NOK-DEVID")) {
                System.out.println();
                System.out.println("Device ID already in use.");
                return;
            }

            System.out.println(msgDevId);

            // Receber resposta
            String srvResponse = UtilsClient.exeCliTest(out, in);

            if (srvResponse.equals("NOK-TESTED") || srvResponse.equals("error") ) {
                System.out.println("File not tested");
                clientSocket.close();
                System.exit(1);
            } else {
                System.out.println("File tested");
            }

            //Criar iters file caso nao exista
            itersFile = new File("iters_" + userId + ".txt");

            if (itersFile.createNewFile()) {
                System.out.println("Personal iters file created");
            } else 
            {
                System.out.println("Personal iters file already exists.");
            }

            //Repopular iters map do user, se ja nao for a primeira conexao do cliente
            File itersFile = new File("iters_" + userId + ".txt");
            if (itersFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader("iters_" + userId + ".txt"));
                String iterLine = reader.readLine();

                while (iterLine != null){
                    String[] splitLine = iterLine.split(":");

                    itersByDomain.put(splitLine[0], Integer.parseInt(splitLine[1]));

                    iterLine = reader.readLine();
                }

                reader.close();
            }

            //Repopular salts map do user, se ja nao for a primeira conexao do cliente
            File directory = new File(".");
            File[] files = directory.listFiles();

            //Ver quais sao ficheiros de salt e repopular
            for (File file : files) {
                if (file.isFile() && file.getName().startsWith("salt_")) {
                    try (FileInputStream fis = new FileInputStream(file.getName())) {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        byte[] buffer = new byte[1024];
                        int length;
    
                        while ((length = fis.read(buffer)) != -1) {
                            bos.write(buffer, 0, length);
                        }
                        
                        String fileName = file.getName().replace(".txt", "");
                        saltsByDomain.put(fileName.split("_")[2], bos.toByteArray());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

            System.out.println();
            System.out.println();

            // Mostrar menu de opções
            System.out.println("Menu de Opções:");
            System.out.println("CREATE <dm> # Criar domínio - utilizador é Owner");
            System.out.println("ADD <user1> <dm> <password-dominio> # Adicionar utilizador <user1> ao domínio <dm>");
            System.out.println("RD <dm> # Registar o Dispositivo atual no domínio <dm>");
            System.out.println("ET <float> # Enviar valor <float> de Temperatura para o servidor.");
            System.out.println("EI <filename.jpg> # Enviar Imagem <filename.jpg> para o servidor.");
            System.out.println("RT <dm> # Receber as últimas medições de Temperatura de cada dispositivo do domínio <dm>, desde que o utilizador tenha permissões.");
            System.out.println("RI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo <userid>:<dev_id> do servidor, desde que o utilizador tenha permissões.");

            System.out.println();

            while (true) {
                System.out.println("--------------------------------------------------");
                System.out.println("Enter command:");
                String command = sc.nextLine();
                String[] parts = command.split(" ");

                if (command.startsWith("CREATE")) {

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } 
                    else 
                    {
                        String domainName = parts[1];

                        out.writeObject("CREATE " + domainName);
                        out.flush();
                    }

                    srvResponse = (String) in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("ADD")) {

                    if (parts.length != 4) {
                        System.out.println("Invalid command");
                        continue;
                    } 
                    else 
                    {
                        out.writeObject("ADD " + parts[1] + " " + parts[2] + " ");
                        out.flush();

                        try {
                            srvResponse = (String) in.readObject();

                            if (srvResponse.equals("OK")) {
                                UtilsClient.genAndSendKey(saltsByDomain, itersByDomain, parts[2], parts[1], parts[3], tstore, rd, out);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }

                    System.out.println(srvResponse);

                } else if (command.startsWith("RD")) {

                    try {
                        if (parts.length != 2) {
                            System.out.println("Invalid command");
                            continue;
                        } 
                        else 
                        {
                            String domainName = parts[1];
                            out.writeObject("RD" + " " + domainName);
                            out.flush();
                        }

                        srvResponse = (String) in.readObject();
                        System.out.println(srvResponse);
                    } catch(Exception e) {
                        e.printStackTrace();
                    }

                } else if (command.startsWith("ET")) {

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } 
                    else 
                    {
                        try {
                            out.writeObject("ET" + " " + parts[1]);
                            out.flush();

                            srvResponse = (String) in.readObject();

                            if (srvResponse.equals("OK")) {
                                //Receber o tamanho da lista de dominios a que pertence
                                int myDomSize = (int) in.readObject();

                                //Guardar as suas keys de dominio
                                LinkedList<SecretKey> recSKeys = new LinkedList<SecretKey>();

                                for (int i = 0; i < myDomSize; i++) {
                                    byte[] secretKeyCiph = (byte[]) in.readObject();

                                    //Dar unwrap da key com a propria private key
                                    Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");

                                    //Get da private key pela key store pessoal
                                    PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);

                                    //Unwrap da key
                                    dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                                    SecretKey secretKey = (SecretKey) dec.unwrap(secretKeyCiph, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);
                                    recSKeys.add(secretKey);
                                }

                                //Utilizar cada key de dominio para enviar a temperatura cifrada para cada domain ao server, bem como os parametros usados no encrypt para depois dar decrypt
                                for (int i = 0; i < recSKeys.size(); i++) {
                                    Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                                    c.init(Cipher.ENCRYPT_MODE, recSKeys.get(i));
                                    byte[] ciphInfo = c.doFinal(parts[1].getBytes());
                                    byte[] params = c.getParameters().getEncoded();

                                    out.writeObject(ciphInfo);
                                    out.flush();

                                    out.writeObject(params);
                                    out.flush();
                                }
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }

                    System.out.println(srvResponse);

                } else if (command.startsWith("EI")) {
                    out.writeObject(command);
                    out.flush();
                    String sourceFileName = parts[1];
                    srvResponse = (String) in.readObject();
                    boolean retEi = ei(sourceFileName, userId, kstorepass);

                    if (!retEi) {
                        continue;
                    }

                    System.out.println(srvResponse);

                } else if (command.startsWith("RT")) {

                    try {
                        if (parts.length != 2) {
                            System.out.println("Invalid command");
                            continue;
                        } else {
                            out.writeObject("RT" + " " + parts[1]);
                            out.flush();
                        }
    
                        srvResponse = (String) in.readObject();
    
                        if (srvResponse.equals("OK")) {
                            //Key
                            byte[] recKey = (byte[]) in.readObject();

                            //Unwrap da key cifrada recebida
                            Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);
                            dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                            SecretKey secretKey = (SecretKey) dec.unwrap(recKey, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);
    
                            //Decrypt da informacao recebida (cada temp de cada user do domain) com a domain key
                            StringBuilder rtSb = new StringBuilder();
                            rtSb.append(parts[1] + ": ");
                            int recSize = (int) in.readObject();
    
                            for (int i = 0; i < recSize; i++) {
                                String recUser = (String) in.readObject();
                                byte[] recTemp = (byte[]) in.readObject();
                                byte[] params = (byte[]) in.readObject();
                                
                                //Parametros para decrypt
                                AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
                                p.init(params);

                                Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                                cipher.init(Cipher.DECRYPT_MODE, secretKey, p);
    
                                //Decrypt dos dados
                                byte[] decryptedTemp = cipher.doFinal(recTemp);
                                String strTemp = new String(decryptedTemp);
    
                                rtSb.append(recUser + ":" + strTemp + " ");
                            }
    
                            System.out.println(srvResponse + "," + rtSb.toString());
                        }
                        else 
                        {
                            System.out.println(srvResponse);
                        }
                    } catch(Exception e) {
                        e.printStackTrace();
                    }

                } else if (command.startsWith("RI")) {

                    try {
                        if (parts.length != 2) {
                            System.out.println("Invalid command");
                            continue;
                        } else {
                            out.writeObject("RI" + " " + parts[1]);
                            out.flush();
                        }
    
                        srvResponse = (String) in.readObject();
    
                        if (srvResponse.equals("OK")) {
                            //Key
                            byte[] recKey = (byte[]) in.readObject();

                            //Unwrap da key cifrada recebida
                            Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);
                            dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                            SecretKey secretKey = (SecretKey) dec.unwrap(recKey, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);
    
                            //Decrypt da informacao recebida (imagem enviada pelo user para o domain valido) com a domain key
                            byte[] recImg = (byte[]) in.readObject();
                            byte[] params = (byte[]) in.readObject();
                            
                            //Parametros para decrypt
                            AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
                            p.init(params);
    
                            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, p);
    
                            //Decrypt da data
                            byte[] decryptedImg = cipher.doFinal(recImg);
    
                            String[] reqUser = parts[1].split(":");
    
                            //Criar file .jpg com os dados decrypted (Formato do nome -> targetUser_targetDevId_received)
                            FileOutputStream fileOutputStream = new FileOutputStream(reqUser[0] + "_" + reqUser[1] + "_received" + ".jpg");
                            fileOutputStream.write(decryptedImg);
                            fileOutputStream.close();
    
                            System.out.println(srvResponse);
                        }
                        else 
                        {
                            System.out.println(srvResponse);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                } else if (command.startsWith("MYDOMAINS")) {
                    out.writeObject("MYDOMAINS");
                    out.flush();

                    StringBuilder sb = new StringBuilder();

                    int domSize = (int) in.readObject();

                    //Caso nao esteja em nenhum domain, print "NO DOMAINS", se sim imprimir os nomes dos domains
                    if (domSize == 0) {
                        System.out.println("NO DOMAINS");
                    }
                    else 
                    {
                        for (int i = 0; i < domSize; i++) {
                            String domName = (String) in.readObject();
                            sb.append(domName);

                            if (i < domSize - 1) {
                                sb.append(System.getProperty("line.separator"));
                            }
                        }
    
                        System.out.println(sb.toString());
                    }

                } else {
                    System.out.println("Invalid command");
                }
            }

        } catch (Exception e) {
            System.err.println("Disconnecting from Server...");
        }
    }

    public static boolean twoFactorAuth(Scanner sc, ObjectOutputStream out, String userId, ObjectInputStream in, KeyStore tstore, KeyStore kstore, char[] kstorepass) {
        boolean firstStep = UtilsClient.assymCrypt(out, userId, in, tstore, kstore, kstorepass);
        boolean secondStep = UtilsClient.emailConf(sc, out, in, userId, tstore, kstore, kstorepass);

        return firstStep && secondStep;
    }

    public static boolean argsCheck(String[] args) {
        if (args.length != 6) {
            System.out.println("---------------------------------");
            System.out.println("--Incorrect number of arguments--");
            System.out.println("--> IoTDevice <serverAddress> <truststore> <keystore> <passwordkeystore> <dev-id> <user-id> <--");
            System.out.println("---------------------------------");
            return false;
        }
        return true;
    }

    public static boolean ei(String sourceFileName, String userId, char[] kstorepass){
        try (
             FileInputStream fileInputStream = new FileInputStream(sourceFileName)) {
            
            //Verificar se a imagem existe
            try {
                out.writeObject("found");
                out.flush();
            } catch (IOException e2) {
                e2.printStackTrace();
            }

            //Tamanho da imagem
            File file = new File(sourceFileName);
            int fileSize = (int) file.length();
            byte[] fileData = new byte[fileSize];

            //Ler os bytes da imagem em memoria
            int bytesRead = 0;
            while (bytesRead < fileSize) {
                bytesRead += fileInputStream.read(fileData, bytesRead, fileSize - bytesRead);
            }

            //Receber numero de domains em que esta
            int myDomSize = (int) in.readObject();

            //Guardar as chaves de cada domain
            LinkedList<SecretKey> recSKeys = new LinkedList<SecretKey>();

            //Para cada domain, receber e dar unwrap da chave para depois encriptar a informacao com ela
            for (int i = 0; i < myDomSize; i++) {
                byte[] secretKeyCiph = (byte[]) in.readObject();

                Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);
                dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                SecretKey secretKey = (SecretKey) dec.unwrap(secretKeyCiph, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);

                recSKeys.add(secretKey);
            }

            //Enviar os bytes da imagem encriptados para cada domain em que esta
            for (int i = 0; i < recSKeys.size(); i++) {
                Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                c.init(Cipher.ENCRYPT_MODE, recSKeys.get(i));
                byte[] ciphImg = c.doFinal(fileData);
                byte[] params = c.getParameters().getEncoded();

                out.writeObject(ciphImg);
                out.flush();

                out.writeObject(params);
                out.flush();
            }

            fileInputStream.close();

            System.out.println("File sent to server successfully.");
            return true;

        } catch (FileNotFoundException e) {
            System.out.println("Image file not found, select a valid image.");

            try {
                out.writeObject("notfound");
                out.flush();
            } catch (IOException e1) {
                e1.printStackTrace();
            }

            return false;
        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
