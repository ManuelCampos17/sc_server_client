// <serverAddress> identifica o servidor. O formato de serverAddress é o seguinte:
// <IP/hostname>[:Port]. O endereço IP/hostname do servidor é obrigatório e o
// porto é opcional. Por omissão, o cliente deve ligar-se ao porto 12345 do servidor.
// • <dev-id> - número inteiro que identifica o dispositivo.
// • <user-id> - string que identifica o (endereço de email do) utilizador local.

// IoTDevice <serverAddress> <truststore> <keystore> <passwordkeystore> <dev-id> <user-id>

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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

    private static File saltsAndIters;

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
            String trustStorePassword = args[3]; // Mudar, para já é igual à password da keystore

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

            // Enviar o devId (NAO VAI SER AQUI, VAI SER MUDADO DE SITIO DEPOIS)
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

            //Criar salts and iters file caso nao exista
            saltsAndIters = new File("saltsAndIters_" + userId + ".txt");

            if (saltsAndIters.createNewFile()) {
                System.out.println("Personal salts file created");
            } else 
            {
                System.out.println("Personal salts file already exists.");
            }

            //Ir buscar os salts e iters do file
            try {
                BufferedReader rb = new BufferedReader(new FileReader("saltsAndIters_" + userId + ".txt"));
                String line = rb.readLine();

                while (line != null){
                    String[] splitLine = line.split(":");
                    String dom = splitLine[0];
                    String params = splitLine[1];

                    byte[] getSalt = (params.split(" ")[0]).getBytes();
                    int getIter = Integer.parseInt(params.split(" ")[1]);

                    saltsByDomain.put(dom, getSalt);
                    itersByDomain.put(dom, getIter);

                    line = rb.readLine();
                }

                rb.close();
            } catch (Exception e) {
                System.out.println("Erro: " + e);
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
            System.out.println(
                    "RT <dm> # Receber as últimas medições de Temperatura de cada dispositivo do domínio <dm>, desde que o utilizador tenha permissões.");
            System.out.println(
                    "RI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo <userid>:<dev_id> do servidor, desde que o utilizador tenha permissões.");

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
                    } else {
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
                    } else {
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
                        } else {
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
                    } else {
                        try {
                            out.writeObject("ET" + " " + parts[1]);
                            out.flush();

                            srvResponse = (String) in.readObject();

                            if (srvResponse.equals("OK")) {
                                int myDomSize = (int) in.readObject();

                                LinkedList<SecretKey> recSKeys = new LinkedList<SecretKey>();

                                for (int i = 0; i < myDomSize; i++) {
                                    byte[] secretKeyCiph = (byte[]) in.readObject();

                                    Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                    PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);
                                    dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                                    SecretKey secretKey = (SecretKey) dec.unwrap(secretKeyCiph, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);
                                    recSKeys.add(secretKey);
                                }

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

                } else if (command.startsWith("RT")) { // print("OK" + " " + fileSize + " " + conteudo)

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
                            Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);
                            dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                            SecretKey secretKey = (SecretKey) dec.unwrap(recKey, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);
    
                            //Data
                            StringBuilder rtSb = new StringBuilder();
                            rtSb.append(parts[1] + ": ");
                            int recSize = (int) in.readObject();
    
                            for (int i = 0; i < recSize; i++) {
                                String recUser = (String) in.readObject();
                                byte[] recTemp = (byte[]) in.readObject();
                                byte[] params = (byte[]) in.readObject();
                                

                                AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
                                p.init(params);

                                Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                                cipher.init(Cipher.DECRYPT_MODE, secretKey, p);
    
                                // Descriptografar os dados
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

                } else if (command.startsWith("RI")) { // print("OK" + " " + fileSize + " " + conteudo)

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
                            Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);
                            dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                            SecretKey secretKey = (SecretKey) dec.unwrap(recKey, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);
    
                            //Data
                            byte[] recImg = (byte[]) in.readObject();
                            byte[] params = (byte[]) in.readObject();
    
                            AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
                            p.init(params);
    
                            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, p);
    
                            // Descriptografar os dados
                            byte[] decryptedImg = cipher.doFinal(recImg);
    
                            String[] reqUser = parts[1].split(":");
    
                            // Write received file data to the destination file
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

            try {
                out.writeObject("found");
                out.flush();
            } catch (IOException e2) {
                e2.printStackTrace();
            }

            // Get the file size
            File file = new File(sourceFileName);
            int fileSize = (int) file.length();
            byte[] fileData = new byte[fileSize];
            // Read the entire file into memory
            int bytesRead = 0;
            while (bytesRead < fileSize) {
                bytesRead += fileInputStream.read(fileData, bytesRead, fileSize - bytesRead);
            }

            int myDomSize = (int) in.readObject();

            LinkedList<SecretKey> recSKeys = new LinkedList<SecretKey>();

            for (int i = 0; i < myDomSize; i++) {
                byte[] secretKeyCiph = (byte[]) in.readObject();

                Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(userId.split("@")[0], kstorepass);
                dec.init(Cipher.UNWRAP_MODE, myPrivateKey);
                SecretKey secretKey = (SecretKey) dec.unwrap(secretKeyCiph, "PBEWithHmacSHA256AndAES_128", Cipher.SECRET_KEY);
                recSKeys.add(secretKey);
            }

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

            //close
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

    public static synchronized void ri(String name, int devid, ObjectInputStream in, ObjectOutputStream out, char[] kpass){
            String destinationFileName = name + "_" + devid + "_received" + ".jpg";

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

                byte[] recKey = (byte[]) in.readObject();

                Cipher dKey = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                Key myPrivateKey = kstore.getKey(name, kpass);
                dKey.init(Cipher.DECRYPT_MODE, myPrivateKey);
                byte[] decKey = dKey.doFinal(recKey);

                SecretKey secretKey = new SecretKeySpec(decKey, "AES");

                Cipher dData = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                dData.init(Cipher.DECRYPT_MODE, secretKey);
                byte [] dec = dData.doFinal(buffer);

                // Write received file data to the destination file
                FileOutputStream fileOutputStream = new FileOutputStream(destinationFileName);
                fileOutputStream.write(dec, 0, totalBytesRead);
                fileOutputStream.close();

                System.out.println("OK, " + fileSize + " (long)");
            } catch (Exception e) {
                System.out.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
            }
        }
}
