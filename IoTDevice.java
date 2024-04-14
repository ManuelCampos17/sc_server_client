// <serverAddress> identifica o servidor. O formato de serverAddress é o seguinte:
// <IP/hostname>[:Port]. O endereço IP/hostname do servidor é obrigatório e o
// porto é opcional. Por omissão, o cliente deve ligar-se ao porto 12345 do servidor.
// • <dev-id> - número inteiro que identifica o dispositivo.
// • <user-id> - string que identifica o (endereço de email do) utilizador local.

// IoTDevice <serverAddress> <truststore> <keystore> <passwordkeystore> <dev-id> <user-id>

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
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

            kstore.load(kfile, kstorepass);           //password para aceder à keystore

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
                        //Gerar key com password - falta guardar os params
                        byte[] salt = new byte[16];
                        rd.nextBytes(salt);

                        int iter = rd.nextInt(1000) + 1;

                        SecretKey domainKey = UtilsClient.generateDomainKey(parts[3], salt, iter);

                        Certificate cert = tstore.getCertificate(parts[1]);
                        PublicKey destUserPubKey = cert.getPublicKey();

                        Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                        c.init(Cipher.ENCRYPT_MODE, destUserPubKey);
                        byte[] dkSend = c.doFinal(domainKey.getEncoded());

                        out.writeObject("ADD " + parts[1] + " " + parts[2] + " " + parts[3]);
                        out.flush();

                        out.writeObject(dkSend);
                        out.flush();
                    }

                    srvResponse = (String) in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("RD")) {

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
                } else if (command.startsWith("ET")) {

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        out.writeObject("ET" + " " + parts[1]);
                        out.flush();
                    }
                    srvResponse = (String) in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("EI")) {
                    out.writeObject(command);
                    out.flush();
                    String sourceFileName = parts[1];
                    boolean retEi = ei(sourceFileName);

                    if (!retEi) {
                        continue;
                    }
                    srvResponse = (String) in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("RT")) { // print("OK" + " " + fileSize + " " + conteudo)

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        out.writeObject("RT" + " " + parts[1]);
                        out.flush();
                    }

                    srvResponse = (String) in.readObject();

                    if (srvResponse.startsWith("OK")) {
                        long fileSize = (long) in.readObject();

                        byte[] buffer = new byte[(int) fileSize];

                        int bytesRead = 0;
                        int count;
                        while (bytesRead < fileSize) {
                            count = in.read(buffer);
                            if (count == -1)
                                break;
                            bytesRead += count;
                        }

                        byte[] recKey = (byte[]) in.readObject();

                        Cipher dKey = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                        Key myPrivateKey = kstore.getKey(userId.split("@")[0], kstorepass);
                        dKey.init(Cipher.DECRYPT_MODE, myPrivateKey);
                        byte[] decKey = dKey.doFinal(recKey);

                        SecretKey secretKey = new SecretKeySpec(decKey, "AES");

                        Cipher dData = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
                        dData.init(Cipher.DECRYPT_MODE, secretKey);
                        byte [] dec = dData.doFinal(buffer);

                        String fileContent = new String(dec);

                        System.out.println(srvResponse + ", " + fileSize + " (long), " + fileContent);
                    }
                    else 
                    {
                        System.out.println(srvResponse);
                    }

                } else if (command.startsWith("RI")) { // print("OK" + " " + fileSize + " " + conteudo)

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        out.writeObject("RI" + " " + parts[1]);
                        out.flush();
                    }

                    srvResponse = (String) in.readObject();

                    String[] reqUser = parts[1].split(":");

                    if (srvResponse.startsWith("OK")) {
                        ri(reqUser[0], Integer.parseInt(reqUser[1]), in, out, kstorepass);
                    }else{
                        System.out.println(srvResponse);
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

    public static boolean ei(String sourceFileName){
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
            // Write the file size to the output stream
            out.writeInt(fileSize);
            // Write the file data to the output stream
            out.write(fileData);
            out.flush(); // Ensure all data is sent
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
        } catch (IOException e) {
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
