// <serverAddress> identifica o servidor. O formato de serverAddress é o seguinte:
// <IP/hostname>[:Port]. O endereço IP/hostname do servidor é obrigatório e o
// porto é opcional. Por omissão, o cliente deve ligar-se ao porto 12345 do servidor.
// • <dev-id> - número inteiro que identifica o dispositivo.
// • <user-id> - string que identifica o (endereço de email do) utilizador local.

// IoTDevice <serverAddress> <dev-id> <user-id>

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
// NOTA: COMPARAR OS OUT & IN do CLIENTE E DO SERVIDOR para garantir que não há falhas
// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
public class IoTDevice {

    private static final String[] protocols = new String[]{"TLSv1.3"};
    private static final String[] cipher_suites = new String[]{"TLS_AES_128_GCM_SHA256"};
    private static SSLSocket clientSocket;
    private static ObjectOutputStream out;
    private static ObjectInputStream in;
    public static void main(String[] args) {
        try {
            System.out.println("Client Initializing...");
            Scanner sc = new Scanner(System.in);

            // Verificar o numero de argumentos
            if (!argsCheck(args)) {
                return;
            }

            // Iniciar a ligação ao servidor
            String serverAddress;
            int port = 12345;
            String[] addr = args[0].split(":");
            int devId = Integer.parseInt(args[1]);
            String userId = args[2];

            if (addr.length == 1) {
                serverAddress = addr[0];
            } else {
                serverAddress = addr[0];
                port = Integer.parseInt(addr[1]);
            }

            //Setup do TLS/SSL

            System.setProperty("javax.net.ssl.trustStore", "cliTruststore");
            System.setProperty("javax.net.ssl.trustStorePassword", "grupo15");

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            clientSocket = (SSLSocket) sslSocketFactory.createSocket(serverAddress, port);
            clientSocket.setEnabledProtocols(protocols);
            clientSocket.setEnabledCipherSuites(cipher_suites);

            clientSocket.startHandshake(); 

            out = new ObjectOutputStream(clientSocket.getOutputStream());
            in = new ObjectInputStream(clientSocket.getInputStream());

            // Pedir a password
            System.out.print("Insere a tua Password: ");
            String password = sc.nextLine();

            // Enviar a password
            out.writeObject(userId + ":" + password);
            out.flush();

            String msgPass = (String) in.readObject();

            // Loop para verificar a password
            while (msgPass.equals("WRONG-PWD")) {
                System.out.println("Password Errada");
                System.out.print("Insere a tua Password: ");
                password = sc.nextLine();
                out.writeObject(password);
                out.flush();
                msgPass = (String) in.readObject();
            }

            System.out.println(msgPass);

            // Enviar o devId
            out.writeObject(devId);
            out.flush();

            // Receber resposta
            String msgDevId = (String) in.readObject();
            while (msgDevId.equals("NOK-DEVID")) {
                System.out.println();
                System.out.println("Device ID em Utilização");
                System.out.print("Insere um novo Device ID: ");
                devId = sc.nextInt();
                out.writeObject(devId);
                out.flush();
                msgDevId = (String) in.readObject();
            }

            System.out.println(msgDevId);

            // O cliente envia o nome e o tamanho do ficheiro executável IoTDevice (.class)
            String flName = "IoTDevice.class";
            File f = new File(flName);
            int flSize = (int) f.length();

            FileInputStream fis = new FileInputStream(f);
            BufferedInputStream bis = new BufferedInputStream(fis);
            byte[] bytesBuffer = new byte[flSize];
            long bytesRd = bis.read(bytesBuffer, 0, bytesBuffer.length);

            out.writeObject(flName);
            out.flush();
            out.writeObject(bytesRd);
            out.flush();
            System.out.println("File Verification: " + flName + ":" + bytesRd + " sent to server!");
            
            // Receber a resposta do servidor
            String srvResponse = (String) in.readObject();

            if (srvResponse.equals("NOK-TESTED")) {
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
            System.out.println("ADD <user1> <dm> # Adicionar utilizador <user1> ao domínio <dm>");
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

                    if (parts.length != 3) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        String user = parts[1];
                        String domainName = parts[2];
                        out.writeObject("ADD " + user + " " + domainName);
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
                        String fileContent = new String(buffer);
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
                        ri(reqUser[0], Integer.parseInt(reqUser[1]), in, out);
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

    public static boolean argsCheck(String[] args) {
        if (args.length != 3) {
            System.out.println("---------------------------------");
            System.out.println("--Incorrect number of arguments--");
            System.out.println("--> IoTDevice <serverAddress> <dev-id> <user-id> <--");
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

    public static synchronized void ri(String name, int devid, ObjectInputStream in, ObjectOutputStream out){
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

                // Write received file data to the destination file
                FileOutputStream fileOutputStream = new FileOutputStream(destinationFileName);
                fileOutputStream.write(buffer, 0, totalBytesRead);
                fileOutputStream.close();

                System.out.println("OK, " + fileSize + " (long)");
            } catch (IOException e) {
                System.out.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
            }
        }
}
