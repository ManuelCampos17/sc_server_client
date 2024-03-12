// <serverAddress> identifica o servidor. O formato de serverAddress é o seguinte:
// <IP/hostname>[:Port]. O endereço IP/hostname do servidor é obrigatório e o
// porto é opcional. Por omissão, o cliente deve ligar-se ao porto 12345 do servidor.
// • <dev-id> - número inteiro que identifica o dispositivo.
// • <user-id> - string que identifica o (endereço de email do) utilizador local.

// IoTDevice <serverAddress> <dev-id> <user-id>

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.util.Scanner;

// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
// NOTA: COMPARAR OS OUT & IN do CLIENTE E DO SERVIDOR para garantir que não há falhas
// --------------------------------- //
// --------------------------------- //
// --------------------------------- //
public class IoTDevice {

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

            Socket clientSocket = new Socket(serverAddress, port);
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

            // Pedir a password
            System.out.print("Insere a tua Password: ");
            String password = sc.nextLine();

            // Enviar a password
            out.writeObject(userId + ":" + password);

            String msgPass = (String) in.readObject();

            // Loop para verificar a password
            while (msgPass.equals("WRONG-PWD")) {
                System.out.println("Password Errada");
                System.out.print("Insere a tua Password: ");
                password = sc.nextLine();
                out.writeObject(userId + ":" + password);
                msgPass = (String) in.readObject();
            }

            System.out.println(msgPass);

            // Enviar o devId
            out.writeObject(devId);

            // Receber resposta
            String msgDevId = (String) in.readObject();
            while (msgDevId.equals("NOK-DEVID")) {
                System.out.println();
                System.out.println("Device ID em Utilização");
                System.out.print("Insere um novo Device ID: ");
                devId = sc.nextInt();
                out.writeObject(devId);
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
            int bytesRd = bis.read(bytesBuffer, 0, bytesBuffer.length);
            out.writeObject(bytesRd);
            out.flush();
            out.write(bytesBuffer);
            out.flush();
            System.out.println("File " + flName + " sent to server");

            // Receber a resposta do servidor
            String srvResponse = (String) in.readObject();

            if (srvResponse.equals("NOK-TESTED")) {
                System.out.println("File not tested");
                System.exit(1);
            } else {
                System.out.println("File tested");
            }

            //Mostrar menu de opções
            System.out.println("Menu de Opções:");
            System.out.println("CREATE <dm> # Criar domínio - utilizador é Owner");
            System.out.println("ADD <user1> <dm> # Adicionar utilizador <user1> ao domínio <dm>");
            System.out.println("RD <dm> # Registar o Dispositivo atual no domínio <dm>");
            System.out.println("ET <float> # Enviar valor <float> de Temperatura para o servidor.");
            System.out.println("EI <filename.jpg> # Enviar Imagem <filename.jpg> para o servidor.");
            System.out.println("RT <dm> # Receber as últimas medições de Temperatura de cada dispositivo do domínio <dm>, desde que o utilizador tenha permissões.");
            System.out.println("RI <user-id>:<dev_id> # Receber o ficheiro Imagem do dispositivo <userid>:<dev_id> do servidor, desde que o utilizador tenha permissões.");

            while (true) {

                System.out.println("Enter command:");
                String command = scanner.nextLine();

                if (command.startsWith("CREATE")) {
                    String[] parts = command.split(" ");

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        String domainName = parts[1];
                        out.writeObject("CREATE");
                        out.writeObject(domainName);
                        out.flush();
                    }
                    srvResponse = in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("ADD")) {
                    String[] parts = command.split(" ");

                    if (parts.length != 3) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        String user = parts[1];
                        String domainName = parts[2];
                        out.writeObject("ADD");
                        out.writeObject(user);
                        out.writeObject(domainName);
                        out.flush();
                    }
                    srvResponse = in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("RD")) {
                    String[] parts = command.split(" ");

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        String domainName = parts[1];
                        out.writeObject("RD");
                        out.writeObject(domainName);
                        out.flush();
                    }
                    srvResponse = in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("ET")) {
                    String[] parts = command.split(" ");

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        float temperature = Float.parseFloat(parts[1]);
                        out.writeObject("ET");
                        out.writeFloat(temperature);
                        out.flush();
                    }
                    srvResponse = in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("EI")) {
                    String[] parts = command.split(" ");

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        File file = new File(parts[1]);
                        byte[] buffer = new byte[(int) file.length()];
                        in = new FileInputStream(file);
                        bis = new BufferedInputStream(in);
                        int bytesRead = in.read(buffer, 0, buffer.length);

                        out.writeObject("EI");
                        out.writeInt(bytesRead);
                        out.write(buffer, 0, bytesRead);
                        out.flush();
                    }
                    srvResponse = in.readObject();
                    System.out.println(srvResponse);

                } else if (command.startsWith("RT")) { // print("OK" + " " + fileSize + " " + conteudo)
                    String[] parts = command.split(" ");

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        out.writeObject("RT");
                        out.writeObject(parts[1]);
                        out.flush();
                    }
                    srvResponse = (String) in.readObject();
                    System.out.println(srvResponse.split(", ")[0]); // checkar regex de separação

                    if (srvResponse.startsWith("OK")) {
                        ;
                        long fileSize = Long.parseLong(in.readObject());

                        byte[] buffer = new byte[(int) fileSize];

                        int bytesRead = 0;
                        int count;
                        while (bytesRead < fileSize) {
                            count = in.read(buffer);
                            if (count == -1) break;
                            bytesRead += count;
                        }
                        String fileContent = new String(buffer);
                        System.out.println(fileContent);
                    }

                } else if (command.startsWith("RI")) { // print("OK" + " " + fileSize + " " + conteudo)

                    String[] parts = command.split(" ");

                    if (parts.length != 2) {
                        System.out.println("Invalid command");
                        continue;
                    } else {
                        out.writeObject("RI");
                        out.writeObject(parts[1]);
                        out.flush();
                    }
                    srvResponse = (String) in.readObject();
                    System.out.println(srvResponse.split(" ")[0]); // checkar regex de separação

                    if (srvResponse.startsWith("OK")) {
                        long fileSize = Long.parseLong(in.readObject());

                        byte[] buffer = new byte[(int) fileSize];

                        int bytesRead = 0;
                        int count;
                        while (bytesRead < fileSize) {
                            count = in.read(buffer);
                            if (count == -1) break;
                            bytesRead += count;
                        }
                        String fileContent = new String(buffer);
                        System.out.println(fileContent);
                    }

                } else {
                    System.out.println("Invalid command");
                    continue;
                }
                // Resposta do servidor

            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
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
