import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class server {
    private static ServerSocket serverSocket;
    private static Socket socket;
    public static void main(String[] args) {
        int serverPort = 12345; // Server port
        try {
            serverSocket = new ServerSocket(serverPort);
            System.out.println("Server listening on port " + serverPort);
            socket = serverSocket.accept();


            ei("manuel",3);


            serverSocket.close();
            socket.close();
        } catch (IOException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void ei(String name, int devid){
        String destinationFileName = name + "-" + devid + ".jpg";

        try {
            // Receive file size from client
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            int fileSize = dataInputStream.readInt();

            // Create buffer to read file data
            byte[] buffer = new byte[fileSize];
            int totalBytesRead = 0;
            int bytesRead;
            while (totalBytesRead < fileSize && (bytesRead = socket.getInputStream().read(buffer, totalBytesRead, fileSize - totalBytesRead)) != -1) {
                totalBytesRead += bytesRead;
            }

            if (totalBytesRead != fileSize) {
                throw new IOException("File size mismatch. Expected: " + fileSize + ", Received: " + totalBytesRead);
            }

            // Write received file data to the destination file
            FileOutputStream fileOutputStream = new FileOutputStream(destinationFileName);
            fileOutputStream.write(buffer, 0, totalBytesRead);
            fileOutputStream.close();

            // Close streams and sockets
            dataInputStream.close();
            socket.close();
            serverSocket.close();

            System.out.println("File received from client and saved successfully.");
        } catch (IOException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
