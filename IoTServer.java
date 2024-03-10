public class IoTServer {
    public static void main(String[] args) {
        try {
            ServerSocket server = new ServerSocket(8080);
            System.out.println("Server started at port 8080");
            while (true) {
                Socket client = server.accept();
                System.out.println("Client connected from " + client.getInetAddress());
                new IoTClientHandler(client).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}