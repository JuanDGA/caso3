package com.uniandes.edu;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Server {
  private final Map<Integer, Status> statusById;

  public Server() throws FileNotFoundException {
    Scanner statusScanner = new Scanner(new File("data/statusIndices.txt"));
    statusById = new HashMap<>();
    while (statusScanner.hasNextLine()) {
      String line = statusScanner.nextLine();
      String[] split = line.split(":");
      int id = Integer.parseInt(split[0]);
      statusById.put(id, Status.valueOf(split[1]));
    }
  }

  public void openSocket(int port) throws IOException {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      while (true) {
        Socket socket = serverSocket.accept();
        System.out.println();
        new ConnectionHandler(socket).start();
      }
    }
  }

  public static void main(String[] args) throws IOException {
    Server server = new Server();
    server.openSocket(8000);
  }
}
