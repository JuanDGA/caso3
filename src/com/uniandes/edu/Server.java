package com.uniandes.edu;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
  private static final Map<Integer, Status> statusById = new HashMap<>();
  private static final Map<String, Package> packageById = new HashMap<>();

  private static final String privateKeyPath = "privateData/key";
  private static final String publicKeyPath = "data/key.pub";

  private PrivateKey privateKey;
  private PublicKey publicKey;

  public static Package findPackage(String userId, String packageId) {
    Package p = packageById.get(packageId);
    if (p == null || !p.getUserId().equals(userId)) return null;
    return p;
  }

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    Scanner input = new Scanner(System.in);
    System.out.println("Seleccione la operación a realizar:");
    System.out.println("1. Generar claves asimétricas");
    System.out.println("2. Escuchar clientes");

    int selectedOption = input.nextInt();

    Server server = new Server();

    switch (selectedOption) {
      case 1:
        System.out.println("Generando claves asimétricas...");
        server.generateKeyPair();
        break;
      case 2:
        System.out.println("Cargando llaves...");
        server.loadUsersTable();
        server.loadKeys();
        System.out.println("Llaves cargadas exitosamente");
        System.out.print("Desea correr el serivdor en modo iterativo? (y/n)\n> ");
        String r = input.next().toLowerCase();

        if (r.equals("y")) {
          System.out.println("Escuchando clientes en puerto 8000...\n");
          server.openSocket(8000);
        } else {
          System.out.print("Ingrese la cantidad máxima de delegados\n> ");
          int max = input.nextInt();
          System.out.println("Escuchando clientes en puerto 8000...\n");
          server.openSocket(8000, max);
        }
        break;
      default:
        System.out.println("Opcion no valida");
    }
  }

  public void loadUsersTable() throws FileNotFoundException {
    Scanner statusScanner = new Scanner(new File("privateData/statusIndices.txt"));
    while (statusScanner.hasNextLine()) {
      String line = statusScanner.nextLine();
      String[] split = line.split(":");
      int id = Integer.parseInt(split[0]);
      statusById.put(id, Status.valueOf(split[1]));
    }
    statusScanner.close();

    Scanner packageScanner = new Scanner(new File("privateData/packages.txt"));

    while (packageScanner.hasNextLine()) {
      String line = packageScanner.nextLine();
      String[] parts = line.split(";");
      packageById.put(parts[1], new Package(parts[0], statusById.get(Integer.parseInt(parts[2]))));
    }

    packageScanner.close();
  }

  public void loadKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    this.privateKey = keyFactory.generatePrivate(privateKeySpec);

    byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    this.publicKey = keyFactory.generatePublic(publicKeySpec);
  }

  // Iterative
  public void openSocket(int port) throws IOException {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      while (true) {
        Socket socket = serverSocket.accept();
        new ConnectionHandler(socket, privateKey).run();
      }
    }
  }

  // Concurrent
  public void openSocket(int port, int maxDelegates) throws IOException {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      ExecutorService executor = Executors.newFixedThreadPool(maxDelegates);
      while (true) {
        Socket socket = serverSocket.accept();
        executor.submit(new ConnectionHandler(socket, privateKey));
      }
    }
  }

  public void generateKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024);
    KeyPair keyPair = generator.generateKeyPair();
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    try (FileOutputStream outputStream = new FileOutputStream(Server.publicKeyPath)) {
      outputStream.write(publicKey.getEncoded());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    try (FileOutputStream outputStream = new FileOutputStream(Server.privateKeyPath)) {
      outputStream.write(privateKey.getEncoded());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
