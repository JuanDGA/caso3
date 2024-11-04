package com.uniandes.edu;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class Server {
  private final Map<Integer, Status> statusById = new HashMap<>();
  private static final String privateKeyPath = "privateData/key";
  private static final String publicKeyPath = "data/key.pub";

  private PrivateKey privateKey;
  private PublicKey publicKey;

  public void loadUsersTable() throws FileNotFoundException {
    Scanner statusScanner = new Scanner(new File("privateData/statusIndices.txt"));
    while (statusScanner.hasNextLine()) {
      String line = statusScanner.nextLine();
      String[] split = line.split(":");
      int id = Integer.parseInt(split[0]);
      statusById.put(id, Status.valueOf(split[1]));
    }
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

  public void openSocket(int port) throws IOException {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      while (true) {
        Socket socket = serverSocket.accept();
        System.out.println();
        new ConnectionHandler(socket).start();
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
        System.out.println("Escuchando clientes en puerto 8000...");
        server.openSocket(8000);
        break;
      default:
        System.out.println("Opcion no valida");
    }
  }
}
