package com.uniandes.edu;

import java.io.*;
import java.net.Socket;

public class ConnectionHandler extends Thread {
  private final Socket socket;

  public ConnectionHandler(Socket socket) {
    this.socket = socket;
  }

  @Override
  public void run() {
    try (
      BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      PrintWriter output =  new PrintWriter(socket.getOutputStream(), true)
    ) {
      boolean waitForInit = true;
      String chunk;
      StringBuilder message = new StringBuilder();
      while ((chunk = input.readLine()) != null) {
        if (!chunk.equals("SECINIT") && waitForInit) continue;
        if (chunk.equals("SECINIT")) {
          waitForInit = false;
          continue;
        }
        // We should receive R here
        message.append(chunk);
        output.println(message);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    } finally {
      try {
        socket.close();
      } catch (IOException e) {
        e.printStackTrace(System.err);
      }
    }
  }
}
