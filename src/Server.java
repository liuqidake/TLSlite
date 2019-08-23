import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server extends Node {
	private ServerSocket serverSocket;

	public Server(String privateKeyName, String signedCertificateName)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		super(privateKeyName, signedCertificateName);
		serverSocket = null;
	}

	public void run() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {
		serverSocket = new ServerSocket(port);

		System.out.println("Waiting for client connection...");

		while (true) {
			try {
				// waiting for client connection
				Socket socket = serverSocket.accept();

				// read from ObjectInputStream
				in = new ObjectInputStream(socket.getInputStream());
				// write to ObjectOutputStream
				out = new ObjectOutputStream(socket.getOutputStream());

				if (!this.handshakeFinished) {

					// send info to client to perform authentication
					if (!this.authenticateServer) {

						this.nonce = (byte[]) in.readObject();

						// put nonce in currentAllMessage
						this.currentAllMessages.write(nonce);

						// send info to client to perform authentication
						this.sendAuthenticationInfoAndGetAuthenticated();
						this.authenticateServer = true;

						in.close();
						out.close();
						Thread.sleep(1000);
						continue;
					}

					// receive info from client to authenticate client, compute shared secret key
					// and derive 6 session keys
					if (!this.clientAuthenticated) {
						boolean authenticated = this.authenticateClient();
						if (authenticated)
							this.clientAuthenticated = true;
						else
							break;
						this.computeSharedSecretKey();
						System.out.println("Client side: shared secret key has been computed");
						this.deriveSessionKeys();
						System.out.println("Client side: session keys has been computed");
						// Mac all handshake messages so far
						this.macedMessages = this.serverMacKey.doFinal(this.currentAllMessages.toByteArray());
						out.writeObject(this.macedMessages);

						in.close();
						out.close();
						this.handshakeFinished = true;
						Thread.sleep(1000);
						continue;
					}
				} else {
					this.messageExchange(socket);
					break;
				}
				socket.close();

			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		serverSocket.close();
	}

	public boolean authenticateClient() {

		// certificate DH public key and signed public key, stored them in current all
		// messages
		Certificate sentCert;
		try {
			sentCert = (Certificate) in.readObject();
			this.currentAllMessages.write(sentCert.getEncoded());
			this.receivedDHPublicKey = (BigInteger) in.readObject();
			this.currentAllMessages.write(this.receivedDHPublicKey.toByteArray());
			byte[] signedDHkey = (byte[]) in.readObject();
			this.currentAllMessages.write(signedDHkey);

			// authentication
			return Handshake.authenticate(sentCert, this.receivedDHPublicKey, signedDHkey);
		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;

	}

	public static void main(String[] args) {

		try {
			Server server = new Server("serverPrivateKey.der", "CASignedServerCertificate.pem");
			server.run();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Server send a file to client and client respond a message to ensure
	 * bidirectional communication is available
	 * 
	 * @param socket
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ClassNotFoundException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public void messageExchange(Socket socket) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, ClassNotFoundException,
			IllegalBlockSizeException, BadPaddingException, IOException, InterruptedException {
		// Read message from client to make sure that the handshake is completed
		String handshakeCompleted = MessageEncryption.readMessages(in, this.clientSKey, this.clientIV);
		if (!handshakeCompleted.equals("handshake completed")) {
			System.out.println("Message sent failed...");
			return;
		}
		else {
			System.out.println("handshake completed!!!");
		}
		//Server sent a large file to message
		MessageEncryption.sendFile("example.txt", out, this.serverMacKey, this.serverSKey, this.serverIV);
		Thread.sleep(1000);
		
		//Server receives response message from client
		socket = serverSocket.accept();
		in = new ObjectInputStream(socket.getInputStream());
		String fileReceived = MessageEncryption.readMessages(in, this.clientSKey, this.clientIV);
		if (!fileReceived.equals("File received"))
			return;
		System.out.println("bidirection communication verified");
		in.close();
		out.close();
	}

}
