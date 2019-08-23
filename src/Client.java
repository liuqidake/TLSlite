import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Client extends Node {
	private Socket socket;

	public Client(String privateKeyName, String signedCertificateName)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		super(privateKeyName, signedCertificateName);
		socket = null;
	}

	public void run() throws IOException, InterruptedException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
		InetAddress host = InetAddress.getLocalHost();

		while (true) {
			try {
				socket = new Socket(host.getHostName(), port);
				out = new ObjectOutputStream(socket.getOutputStream());
				if (!this.handshakeFinished) {
					// Client sends nonce and receive the data to authenticate server
					if (!this.authenticateServer) {
						boolean authenticated = authenticateServer();
						if (!authenticated)
							break;
						Thread.sleep(1000);
						continue;
					}

					// Client sends verification info to server. Compute shared secret key and
					// derive 6 session keys
					if (!this.clientAuthenticated) {
						this.sendAuthenticationInfoAndGetAuthenticated();
						this.clientAuthenticated = true;
						// Compute the shared secret key
						this.computeSharedSecretKey();
						// Derive 6 session keys
						this.deriveSessionKeys();
						// Read hash value from server
						in = new ObjectInputStream(socket.getInputStream());
						this.currentAllMessages.write(in.readAllBytes());
						// mac all messages
						this.macedMessages = this.clientMacKey.doFinal(this.currentAllMessages.toByteArray());
						System.out.println("handshake completed");
						this.handshakeFinished = true;
						in.close();
						out.close();
						Thread.sleep(1000);
						continue;
					}
				} else {
					this.messageExchange(host);
					break;
					
				}
				socket.close();

			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

	public void sendNonce() throws IOException {
		SecureRandom rand = new SecureRandom();
		rand.nextBytes(this.nonce);
		// Add nonce to current all messages
		this.currentAllMessages.write(nonce);
		out.writeObject(nonce);
	}

	public boolean authenticateServer() {
		try {
			sendNonce();
			System.out.println("Client sent the nonce...");

			in = new ObjectInputStream(socket.getInputStream());
			// Read ObjectInputStream
			Certificate sentCert = (Certificate) in.readObject();
			this.currentAllMessages.write(sentCert.getEncoded());

			this.receivedDHPublicKey = (BigInteger) in.readObject();
			this.currentAllMessages.write(this.receivedDHPublicKey.toByteArray());

			byte[] signedDHkey = (byte[]) in.readObject();
			this.currentAllMessages.write(signedDHkey);

			boolean serverAuthenticated = Handshake.authenticate(sentCert, this.receivedDHPublicKey, signedDHkey);

			if (serverAuthenticated) {
				System.out.println("Server is authenticated...");
				this.authenticateServer = true;
				in.close();
				out.close();
				return true;
			} else {
				System.out.println("Server authentication failed");
				in.close();
				out.close();
				return false;
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;

	}

	public static void main(String[] args) {

		try {
			Client client = new Client("clientPrivateKey.der", "CASignedClientCertificate.pem");
			client.run();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void messageExchange(InetAddress host) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			IOException, ClassNotFoundException, InterruptedException {
		//send message to server to tell server that the handshake is completed
		MessageEncryption.sendMessage("handshake completed".getBytes(), out, this.clientMacKey,
				this.clientSKey, this.clientIV);
		//received the file sent from server
		in = new ObjectInputStream(socket.getInputStream());
		byte[] cipher = (byte[])in.readObject();
		if (cipher.length == 0) {
			System.out.println("File receiving failed..");
			return;
		}
		Thread.sleep(1000);
		
		//send message to server to say that the file has been received 
		socket = new Socket(host.getHostName(), port);
		out = new ObjectOutputStream(socket.getOutputStream());
		MessageEncryption.sendMessage("File received".getBytes(), out, this.clientMacKey, this.clientSKey,
				this.clientIV);
		in.close();
		out.close();
	}
	

}