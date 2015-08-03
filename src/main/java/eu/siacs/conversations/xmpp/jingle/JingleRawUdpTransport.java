package eu.siacs.conversations.xmpp.jingle;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import eu.siacs.conversations.Config;

public class JingleRawUdpTransport extends JingleTransport {
	private JingleCandidate candidate;
	private JingleConnection connection;
	private String destination;
	private boolean isEstablished = false;
	protected DatagramSocket datagramSocket;

	public JingleRawUdpTransport(final JingleConnection jingleConnection,
	                             final JingleCandidate candidate) {
		this.candidate = candidate;
		this.connection = jingleConnection;
	}

	@Override
	public void connect(final OnTransportConnected callback) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					datagramSocket = new DatagramSocket();
					final SocketAddress address = new InetSocketAddress(candidate.getHost(),candidate.getPort());
					datagramSocket.setSoTimeout(Config.SOCKET_TIMEOUT * 1000);
					datagramSocket.connect(address);
					isEstablished = true;
					callback.established();
				} catch (IOException e) {
					callback.failed();
				}
			}
		}).start();
	}

	@Override
	public void disconnect() {
		if (this.datagramSocket != null) {
			this.datagramSocket.close();
		}
	}

	public boolean isEstablished() {
		return this.isEstablished;
	}
}
