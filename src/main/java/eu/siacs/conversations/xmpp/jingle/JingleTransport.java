package eu.siacs.conversations.xmpp.jingle;

import eu.siacs.conversations.entities.DownloadableFile;
import eu.siacs.conversations.entities.Streamable;

public abstract class JingleTransport {
	public abstract void connect(final OnTransportConnected callback);

	public void receive(final DownloadableFile file,
			final OnTransmissionStatusChanged callback) {
		throw new UnsupportedOperationException();
	}

	public void send(final DownloadableFile file,
			final OnTransmissionStatusChanged callback) {
		throw new UnsupportedOperationException();
	}

	public abstract void disconnect();
}
