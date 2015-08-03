package eu.siacs.conversations.xmpp.jingle;

import eu.siacs.conversations.entities.DownloadableFile;

public interface OnTransmissionStatusChanged {
	public void onTransmitted(DownloadableFile file);

	public void onTransferAborted();
}
