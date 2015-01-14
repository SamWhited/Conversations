package eu.siacs.conversations.utils;

import android.os.Bundle;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import de.measite.minidns.Client;
import de.measite.minidns.DNSMessage;
import de.measite.minidns.Record;
import de.measite.minidns.Record.CLASS;
import de.measite.minidns.Record.TYPE;
import de.measite.minidns.record.A;
import de.measite.minidns.record.AAAA;
import de.measite.minidns.record.Data;
import de.measite.minidns.record.SRV;
import de.measite.minidns.util.NameUtil;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.xmpp.jid.Jid;

public final class DNSHelper {
	@SuppressWarnings("StaticVariableOfConcreteClass")
	private static final Client client = new Client();

	public static Bundle getSRVRecord(final Jid jid, final boolean isUsingTor) throws IOException {
		final String host = jid.getDomainpart();

        if (isUsingTor || host.endsWith(".onion")) {
            // we should _never_ disclose the usage of a .onion address
            return queryDNS(host, InetAddress.getLocalHost(), 5400);
        } else {
			final String[] dns = client.findDNS();

			if (dns != null) {
				for (final String dnsserver : dns) {
					final InetAddress ip = InetAddress.getByName(dnsserver);
					final Bundle b = queryDNS(host, ip);
					if (b.containsKey("values")) {
						return b;
					} else if (b.containsKey("error")
							&& "nosrv".equals(b.getString("error", null))) {
						return b;
							}
				}
			}
			return queryDNS(host, InetAddress.getByName("8.8.8.8"));
		}
	}

    private static Bundle queryDNS(final String host, final InetAddress dnsServer) {
        return queryDNS(host, dnsServer, 53);
    }

	private static Bundle queryDNS(final String host, final InetAddress dnsServer, final int port) {
		final Bundle bundle = new Bundle();
		try {
			final String qname = "_xmpp-client._tcp." + host;
			Log.d(Config.LOGTAG,
					"using dns server: " + dnsServer.getHostAddress()
					+ " to look up " + host);
			final DNSMessage message = client.query(qname, TYPE.SRV, CLASS.IN,
					dnsServer.getHostAddress(), port);

			// How should we handle priorities and weight?
			// Wikipedia has a nice article about priorities vs. weights:
			// https://en.wikipedia.org/wiki/SRV_record#Provisioning_for_high_service_availability

			// we bucket the SRV records based on priority, pick per priority
			// a random order respecting the weight, and dump that priority by
			// priority

			final Map<Integer, ArrayList<SRV>> priorities = new TreeMap<>();
			final Map<String, ArrayList<String>> ips4 = new TreeMap<>();
			final Map<String, ArrayList<String>> ips6 = new TreeMap<>();

			for (final Record[] rrset : new Record[][] { message.getAnswers(),
				message.getAdditionalResourceRecords() }) {
				for (final Record rr : rrset) {
					final Data d = rr.getPayload();
					if (d instanceof SRV
							&& NameUtil.idnEquals(qname, rr.getName())) {
						final SRV srv = (SRV) d;
						if (!priorities.containsKey(srv.getPriority())) {
							priorities.put(srv.getPriority(),
									new ArrayList<SRV>(2));
						}
						priorities.get(srv.getPriority()).add(srv);
							}
					if (d instanceof A) {
						final A arecord = (A) d;
						if (!ips4.containsKey(rr.getName())) {
							ips4.put(rr.getName(), new ArrayList<String>(3));
						}
						ips4.get(rr.getName()).add(arecord.toString());
					}
					if (d instanceof AAAA) {
						final AAAA aaaa = (AAAA) d;
						if (!ips6.containsKey(rr.getName())) {
							ips6.put(rr.getName(), new ArrayList<String>(3));
						}
						ips6.get(rr.getName()).add("[" + aaaa.toString() + "]");
					}
				}
			}

			final Random rnd = new Random();
			final ArrayList<SRV> result = new ArrayList<>(
					priorities.size() * 2 + 1);
			for (final ArrayList<SRV> s : priorities.values()) {

				// trivial case
				if (s.size() <= 1) {
					result.addAll(s);
					continue;
				}

				long totalweight = 0l;
				for (final SRV srv : s) {
					totalweight += srv.getWeight();
				}

				while (totalweight > 0l && s.size() > 0) {
					long p = (rnd.nextLong() & 0x7fffffffffffffffl)
						% totalweight;
					int i = 0;
					while (p > 0) {
						p -= s.get(i++).getPriority();
					}
					i--;
					// remove is expensive, but we have only a few entries
					// anyway
					final SRV srv = s.remove(i);
					totalweight -= srv.getWeight();
					result.add(srv);
				}

				Collections.shuffle(s, rnd);
				result.addAll(s);

			}

			if (result.size() == 0) {
				bundle.putString("error", "nosrv");
				return bundle;
			}
			final ArrayList<Bundle> values = new ArrayList<>();
			for (final SRV srv : result) {
				boolean added = false;
				if (ips6.containsKey(srv.getName())) {
					values.add(createNamePortBundle(srv.getName(),srv.getPort(),ips6));
					added = true;
				}
				if (ips4.containsKey(srv.getName())) {
					values.add(createNamePortBundle(srv.getName(),srv.getPort(),ips4));
					added = true;
				}
				if (!added) {
					values.add(createNamePortBundle(srv.getName(),srv.getPort(),null));
				}
			}
			bundle.putParcelableArrayList("values", values);
		} catch (final SocketTimeoutException e) {
			bundle.putString("error", "timeout");
		} catch (final Exception e) {
			bundle.putString("error", "unhandled");
		}
		return bundle;
	}

	private static Bundle createNamePortBundle(final String name,
			final int port,
			final Map<String, ArrayList<String>> ips) {
		final Bundle namePort = new Bundle();
		namePort.putString("name", name);
		namePort.putInt("port", port);
		if (ips!=null) {
			final ArrayList<String> ip = ips.get(name);
			Collections.shuffle(ip, new Random());
			namePort.putString("ip", ip.get(0));
		}
		return namePort;
	}

}
