package org.archie.groktls.cipher;

import org.archie.groktls.NamedItem;

public interface CipherSuite extends NamedItem {

    public boolean isSignalling();

	public KeyExchange getKeyExchange();

	public Cipher getCipher();

	public Mac getMac();

    @Override
    public boolean equals(Object obj);

    @Override
    public int hashCode();

}
