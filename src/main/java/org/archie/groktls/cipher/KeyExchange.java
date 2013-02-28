package org.archie.groktls.cipher;

public interface KeyExchange {

	String getName();
	
	boolean isExport();
	
	String getExportVariant();
	
	String getKeyAgreementAlgo();
	
	String getAuthenticationAlgo();

}
