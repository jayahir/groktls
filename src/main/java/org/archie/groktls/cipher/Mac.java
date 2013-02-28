package org.archie.groktls.cipher;

public interface Mac {

	String getName();

    String getAlgorithm();
    
    int getSize();

}
