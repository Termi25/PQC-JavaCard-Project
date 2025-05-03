package pqc.javacard.implementation;

import javacard.framework.*;
import javacard.security.MessageDigest;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;

import java.security.*;
import java.security.KeyPair;
import java.security.Signature;


public class PQC_Applet extends Applet {
    protected static MessageDigest sha3;
    protected static KeyPairGenerator kpg;
    protected static KeyPair kp;
    protected static Signature sig;

    private static final int BYTE_LENGTH = 32;

    public static final byte INS_SET_SIGN = 0x00;

    public static final byte INS_P_START = 0x10;
    public static final byte INS_P_END = 0x20;

    public static final byte INS_P_HASH_ONLY = 0x10;

    private PQC_Applet() {
        net.thiim.dilithium.provider.DilithiumProvider provider = new net.thiim.dilithium.provider.DilithiumProvider();
        Security.addProvider(provider);

        SecureRandom sr = new SecureRandom();
        try {
            kpg =KeyPairGenerator.getInstance("Dilithium");
            kpg.initialize(DilithiumParameterSpec.LEVEL2,sr);
            kp = kpg.generateKeyPair();
            sig = Signature.getInstance("Dilithium");
            sig.initSign(kp.getPrivate());
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        sha3= MessageDigest.getInstance(MessageDigest.ALG_SHA3_256, false);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte BLength) {
        new PQC_Applet();
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] == INS_SET_SIGN) {
            createSHA3(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }


    public static void createSHA3(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_P_START:
                sha3.update(buffer, ISO7816.OFFSET_CDATA, len);
                break;
            case INS_P_END:
                sha3.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0x00);

                if(buffer[ISO7816.OFFSET_P1]!=INS_P_HASH_ONLY){
                    byte[] hashData=new byte[BYTE_LENGTH];
                    System.arraycopy(buffer,ISO7816.OFFSET_CDATA,hashData,0,BYTE_LENGTH);
                    try {
                        sig.update(hashData);
                        byte[] signature = sig.sign();
                        System.arraycopy(signature,0,buffer,ISO7816.OFFSET_CDATA,BYTE_LENGTH);
                    } catch (SignatureException e) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                }
                apdu.setOutgoingAndSend((short) 0, (short) BYTE_LENGTH);
                sha3.reset();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
