package pqc.javacard.implementation;

import javacard.framework.*;
import javacard.security.MessageDigest;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;

import java.security.*;
import java.security.KeyPair;
import java.security.Signature;

/**
 * Crystals-Dilithium SHA3-256 Signing applet that supports chunked signing or only SHA3-256 hashing.
 *
 * CLA | Meaning
 * -----+-----------------------------
 * 0x00 | SIGN (Crystals-Dilithium Signing with SHA3-256 or SHA3-256 only; see P1 Meaning)
 *
 * INS | Meaning
 * -----+-----------------------------
 * 0x10 | P_START (SHA3 Updating)
 * 0x20 | INS_P_END (SHA3 Final & Crystals-Dilithium Signing)
 *
 * P1 | Meaning when used with INS_P_END
 * ------+------------------------------------------
 * 0x00 | Crystals-Dilithium Signing with SHA3-256
 * 0x10 | only SHA3-256
 */
public class PQC_Applet extends Applet {

    /*-----Command Constants-----*/
    public static final byte INS_SET_SIGN = 0x00;

    public static final byte INS_P_START = 0x10;
    public static final byte INS_P_END = 0x20;

    public static final byte INS_P_HASH_ONLY = 0x10;

    /*-----Fields kept in EEPROM-----*/
    protected static MessageDigest sha3;
    protected static KeyPairGenerator kpg;
    protected static KeyPair kp;
    protected static Signature sig;

    /*-----Algorithm Constants-----*/
    private static final int BYTE_LENGTH = 32;

    /** This is the Class Constructor used for initialising Fields kept in EEPROM.*/
    private PQC_Applet() {
        net.thiim.dilithium.provider.DilithiumProvider provider = new net.thiim.dilithium.provider.DilithiumProvider();
        Security.addProvider(provider);

        try {
            /* generate a new keypair for applet */
            SecureRandom sr = new SecureRandom();
            kpg = KeyPairGenerator.getInstance("Dilithium");
            kpg.initialize(DilithiumParameterSpec.LEVEL2,sr);
            kp = kpg.generateKeyPair();

            /* create a new Signature object for Crystals-Dilithium signing */
            sig = Signature.getInstance("Dilithium");
            sig.initSign(kp.getPrivate());
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        /* create a new MessageDigest to use to calculate the SHA3-256 value */
        sha3= MessageDigest.getInstance(MessageDigest.ALG_SHA3_256, false);
        register();
    }

    /** This is the method used when first installing the Applet on the Java Card. */
    public static void install(byte[] bArray, short bOffset, byte BLength) {
        new PQC_Applet();
    }


    @Override
    public void process(APDU apdu) throws ISOException {

        byte[] buffer = apdu.getBuffer();

        /* check if CLA is the one for signing; throws error if not*/
        /** This is an extra validation for future modification if need be.*/
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

            /* Feeding the first N-1 Blocks of Data to the SHA3-256 MessageDigest Object*/
            case INS_P_START:
                sha3.update(buffer, ISO7816.OFFSET_CDATA, len);
                break;

            /* Feeding the first N-1 Blocks of Data to the SHA3-256 MessageDigest Object*/
            case INS_P_END:
                sha3.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0x00);

                /* Checking if the P1 value isn't the HASH_ONLY option */
                if(buffer[ISO7816.OFFSET_P1]!=INS_P_HASH_ONLY){

                    byte[] hashData=new byte[BYTE_LENGTH];
                    System.arraycopy(buffer,ISO7816.OFFSET_CDATA,hashData,0,BYTE_LENGTH);

                    try {

                        /* Signing the SHA3-256 value of the inputted data with PQC Crystals-Dilithium Algorithm*/
                        sig.update(hashData);
                        byte[] signature = sig.sign();
                        System.arraycopy(signature,0,buffer,ISO7816.OFFSET_CDATA,BYTE_LENGTH);

                    } catch (SignatureException e) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                }

                /* Sending the final data output (be it only the SHA3 value or the PQC Signature */
                apdu.setOutgoingAndSend((short) 0, (short) BYTE_LENGTH);

                /* Resetting the SHA3-256 MessageDigest Object for future use. */
                sha3.reset();
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
