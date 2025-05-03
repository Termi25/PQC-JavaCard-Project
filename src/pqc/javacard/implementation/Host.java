package pqc.javacard.implementation;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;

/** An example host for testing the PQC_Applet using jCardSim. */
public class Host {
    /*-----APDU Contract Mode Modifiers (see PQC_Applet)*/
    private static final byte SIGN = 0x00;
    private static final byte HASH_ONLY = 0x10;

    private static final int BYTE_LENGTH = 32;

    public static void main(String[] args) throws IOException {

        /*-----Card Simulator Creation-----*/

        CardSimulator simulator = new CardSimulator();

        /*-----Card Applet Creation, Registration & Selection for use-----*/

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, PQC_Applet.class);

        simulator.selectApplet(appletAID);

        /*-----Initialising Test Folder Root-----*/

        File folder = new File("testFiles");
        if(!folder.isDirectory()){
            System.out.println("Test folder doesn't exists. Add a test folder in project root named: testFiles");
            return;
        }

        /*-----Running Applet for each of the test files-----*/
        /** For each test file it will create:
         *  1) Crystals-Dilithium PQC Signature file (*.enc);
         *  2) SHA3-256 file (*.sha3). */

        for (File file : folder.listFiles()) {
            if (file.isDirectory()) {
                continue;
            }
            if (file.getName().endsWith(".enc") || file.getName().endsWith(".sha3")) {
                continue;
            }

            /*-----Creating file signature using the provided Applet-----*/

            File encFile = new File(folder, file.getName().split("\\.")[0] + ".enc");
            signFile(simulator, file, encFile, false);

            /*-----Creating file SHA3-256 bit hash value using the provided Applet-----*/

            encFile = new File(folder, file.getName().split("\\.")[0] + ".sha3");
            signFile(simulator, file, encFile, true);
        }
    }

    public static void signFile(CardSimulator simulator, File inputFile, File outputFile, boolean isOnlySHA3) throws IOException {
        if (inputFile.exists()) {

            /*-----Checking Applet Mode-----*/

            byte appletMode = SIGN;
            if(isOnlySHA3){
                appletMode = HASH_ONLY;
            }

            /*-----Creating Input Stream-----*/

            FileInputStream fis = new FileInputStream(inputFile);
            BufferedInputStream bis = new BufferedInputStream(fis);

            /*-----Creating Output Stream-----*/

            FileOutputStream fos = new FileOutputStream(outputFile);
            BufferedOutputStream bos = new BufferedOutputStream(fos);

            /*-----Creating Input Stream Buffer-----*/
            /** The Offset variable is used to address blocks of bytes from the buffer to be sent to the Java Card. */

            byte[] buffer = fis.readAllBytes();
            int offset = 0;
            while (offset < buffer.length) {

                int remainingBytes = buffer.length - offset;
                boolean lastBlock = (remainingBytes <= BYTE_LENGTH);


                /*-----Send blocks of bytes to the Java Card for SHA3 processing-----*/
                /** When reaching the last block of bytes, we need to announce the Java Card
                 *  so that it may perform the final operations (finishing the SHA3-256
                 *  Algorithm and possibly Crystals-Dilithium PQC Signing Scheme).*/
                if(lastBlock){

                    byte[] dataBlock = new byte[remainingBytes];
                    System.arraycopy(buffer, 0, dataBlock, 0, remainingBytes);

                    ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0x00,0x20,appletMode,0x00,dataBlock));
                    bos.write(response.getData());

                    if (response.getSW() != 0x9000) {
                        throw new RuntimeException(String.format(
                                "APDU error at offset %d (SW=%04X)", offset, response.getSW()));
                    }

                }else{

                    ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0x00,0x10,0x00,0x00,buffer));

                    if (response.getSW() != 0x9000) {
                        throw new RuntimeException(String.format(
                                "APDU error at offset %d (SW=%04X)", offset, response.getSW()));
                    }
                }
                offset += BYTE_LENGTH;
            }

            fis.close();
            bos.close();
        }
    }
}
