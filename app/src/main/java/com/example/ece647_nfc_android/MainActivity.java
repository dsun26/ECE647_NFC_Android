package com.example.ece647_nfc_android;
/**
 *  Derek Sun
 *  ECE 647 - Security Engineering
 */
import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.os.Build;
import android.os.Bundle;
import android.app.Activity;
import android.os.Parcelable;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import android.content.IntentFilter.MalformedMimeTypeException;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class MainActivity extends Activity implements NfcAdapter.OnNdefPushCompleteCallback, NfcAdapter.CreateNdefMessageCallback{
    /**
     *  Global variables
     */
    //text that displays read messages
    private TextView readText;
    //textbox for entering messages to send
    private EditText writeText;
    //text that displays read or write mode
    private TextView modeLabel;
    //textbox for entering secret key (to be used for encryption later)
    private EditText secretKeyText;
    //array for messages to send and messages received
    private ArrayList<String> messagesToSendArray;
    private ArrayList<String> messagesReceivedArray;
    //button to switch between read/write mode
    private Button switchButton;
    //    private Button writeButton;
    //boolean indicating read or write mode
    private boolean readMode;
    private boolean hasKey;
    //NfcAdapter for connecting to NFC devices
    private NfcAdapter nfcAdapter;
    // Intent listener that grabs nfc events
    private PendingIntent pendingIntent;

    /**
     *  On create, initialize everything.
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //TextView that outputs received messages to screen
        readText = findViewById(R.id.readMessageText);
        //EditText that takes secret key input for encryption
        secretKeyText = findViewById(R.id.secretKeyText);
        //EditText that takes input
        writeText = findViewById(R.id.writeMessageText);

        messagesToSendArray = new ArrayList<>();
        messagesReceivedArray = new ArrayList<>();
        //TextView that displays read/write mode
        modeLabel = findViewById(R.id.modeLabel);
        //initial mode is read
        readMode = true;
        //initial no key
        hasKey = false;
        //button that switches between read and write modes
        switchButton = findViewById(R.id.switchButton);
//        writeButton = findViewById(R.id.writeButton);
        //initialize NfcAdapter
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        //check if device supports NFC functionality
        if(nfcAdapter == null){
            Toast.makeText(this, "This device doesn't support NFC.", Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        //check if device has NFC enabled
        if(!nfcAdapter.isEnabled()){
            Toast.makeText(this, "NFC is disabled.", Toast.LENGTH_LONG).show();
            finish();
        }
        //This will refer back to createNdefMessage for what it will send
        nfcAdapter.setNdefPushMessageCallback(this, this);

        //This will be called if the message is sent successfully
        nfcAdapter.setOnNdefPushCompleteCallback(this, this);

        handleIntent(getIntent());
    }

    /**
     *  On resume, get priority in receiving NFC events over all other activities.
     */
    @Override
    protected void onResume() {
        super.onResume();
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
    }

    /**
     *  On pause, relinquish priority in receiving NFC events over all other activities.
     */
    @Override
    protected void onPause() {
        super.onPause();
        nfcAdapter.disableForegroundDispatch(this);
    }

    /**
     *  Called when new intent is detected
     */
    @Override
    protected void onNewIntent(Intent intent) {
//        super.onNewIntent(intent);
        handleIntent(intent);
    }

    /**
     *  Sends string on writeText line to other NFC device (if in writeMode)
     */
    private void handleIntent(Intent intent) {
        if(readMode){
            readMessage(intent);
        }
        else{
            Toast.makeText(this, "Currently in write mode and won't receive incoming messages.", Toast.LENGTH_LONG).show();
        }
    }

    /**
     *  Called when the NdefMessage was successfully sent
     *  Clear the messagesToSendArray so no previous messages are sent next time.
     */
    @Override
    public void onNdefPushComplete(NfcEvent event) {
        messagesToSendArray.clear();
        writeText.setText("");
    }

    /**
     *  Called when another NFC capable device is detected.
     *  If in write mode, send message.
     *  If in read mode, do nothing and just wait.
     */
    @Override
    public NdefMessage createNdefMessage(NfcEvent event) {
        //if in write mode, and the input is not empty string
        if(!readMode && !writeText.getText().toString().matches("")) {
            messagesToSendArray.add(writeText.getText().toString());
            NdefRecord[] recordsToAttach = createRecords();
            //provide NdefRecord[] to create an NdefMessage
            return new NdefMessage(recordsToAttach);
        }
        return null;
    }

    /**
     *  Create NDEF Record containing the messages in messagesToSendArray
     */
    public NdefRecord[] createRecords() {
        NdefRecord[] records = new NdefRecord[messagesToSendArray.size() + 1];
        if(!secretKeyText.getText().toString().matches("")){
            hasKey = true;
        }
        else{
            hasKey = false;
        }
        byte[] payload;
        //create messages manually if API is not high enough
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN) {
            for (int i = 0; i < messagesToSendArray.size(); i++){
                if(hasKey){
                    try{
                        payload = encryptMessage(secretKeyText.getText().toString(), messagesToSendArray.get(i));
                    }
                    catch (Exception e){
                        Toast.makeText(this, "Message cannot be encrypted.", Toast.LENGTH_LONG).show();
                        return records;
                    }
                }
                else{
                    payload = messagesToSendArray.get(i).getBytes(Charset.forName("UTF-8"));
                }
                NdefRecord record = new NdefRecord(
                        NdefRecord.TNF_WELL_KNOWN,      //Our 3-bit Type name format
                        NdefRecord.RTD_TEXT,            //Description of our payload
                        new byte[0],                    //The optional id for our Record
                        payload);                       //Our payload for the Record
                records[i] = record;
            }
        }
        //API high enough, so we can use createMime
        else {
            for (int i = 0; i < messagesToSendArray.size(); i++){
                if(hasKey){
                    try{
                        payload = encryptMessage(secretKeyText.getText().toString(), messagesToSendArray.get(i));
                    }
                    catch (Exception e){
                        Toast.makeText(this, "Message cannot be encrypted.", Toast.LENGTH_LONG).show();
                        return records;
                    }
                }
                else{
                    payload = messagesToSendArray.get(i).getBytes(Charset.forName("UTF-8"));
                }
                NdefRecord record = NdefRecord.createMime("text/plain", payload);
                records[i] = record;
            }
        }
        records[messagesToSendArray.size()] = NdefRecord.createApplicationRecord(getPackageName());
        return records;
    }

    /**
     *  Reads NDEF message from other device and displays the message in readText (if in read mode).
     */
    public void readMessage(Intent intent) {
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(intent.getAction())) {
            Parcelable[] receivedArray = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);

            if(receivedArray != null) {
                messagesReceivedArray.clear();
                NdefMessage receivedMessage = (NdefMessage) receivedArray[0];
                NdefRecord[] attachedRecords = receivedMessage.getRecords();
                if(!secretKeyText.getText().toString().matches("")){
                    hasKey = true;
                }
                else{
                    hasKey = false;
                }
                readText.setText("Messages Received:\n");
                for (NdefRecord record:attachedRecords) {
                    String msg = new String(record.getPayload());
                    if (msg.equals(getPackageName())){
                        continue;
                    }
                    if(hasKey){
                        try{
                            msg = new String(decryptMessage(secretKeyText.getText().toString(), record.getPayload()));
                        }
                        catch (Exception e){
                            Toast.makeText(this, "Message cannot be decrypted. Incorrect key or corrupted message.", Toast.LENGTH_LONG).show();
                            return;
                        }
                    }
                    messagesReceivedArray.add(msg);
                }
                Toast.makeText(this, "Received " + messagesReceivedArray.size() + " Messages", Toast.LENGTH_LONG).show();
                //readText.setText("Messages Received:\n");
                if (messagesReceivedArray.size() > 0) {
                    for (int i = 0; i < messagesReceivedArray.size(); i++) {
                        readText.append(messagesReceivedArray.get(i));
                        readText.append("\n");
                    }
                }
            }
            else {
                Toast.makeText(this, "Received Blank Parcel", Toast.LENGTH_LONG).show();
            }
        }
    }

    /**
     *  Called when the mode switch button is pressed.
     *  Changes the functionality and UI to read mode or write mode.
     */
    public void switchMode(View view){
        readMode = !readMode;
        if(readMode){
            toRead(view);
        }
        else{
            toWrite(view);
        }
    }

    /**
     *  Call to change UI to read mode.
     */
    public void toRead(View view){
        modeLabel.setText("Mode: Read");
        switchButton.setText("Write Mode");
        readText.setVisibility(View.VISIBLE);
//        writeButton.setVisibility(View.GONE);
        writeText.setVisibility(View.GONE);
    }

    /**
     *  Call to change UI to write mode.
     */
    public void toWrite(View view){
        modeLabel.setText("Mode: Write");
        switchButton.setText("Read Mode");
        readText.setVisibility(View.GONE);
//        writeButton.setVisibility(View.VISIBLE);
        writeText.setVisibility(View.VISIBLE);
    }
    /**
     *  Encryption/decryption methods
     */
//    private static Key generateKey(String secretKeyString) throws Exception {
//        // generate secret key from string
//        Key key = new SecretKeySpec(secretKeyString.getBytes(), "AES");
//        return key;
//    }
//    public static byte[] encryptMessage(String secretKeyString, String msgContentString) {
//        try {
//            // generate AES secret key from user input
//            Key key = generateKey(secretKeyString);
//
//            // specify the cipher algorithm using AES
//            Cipher c = Cipher.getInstance("AES");
//
//            // specify encryption mode
//            c.init(Cipher.ENCRYPT_MODE, key);
//
//            // encrypt
//            byte[] returnArray = c.doFinal(msgContentString.getBytes());
//
//            return returnArray;
//        } catch (Exception e) {
//            e.printStackTrace();
//            return null;
//        }
//    }
//
//    public static byte[] decryptMessage(String secretKeyString, byte[] encryptedMsg) throws  Exception {
//        // generate AES secret key from the user input string
//        Key key = generateKey(secretKeyString);
//        // get the cipher algorithm for AES
//        Cipher c = Cipher.getInstance("AES");
//        // specify the decryption mode
//        c.init(Cipher.DECRYPT_MODE, key);
//        // decrypt the message
//        byte[] decryptValue = c.doFinal(encryptedMsg);
//
//        return decryptValue;
//    }

    public static byte[] encryptMessage(String secretKeyString, String msgContentString) throws Exception {
        byte[] bytesOfMessage = secretKeyString.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(bytesOfMessage);
        SecretKeySpec keySpec = new SecretKeySpec(digest, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        return cipher.doFinal(msgContentString.getBytes()); //return ciphertext bytes
    }

    public static byte[] decryptMessage(String secretKeyString, byte[] encryptedMsg) throws  Exception {
        byte[] bytesOfMessage = secretKeyString.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(bytesOfMessage);
        SecretKeySpec keySpec = new SecretKeySpec(digest, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        return cipher.doFinal(encryptedMsg); //return plaintext bytes
    }
}
