
package project_rsa;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import javax.swing.JFileChooser;

/**
 * This program uses RSA encryption to scramble text
 * @author sylvain Goedike
 */
public class project_RSA extends javax.swing.JFrame {
    
    private int rsa;
    private BigInteger p, q, n, z, k, j;
    private final BigInteger one = new BigInteger("1");
    private final BigInteger two = new BigInteger("2");
    private String filePath = "";

    /**
     * Creates new form project_RSA_SIM
     */
    public project_RSA() {
        initComponents();
        this.setLocationRelativeTo(null);
        this.setTitle("RSA Encryption Text Scrambler");
        jTextArea_log.append("\n\n---- Welcome to RSA Encryption Text Scrambler ----\n"
                             + "\n\t-- INSTRUCTIONS --\n\n- Start by setting the path to store the privateKey.dat file\n- After setting the path, you can gererate a key if you don't already have one"
                             + "\n- Write and encrypt your message\n- Copy the encrypted message and send it by email along with the privateKey.dat file as attachement\n\n");
    }
    
    /**
    * Generates public and private keys
    * @param bits the RSA in bits
    */
    public void generate(int bits){
        SecureRandom random = new SecureRandom();
        // test if keys work
        do{
            try{
            // find the modulo and totient
                p = BigInteger.probablePrime(bits, random);
                q = BigInteger.probablePrime(bits, random);
                n = p.multiply(q);
                z = p.subtract(one).multiply(q.subtract(one));
                
            // find a public exponent (prime number k) that is coprime to z (doesn't divise z)
                k = BigInteger.probablePrime(bits, random);

            // find the private exponent (congruence relation to k (k * j) % z = 1)
                // k^-1 % z
                j = k.modInverse(z);
                
            }catch(ArithmeticException | NullPointerException e){
                jTextArea_log.append(this.log("Null Pointer ERROR: ", String.valueOf(e)));
            }
        }while((k.gcd(z).equals(BigInteger.ONE) == false));
        
        DataOutputStream output = writeFile();
        this.pushKeysToFile(output);
               
        jTextArea_log.append("\n\n---- Begin RSA Public Key of " + bits + "-Bits ----\n\n");       
        jTextArea_log.append(this.log("1st random p = ", String.valueOf(p)));       
        jTextArea_log.append(this.log("2nd random q = ", String.valueOf(q)));
        jTextArea_log.append(this.log("modulo n = ", String.valueOf(n)));       
        jTextArea_log.append(this.log("totient z = ", String.valueOf(z)));       
        jTextArea_log.append(this.log("public key exponent (coprime to z) = ", String.valueOf(k))); 
        jTextArea_log.append(this.log("private key exponent (inverse of public) = ", String.valueOf(j) + "\n\n"));   
    }
     
    /**
    * Encrypts the message using the appropriate keys ( messageIn^exponent % n = messageOut )
    * @param messageIn the message in plain text
    * @return messageOut - the encrypted message
    */
    public BigInteger cypherE(String messageIn){
        byte[] encode = messageIn.getBytes();
        BigInteger message = new BigInteger(1, encode);
        BigInteger messageOut = message.modPow(k, n);

        jTextArea_log.append("------- Begin Encryption -------\n\n");       
        jTextArea_log.append(this.log("plain text message = ", messageIn)); 
        jTextArea_log.append(this.log("encoded text message = ", String.valueOf(message)));       
        jTextArea_log.append(this.log("public exponent = ", String.valueOf(k)));       
        jTextArea_log.append(this.log("modulo =  ", String.valueOf(n)));       
        jTextArea_log.append(this.log("encrypted message =  ", String.valueOf(messageOut)) + "\n-------- End Encryption --------\n\n");        
                
        return messageOut;       
    }
    
    /**
    * Decrypts the message using the appropriate keys ( messageIn^exponent % n = messageOut )
    * @param messageIn the message to decrypt
    * @return messageOut - the message in its original state
    */
    public String cypherP(BigInteger messageIn){
        BigInteger decode = messageIn.modPow(j, n);
        String messageOut = new String(decode.toByteArray());

        jTextArea_log.append("------- Begin Decryption -------\n\n");       
        jTextArea_log.append(this.log("encrypted message = ", String.valueOf(messageIn)));
        jTextArea_log.append(this.log("decoded text message = ", String.valueOf(decode)));              
        jTextArea_log.append(this.log("private exponent = ", String.valueOf(j)));       
        jTextArea_log.append(this.log("modulo =  ", String.valueOf(n))); 
        jTextArea_log.append(this.log("decrypted message =  ", String.valueOf(messageOut)) + "\n-------- End Decryption --------\n\n");
        
        return messageOut;       
    }
       
    /**
    * Adds a string to the log
    * @param name info about the string to append
    * @param a a string to append
    * @return logString - the string that will be added to the log
    */
    public String log(String name, String a){
        StringBuilder logString = new StringBuilder();
        String nextLine = "\n\n";
        logString.append(name);
        logString.append(a);
        logString.append(nextLine);
        
        return logString.toString();       
    }
    
    /**
    * Sets the clipboard to string
    * @param message the string to copy on the clipboard
    */
    public void copy(String message){
        StringSelection stringSelection = new StringSelection (message);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard ();
        clipboard.setContents (stringSelection, null);
    }
    
    /**
    * Gets the String residing on the clipboard.
    * @return result - any text found on the Clipboard or return an empty String
    */
    public String paste() {
        String result = "";
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        //odd: the Object param of getContents is not currently used
        Transferable contents = clipboard.getContents(null);
        boolean hasTransferableText = (contents != null) && contents.isDataFlavorSupported(DataFlavor.stringFlavor);
        if (hasTransferableText) {
            try {
                result = (String)contents.getTransferData(DataFlavor.stringFlavor);
            }
            catch (UnsupportedFlavorException fl){
                jTextArea_log.append(this.log("Unsupported Flavor ERROR =  ", String.valueOf(fl)));
            }
            catch (IOException io){
                jTextArea_log.append(this.log("IO ERROR =  ", String.valueOf(io)));
            }            
        }
        return result;
    } 
    
    /**
    * Writes the output stream
    * @return null
    */
    public DataOutputStream writeFile(){
        try{
            File pKey = new File(filePath);
            DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(pKey, false)));
            
            return output;
            
        }catch(IOException e){
            jTextArea_log.append(this.log("IO ERROR = can't create file at ", String.valueOf(filePath)));
        }
        return null;
    }
    
    /**
     * Writes the key data to file
     * @param output the data output stream
     */
    public void pushKeysToFile(DataOutputStream output){
        try{
            output.writeUTF(String.valueOf(k) + "|");
            output.writeUTF(String.valueOf(j) + "|");
            output.writeUTF(String.valueOf(n) + "|");
            output.close();
        }catch (IOException io){
            jTextArea_log.append(this.log("IO ERROR = can't write to file ", String.valueOf(filePath)));
        }
    }
    
    /**
     * Reads the key data from file
     */
    public void getKeysFromFile(){
        String first = "";
        String second = "";
        String third = "";    
        boolean found = true;
        try{
            File pKey = new File(filePath);       
            DataInputStream input = new DataInputStream(new BufferedInputStream(new FileInputStream(pKey)));                       
            first = input.readUTF();
            second = input.readUTF();
            third = input.readUTF();
           
            input.close();
        }catch(IOException e){
            jTextArea_log.append(this.log("IO ERROR = can't read from file: ", String.valueOf(filePath)));
            found = false;
        }
        if(found == true){
            BigInteger tmpPubKey = new BigInteger(first.substring(0, first.length()-1));
            BigInteger tmpPrivKey = new BigInteger(second.substring(0, second.length()-1));
            BigInteger tmpModulo = new BigInteger(third.substring(0, third.length()-1));
            k = tmpPubKey;      
            j = tmpPrivKey;      
            n = tmpModulo;
        }else {
            jTextArea_log.append("Please locate the file privateKey.dat\n");
        }
    }
    
    /**
     * Creates a File Chooser for browsing files 
     */
    class MyCustomFilter extends javax.swing.filechooser.FileFilter {
        @Override
        public boolean accept(File file) {
            // Allow only directories, or files with ".txt" extension
            return file.isDirectory() || file.getAbsolutePath().endsWith(".dat");
        }
        @Override
        public String getDescription() {
            // This description will be displayed in the dialog,
            // hard-coded = ugly, should be done via I18N
            return "Text documents (*.dat)";
        }
    } 

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jFileChooser = new javax.swing.JFileChooser();
        jPanel_generate = new javax.swing.JPanel();
        jLabel_RSA = new javax.swing.JLabel();
        jButton_generate = new javax.swing.JButton();
        jTextField_RSA = new javax.swing.JTextField();
        jLabel_encryption = new javax.swing.JLabel();
        jPanel_encryption = new javax.swing.JPanel();
        jButton_encryption = new javax.swing.JButton();
        jButton_decryption = new javax.swing.JButton();
        jScrollPane_encryption_message = new javax.swing.JScrollPane();
        jTextArea_encryption_message = new javax.swing.JTextArea();
        jButton_encryption_paste = new javax.swing.JButton();
        jLabel_decryption = new javax.swing.JLabel();
        jPanel_decryption = new javax.swing.JPanel();
        jScrollPane_decryption_message = new javax.swing.JScrollPane();
        jTextArea_decryption_message = new javax.swing.JTextArea();
        jButton_copy = new javax.swing.JButton();
        jLabel_log = new javax.swing.JLabel();
        jPanel_log = new javax.swing.JPanel();
        jScrollPane_log = new javax.swing.JScrollPane();
        jTextArea_log = new javax.swing.JTextArea();
        jTextField_path = new javax.swing.JTextField();
        jLabel_path = new javax.swing.JLabel();
        jButton_open = new javax.swing.JButton();

        jFileChooser.setCurrentDirectory(new java.io.File("/Users/Sylvain/Documents"));
        jFileChooser.setDialogTitle("locate privateKey.dat");
        jFileChooser.setFileFilter(new MyCustomFilter());

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("RSA Encryption Text Scrambler");
        setBackground(new java.awt.Color(0, 0, 0));

        jPanel_generate.setBackground(new java.awt.Color(0, 0, 0));

        jLabel_RSA.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_RSA.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_RSA.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_RSA.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_RSA.setText("-bits");
        jLabel_RSA.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jButton_generate.setText("Generate Key");
        jButton_generate.setToolTipText("Generate");
        jButton_generate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_generateActionPerformed(evt);
            }
        });

        jTextField_RSA.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jTextField_RSA.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField_RSA.setText("1024");
        jTextField_RSA.setToolTipText("max 32-bits");
        jTextField_RSA.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField_RSAActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel_generateLayout = new javax.swing.GroupLayout(jPanel_generate);
        jPanel_generate.setLayout(jPanel_generateLayout);
        jPanel_generateLayout.setHorizontalGroup(
            jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_generateLayout.createSequentialGroup()
                .addContainerGap(29, Short.MAX_VALUE)
                .addComponent(jTextField_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel_RSA)
                .addGap(18, 18, 18)
                .addComponent(jButton_generate)
                .addGap(10, 10, 10))
        );
        jPanel_generateLayout.setVerticalGroup(
            jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_generateLayout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton_generate)
                    .addComponent(jTextField_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(18, Short.MAX_VALUE))
        );

        jLabel_encryption.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_encryption.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_encryption.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_encryption.setText("Encryption:");
        jLabel_encryption.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_encryption.setBackground(new java.awt.Color(0, 0, 0));

        jButton_encryption.setText("Encrypt");
        jButton_encryption.setToolTipText("Encrypt");
        jButton_encryption.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_encryptionActionPerformed(evt);
            }
        });

        jButton_decryption.setText("Decrypt");
        jButton_decryption.setToolTipText("Decrypt");
        jButton_decryption.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_decryptionActionPerformed(evt);
            }
        });

        jScrollPane_encryption_message.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        jTextArea_encryption_message.setColumns(20);
        jTextArea_encryption_message.setLineWrap(true);
        jTextArea_encryption_message.setRows(5);
        jScrollPane_encryption_message.setViewportView(jTextArea_encryption_message);

        jButton_encryption_paste.setText("Paste");
        jButton_encryption_paste.setToolTipText("Paste");
        jButton_encryption_paste.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_encryption_pasteActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel_encryptionLayout = new javax.swing.GroupLayout(jPanel_encryption);
        jPanel_encryption.setLayout(jPanel_encryptionLayout);
        jPanel_encryptionLayout.setHorizontalGroup(
            jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                .addGroup(jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                        .addGap(14, 14, 14)
                        .addComponent(jScrollPane_encryption_message, javax.swing.GroupLayout.PREFERRED_SIZE, 323, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jButton_encryption_paste, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(58, 58, 58)
                        .addComponent(jButton_encryption)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton_decryption)))
                .addContainerGap(12, Short.MAX_VALUE))
        );
        jPanel_encryptionLayout.setVerticalGroup(
            jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton_encryption)
                    .addComponent(jButton_decryption)
                    .addComponent(jButton_encryption_paste))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane_encryption_message, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(11, Short.MAX_VALUE))
        );

        jLabel_decryption.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_decryption.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_decryption.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_decryption.setText("Decryption:");
        jLabel_decryption.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_decryption.setBackground(new java.awt.Color(0, 0, 0));

        jScrollPane_decryption_message.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        jTextArea_decryption_message.setColumns(20);
        jTextArea_decryption_message.setLineWrap(true);
        jTextArea_decryption_message.setRows(5);
        jScrollPane_decryption_message.setViewportView(jTextArea_decryption_message);

        jButton_copy.setText("Copy");
        jButton_copy.setToolTipText("Copy");
        jButton_copy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_copyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel_decryptionLayout = new javax.swing.GroupLayout(jPanel_decryption);
        jPanel_decryption.setLayout(jPanel_decryptionLayout);
        jPanel_decryptionLayout.setHorizontalGroup(
            jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_decryptionLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel_decryptionLayout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addComponent(jScrollPane_decryption_message, javax.swing.GroupLayout.PREFERRED_SIZE, 324, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jButton_copy))
                .addContainerGap(14, Short.MAX_VALUE))
        );
        jPanel_decryptionLayout.setVerticalGroup(
            jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_decryptionLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButton_copy)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane_decryption_message, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(11, Short.MAX_VALUE))
        );

        jLabel_log.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_log.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_log.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_log.setText("Log:");
        jLabel_log.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_log.setBackground(new java.awt.Color(0, 0, 0));

        jScrollPane_log.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jScrollPane_log.setPreferredSize(new java.awt.Dimension(240, 80));

        jTextArea_log.setColumns(20);
        jTextArea_log.setLineWrap(true);
        jTextArea_log.setRows(5);
        jTextArea_log.setToolTipText("");
        jScrollPane_log.setViewportView(jTextArea_log);

        javax.swing.GroupLayout jPanel_logLayout = new javax.swing.GroupLayout(jPanel_log);
        jPanel_log.setLayout(jPanel_logLayout);
        jPanel_logLayout.setHorizontalGroup(
            jPanel_logLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_logLayout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jScrollPane_log, javax.swing.GroupLayout.PREFERRED_SIZE, 696, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(16, Short.MAX_VALUE))
        );
        jPanel_logLayout.setVerticalGroup(
            jPanel_logLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_logLayout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jScrollPane_log, javax.swing.GroupLayout.PREFERRED_SIZE, 385, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(14, Short.MAX_VALUE))
        );

        jTextField_path.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField_pathActionPerformed(evt);
            }
        });

        jLabel_path.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_path.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_path.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_path.setText("Path:");
        jLabel_path.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jButton_open.setText("Browse");
        jButton_open.setToolTipText("Browse");
        jButton_open.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_openActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(39, 39, 39)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jLabel_path)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jTextField_path, javax.swing.GroupLayout.PREFERRED_SIZE, 393, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButton_open, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jPanel_generate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(46, 46, 46))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel_log, javax.swing.GroupLayout.PREFERRED_SIZE, 97, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jPanel_log, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, 159, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jPanel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jPanel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE))))
                        .addGap(39, 39, 39))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jPanel_generate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jTextField_path, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel_path))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton_open)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jPanel_decryption, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel_encryption, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel_log, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel_log, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(22, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton_generateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_generateActionPerformed
        String RSA = jTextField_RSA.getText();
        int bits = Integer.parseInt(RSA);
        this.generate(bits);      
    }//GEN-LAST:event_jButton_generateActionPerformed

    private void jTextField_RSAActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField_RSAActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextField_RSAActionPerformed

    private void jButton_encryptionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_encryptionActionPerformed
        String messageIn = jTextArea_encryption_message.getText();
        BigInteger E = this.cypherE(messageIn);
        String messageEncrypted = String.valueOf(E);
        jTextArea_decryption_message.setText(messageEncrypted); 
        jTextArea_encryption_message.setText("");        
    }//GEN-LAST:event_jButton_encryptionActionPerformed

    private void jButton_decryptionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_decryptionActionPerformed
        BigInteger messageIn = new BigInteger(jTextArea_encryption_message.getText());
        String P = this.cypherP(messageIn);
        String messageDecrypted = String.valueOf(P);
        jTextArea_decryption_message.setText(messageDecrypted);
        jTextArea_encryption_message.setText("");
    }//GEN-LAST:event_jButton_decryptionActionPerformed

    private void jButton_copyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_copyActionPerformed
        this.copy(jTextArea_decryption_message.getText());
    }//GEN-LAST:event_jButton_copyActionPerformed

    private void jButton_openActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_openActionPerformed
        int returnVal = jFileChooser.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = jFileChooser.getSelectedFile();
            filePath = String.valueOf(file.getAbsolutePath());
            jTextField_path.setText(filePath);
            this.getKeysFromFile();
        jTextArea_log.append("\nFile succesfully loaded.\n");
        } else {
            //System.out.println("File access cancelled by user.");
            jTextArea_log.append("\nFile access was cancelled.\n");
        }
    }//GEN-LAST:event_jButton_openActionPerformed

    private void jTextField_pathActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField_pathActionPerformed
        // load from file on start up 
    }//GEN-LAST:event_jTextField_pathActionPerformed

    private void jButton_encryption_pasteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_encryption_pasteActionPerformed
        jTextArea_encryption_message.setText(this.paste());

    }//GEN-LAST:event_jButton_encryption_pasteActionPerformed
   
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(project_RSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(project_RSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(project_RSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(project_RSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /*project_RSA test = new project_RSA();
        test.random(16);*/
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new project_RSA().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton_copy;
    private javax.swing.JButton jButton_decryption;
    private javax.swing.JButton jButton_encryption;
    private javax.swing.JButton jButton_encryption_paste;
    private javax.swing.JButton jButton_generate;
    private javax.swing.JButton jButton_open;
    private javax.swing.JFileChooser jFileChooser;
    private javax.swing.JLabel jLabel_RSA;
    private javax.swing.JLabel jLabel_decryption;
    private javax.swing.JLabel jLabel_encryption;
    private javax.swing.JLabel jLabel_log;
    private javax.swing.JLabel jLabel_path;
    private javax.swing.JPanel jPanel_decryption;
    private javax.swing.JPanel jPanel_encryption;
    private javax.swing.JPanel jPanel_generate;
    private javax.swing.JPanel jPanel_log;
    private javax.swing.JScrollPane jScrollPane_decryption_message;
    private javax.swing.JScrollPane jScrollPane_encryption_message;
    private javax.swing.JScrollPane jScrollPane_log;
    private javax.swing.JTextArea jTextArea_decryption_message;
    private javax.swing.JTextArea jTextArea_encryption_message;
    private javax.swing.JTextArea jTextArea_log;
    private javax.swing.JTextField jTextField_RSA;
    private javax.swing.JTextField jTextField_path;
    // End of variables declaration//GEN-END:variables
}
