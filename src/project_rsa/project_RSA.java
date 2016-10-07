
package project_rsa;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This program uses RSA encryption to scramble text
 * @author sylvain Goedike
 */
public class project_RSA extends javax.swing.JFrame {
    
    private int rsa;
    private BigInteger p, q, n, z, k, j;
    private static Boolean primeState;
    BigInteger one = new BigInteger("1");
    BigInteger two = new BigInteger("2");

    /**
     * Creates new form project_RSA_SIM
     */
    public project_RSA() {
        initComponents();
        this.setLocationRelativeTo(null);
        this.setTitle("RSA Encryption Text Scrambler");
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
                jTextArea_log.append(this.log("ERROR ", String.valueOf(e)));
            }
        }while((k.gcd(z).equals(BigInteger.ONE) == false));
        
        String prime1 = String.valueOf(p);
        String prime2 = String.valueOf(q);
        String mod = String.valueOf(n);
        String totient = String.valueOf(z);
        String pubKey = String.valueOf(k);
        String privKey = String.valueOf(j);
        
        jTextArea_log.append("\n\n---- Begin RSA Public Key of " + bits + "-Bits ----\n\n");       
        jTextArea_log.append(this.log("1st random p = ", prime1));       
        jTextArea_log.append(this.log("2nd random q = ", prime2));
        jTextArea_log.append("modulo n = (" + prime1 + " x " + prime2 + ")" + this.log(" = ", mod));       
        jTextArea_log.append("totient z = ((" + prime1 + "-1) x (" + prime2 + "-1))" + this.log(" = ", totient));       
        jTextArea_log.append(this.log("public key exponent (coprime to z) = ", pubKey)); 
        jTextArea_log.append(this.log("private key exponent (inverse of public) = ", privKey));   
        jTextArea_log.append("verify = (" + pubKey + " x " + privKey + ") mod" + totient + " = 1\n\n"); 
    }
     
    /**
    * Encrypts the message using the appropriate keys ( messageIn^exponent % n = messageOut )
    * @param messageIn the message in plain text
    * @param exponent the public exponent key
    * @param n the modulo
    * @return messageOut - the encrypted message
    */
    public BigInteger cypherE(String messageIn, BigInteger exponent, BigInteger n){
        byte[] encode = messageIn.getBytes();
        BigInteger message = new BigInteger(1, encode);
        BigInteger messageOut = message.modPow(exponent, n);
        
        String pubKey = String.valueOf(exponent);       
        String mod = String.valueOf(n);
        jTextArea_log.append("------- Begin Encryption -------\n\n");       
        jTextArea_log.append(this.log("plain text message = ", messageIn)); 
        jTextArea_log.append(this.log("encoded text message = ", String.valueOf(message)));       
        jTextArea_log.append(this.log("public exponent = ", pubKey));       
        jTextArea_log.append(this.log("modulo =  ", mod));       
        jTextArea_log.append(this.log("encrypted message =  ", String.valueOf(messageOut)) + "\n-------- End Encryption --------\n\n");        
        
        return messageOut;       
    }
    
    /**
    * Decrypts the message using the appropriate keys ( messageIn^exponent % n = messageOut )
    * @param messageIn the message to decrypt
    * @param exponent the private exponent key
    * @param n the modulo
    * @return messageOut - the message in its original state
    */
    public String cypherP(BigInteger messageIn, BigInteger exponent, BigInteger n){
        BigInteger decode = messageIn.modPow(exponent, n);
        String messageOut = new String(decode.toByteArray());

        String privKey = String.valueOf(exponent);
        String mod = String.valueOf(n);
        jTextArea_log.append("------- Begin Decryption -------\n\n");       
        jTextArea_log.append(this.log("encrypted message = ", String.valueOf(messageIn)));
        jTextArea_log.append(this.log("decoded text message = ", String.valueOf(decode)));              
        jTextArea_log.append(this.log("private exponent = ", privKey));       
        jTextArea_log.append(this.log("modulo =  ", mod)); 
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
            catch (UnsupportedFlavorException | IOException ex){
                System.out.println(ex);
            }
        }
        return result;
    } 

    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel_generate = new javax.swing.JPanel();
        jLabel_RSA = new javax.swing.JLabel();
        jTextField_RSA = new javax.swing.JTextField();
        jButton_generate = new javax.swing.JButton();
        jLabel_encryption = new javax.swing.JLabel();
        jPanel_encryption = new javax.swing.JPanel();
        jButton_encryption = new javax.swing.JButton();
        jButton_decryption = new javax.swing.JButton();
        jScrollPane_encryption_message = new javax.swing.JScrollPane();
        jTextArea_encryption_message = new javax.swing.JTextArea();
        jButton_paste1 = new javax.swing.JButton();
        jLabel_decryption = new javax.swing.JLabel();
        jPanel_decryption = new javax.swing.JPanel();
        jScrollPane_decryption_message = new javax.swing.JScrollPane();
        jTextArea_decryption_message = new javax.swing.JTextArea();
        jButton_copy = new javax.swing.JButton();
        jLabel_log = new javax.swing.JLabel();
        jPanel_log = new javax.swing.JPanel();
        jScrollPane_log = new javax.swing.JScrollPane();
        jTextArea_log = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("RSA Encryption Text Scrambler");
        setBackground(new java.awt.Color(0, 0, 0));

        jPanel_generate.setBackground(new java.awt.Color(0, 0, 0));

        jLabel_RSA.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_RSA.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_RSA.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_RSA.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_RSA.setText("Nombre de bits:");
        jLabel_RSA.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jTextField_RSA.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jTextField_RSA.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField_RSA.setText("1024");
        jTextField_RSA.setToolTipText("max 32-bits");
        jTextField_RSA.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField_RSAActionPerformed(evt);
            }
        });

        jButton_generate.setText("Generate Key");
        jButton_generate.setToolTipText("Generate");
        jButton_generate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_generateActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel_generateLayout = new javax.swing.GroupLayout(jPanel_generate);
        jPanel_generate.setLayout(jPanel_generateLayout);
        jPanel_generateLayout.setHorizontalGroup(
            jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_generateLayout.createSequentialGroup()
                .addGap(22, 22, 22)
                .addComponent(jLabel_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 109, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextField_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jButton_generate)
                .addContainerGap(17, Short.MAX_VALUE))
        );
        jPanel_generateLayout.setVerticalGroup(
            jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_generateLayout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton_generate))
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

        jButton_paste1.setText("Paste");
        jButton_paste1.setToolTipText("Encrypt");
        jButton_paste1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_paste1ActionPerformed(evt);
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
                        .addComponent(jButton_paste1, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE)
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
                    .addComponent(jButton_paste1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane_encryption_message, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jLabel_decryption.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_decryption.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_decryption.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_decryption.setText("Décryption:");
        jLabel_decryption.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_decryption.setBackground(new java.awt.Color(0, 0, 0));

        jScrollPane_decryption_message.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        jTextArea_decryption_message.setColumns(20);
        jTextArea_decryption_message.setLineWrap(true);
        jTextArea_decryption_message.setRows(5);
        jScrollPane_decryption_message.setViewportView(jTextArea_decryption_message);

        jButton_copy.setText("Copy");
        jButton_copy.setToolTipText("Encrypt");
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

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(39, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel_log, javax.swing.GroupLayout.PREFERRED_SIZE, 97, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jPanel_log, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(jPanel_generate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(jLabel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, 159, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jPanel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGap(18, 18, 18)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(jPanel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jLabel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE)))))
                .addGap(39, 39, 39))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addComponent(jPanel_generate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
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
        BigInteger E = this.cypherE(messageIn, k, n);
        String messageEncrypted = String.valueOf(E);
        jTextArea_decryption_message.setText(messageEncrypted);         
    }//GEN-LAST:event_jButton_encryptionActionPerformed

    private void jButton_decryptionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_decryptionActionPerformed
        BigInteger messageIn = new BigInteger(jTextArea_encryption_message.getText());
        String P = this.cypherP(messageIn, j, n);
        String messageDecrypted = String.valueOf(P);
        jTextArea_decryption_message.setText(messageDecrypted);
    }//GEN-LAST:event_jButton_decryptionActionPerformed

    private void jButton_copyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_copyActionPerformed
        this.copy(jTextArea_decryption_message.getText());
    }//GEN-LAST:event_jButton_copyActionPerformed

    private void jButton_paste1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_paste1ActionPerformed
        jTextArea_encryption_message.setText(this.paste());
    }//GEN-LAST:event_jButton_paste1ActionPerformed

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
    private javax.swing.JButton jButton_generate;
    private javax.swing.JButton jButton_paste1;
    private javax.swing.JLabel jLabel_RSA;
    private javax.swing.JLabel jLabel_decryption;
    private javax.swing.JLabel jLabel_encryption;
    private javax.swing.JLabel jLabel_log;
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
    // End of variables declaration//GEN-END:variables
}
