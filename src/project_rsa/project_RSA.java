
package project_rsa;

import java.math.BigInteger;
import java.util.Random;

/**
 * This program does RSA encryption
 * @author sylvain Goedike
 */
public class project_RSA extends javax.swing.JFrame {
    
    private int rsa;
    private BigInteger n, z, k, j;
    private int p, q;
    private static Boolean primeState;

    /**
     * Creates new form project_RSA_SIM
     */
    public project_RSA() {
        initComponents();
        this.setLocationRelativeTo(null);
        this.setTitle("RSA Encryption Simulator");
    }
    
    /*
    * @param randNum - a random number in range of min and max
    * @return primeState - true if the number is prime
    */
    public static Boolean isPrime(int randNum){
        if(randNum%2!=0 && randNum%3!=0 &&randNum%4!=0 && randNum%5!=0 && randNum%6!=0 && randNum%7!=0 && randNum%8!=0 && randNum%9!=0)
            primeState = true;
        else primeState = false;
        
        return primeState;
    }
    
    /*
    * @param bits - the RSA in bits
    * @return randNumPrime - a random prime number in range of min and max
    */
    public int randomPrime(int bits){
        int randNumPrime;
        do{
            int min = (int) Math.pow(2, bits-1);
            int max = (int) Math.pow(2, bits) -1;
            Random rand = new Random();
            randNumPrime = rand.nextInt(max - min) + min;
        }while(isPrime(randNumPrime) == false);
                
        return randNumPrime;
    }
    
    /*
    * THIS FUNCTION IS REPLACED BY BIGINTEGERS.MODINVERSE()
    * Calculates the inverse of a given integer using the Extended Euclidean Algorithm
    * First finds the GCD of z (totient) and k (public exponent), then finds the x and y ( GCD = (x*z) + (y*k) )
    * @param z - the totient value
    * @param k - the public exponent
    * @return lastY - the private key
    */
    /*public long Ext_Euclidean(long z, long k){
        long x = 0, y = 1, lastX = 1, lastY = 0, temp;
        
        while(k != 0){
            long quotient = z / k;
            long remainder = z % k;
            z = k;
            k = remainder;
 
            temp = x;
            x = lastX - quotient * x;
            lastX = temp;
 
            temp = y;
            y = lastY - quotient * y;
            lastY = temp;
        }  
        
        return lastY;
    }*/
    
    /*
    * Generates public and private keys
    * @param bits - the RSA in bits
    */
    public void generate(int bits){
    // test if keys work
        do{
            try{
            // find the modulo and totient
                p = randomPrime(bits);
                q = randomPrime(bits);               
                n = BigInteger.valueOf(p * q);
                z = BigInteger.valueOf((p-1) * (q-1));
                
            // find a public exponent (prime number k) that is coprime to z (doesn't divise z)
                k = BigInteger.valueOf(randomPrime(bits));

            // find the private exponent (congruence relation to k (k * j) % z = 1)
                // k^-1 % z
                j = k.modInverse(z);
                
            }catch(ArithmeticException | NullPointerException e){
                jTextArea_log.append(this.log("ERROR ", String.valueOf(e)));
            }
        }while(this.testKeys() == false);
        
        jLabel_n_modulo.setText(String.valueOf(n));                      
        jLabel_k_exponent.setText(String.valueOf(k));       
        jLabel_j_private_key.setText(String.valueOf(j));
    }
     
    /*
    * Encrypts or decrypts the message using the appropriate keys ( messageIn^exponent % n = messageOut )
    * @param messageIn - the message in
    * @param exponent - the exponent key
    * @param n - the modulo
    * @return messageOut - the message out
    */
    public BigInteger cypher(String messageIn, BigInteger exponent, BigInteger n){
        BigInteger message = new BigInteger(messageIn);
        BigInteger messageOut = message.modPow(exponent, n);
        
        return messageOut;       
    }
    
    /*
    * Test if both pulic and private keys are valid
    * @return pass - true if valid
    */
    public Boolean testKeys(){
        Boolean pass;
        BigInteger two = new BigInteger("2");
        String in = String.valueOf(n.subtract(two));
        String out = String.valueOf(this.cypher(in, k, n));
        String compare = String.valueOf(this.cypher(out, j, n));
        pass = (k.gcd(z).equals(BigInteger.ONE) && in.equals(compare));
        
        return pass;
    }
    
    /*
    * Adds a string to the log
    * @param name - info about the string to append
    * @param a - a string to append
    * @return - the string that will be added to the log
    */
    public String log(String name, String a){
        StringBuilder logString = new StringBuilder();
        String nextLine = "\n";
        logString.append(name);
        logString.append(a);
        logString.append(nextLine);
        
        return logString.toString();       
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel_nombre_de_bits1 = new javax.swing.JLabel();
        jPanel_generate = new javax.swing.JPanel();
        jLabel_RSA = new javax.swing.JLabel();
        jTextField_RSA = new javax.swing.JTextField();
        jButton_generate = new javax.swing.JButton();
        jLabel_public_key = new javax.swing.JLabel();
        jPanel_public_key = new javax.swing.JPanel();
        jLabel_n_modulo = new javax.swing.JLabel();
        jLabel_k_exponent = new javax.swing.JLabel();
        jLabel_private_key = new javax.swing.JLabel();
        jPanel_private_key = new javax.swing.JPanel();
        jLabel_j_private_key = new javax.swing.JLabel();
        jLabel_encryption = new javax.swing.JLabel();
        jPanel_encryption = new javax.swing.JPanel();
        jLabel_message = new javax.swing.JLabel();
        jTextField_P_message_plain = new javax.swing.JTextField();
        jButton_encryption = new javax.swing.JButton();
        jLabel_message_encrypte = new javax.swing.JLabel();
        jPanel_message_encrypte = new javax.swing.JPanel();
        jLabel_E_message_crypted = new javax.swing.JLabel();
        jLabel_decryption = new javax.swing.JLabel();
        jPanel_decryption = new javax.swing.JPanel();
        jLabel_private_key_try = new javax.swing.JLabel();
        jTextField_j_private_key_try = new javax.swing.JTextField();
        jButton_decryption = new javax.swing.JButton();
        jLabel_message_decryption = new javax.swing.JLabel();
        jPanel_message_decryption = new javax.swing.JPanel();
        jLabel_P_message_decrypted = new javax.swing.JLabel();
        jLabel_log = new javax.swing.JLabel();
        jPanel_log = new javax.swing.JPanel();
        jScrollPane_log = new javax.swing.JScrollPane();
        jTextArea_log = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(0, 0, 0));

        jLabel_nombre_de_bits1.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_nombre_de_bits1.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_nombre_de_bits1.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_nombre_de_bits1.setText("Générateur de clées");
        jLabel_nombre_de_bits1.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_generate.setBackground(new java.awt.Color(0, 0, 0));

        jLabel_RSA.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_RSA.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_RSA.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_RSA.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_RSA.setText("Nombre de bits:");
        jLabel_RSA.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jTextField_RSA.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jTextField_RSA.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField_RSA.setToolTipText("max 32-bits");
        jTextField_RSA.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField_RSAActionPerformed(evt);
            }
        });

        jButton_generate.setText("Generate");
        jButton_generate.setToolTipText("Generate");
        jButton_generate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_generateActionPerformed(evt);
            }
        });

        jLabel_public_key.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_public_key.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_public_key.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_public_key.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_public_key.setText("Public Key:");
        jLabel_public_key.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_public_key.setBackground(new java.awt.Color(255, 255, 255));

        jLabel_n_modulo.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_n_modulo.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_n_modulo.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel_n_modulo.setToolTipText("Key size (modulo)");
        jLabel_n_modulo.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        jLabel_k_exponent.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_k_exponent.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_k_exponent.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel_k_exponent.setToolTipText("Exponent");
        jLabel_k_exponent.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout jPanel_public_keyLayout = new javax.swing.GroupLayout(jPanel_public_key);
        jPanel_public_key.setLayout(jPanel_public_keyLayout);
        jPanel_public_keyLayout.setHorizontalGroup(
            jPanel_public_keyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_public_keyLayout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(jPanel_public_keyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel_k_exponent, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel_n_modulo, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(0, 27, Short.MAX_VALUE))
        );
        jPanel_public_keyLayout.setVerticalGroup(
            jPanel_public_keyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_public_keyLayout.createSequentialGroup()
                .addGap(17, 17, 17)
                .addComponent(jLabel_n_modulo, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel_k_exponent, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(12, Short.MAX_VALUE))
        );

        jLabel_private_key.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_private_key.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_private_key.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_private_key.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_private_key.setText("Private Key:");
        jLabel_private_key.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_private_key.setBackground(new java.awt.Color(255, 255, 255));

        jLabel_j_private_key.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_j_private_key.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_j_private_key.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel_j_private_key.setToolTipText("Private Key");
        jLabel_j_private_key.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout jPanel_private_keyLayout = new javax.swing.GroupLayout(jPanel_private_key);
        jPanel_private_key.setLayout(jPanel_private_keyLayout);
        jPanel_private_keyLayout.setHorizontalGroup(
            jPanel_private_keyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_private_keyLayout.createSequentialGroup()
                .addGap(25, 25, 25)
                .addComponent(jLabel_j_private_key, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(25, Short.MAX_VALUE))
        );
        jPanel_private_keyLayout.setVerticalGroup(
            jPanel_private_keyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_private_keyLayout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jLabel_j_private_key, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(14, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout jPanel_generateLayout = new javax.swing.GroupLayout(jPanel_generate);
        jPanel_generate.setLayout(jPanel_generateLayout);
        jPanel_generateLayout.setHorizontalGroup(
            jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_generateLayout.createSequentialGroup()
                .addGroup(jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel_generateLayout.createSequentialGroup()
                        .addGap(22, 22, 22)
                        .addComponent(jLabel_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 109, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jTextField_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jButton_generate))
                    .addGroup(jPanel_generateLayout.createSequentialGroup()
                        .addGap(23, 23, 23)
                        .addGroup(jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel_public_key, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 147, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jPanel_public_key, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addGroup(jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel_private_key, javax.swing.GroupLayout.PREFERRED_SIZE, 80, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jPanel_private_key, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel_generateLayout.setVerticalGroup(
            jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_generateLayout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField_RSA, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton_generate))
                .addGap(18, 18, 18)
                .addGroup(jPanel_generateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel_generateLayout.createSequentialGroup()
                        .addComponent(jLabel_private_key, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel_private_key, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel_generateLayout.createSequentialGroup()
                        .addComponent(jLabel_public_key, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel_public_key, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(21, Short.MAX_VALUE))
        );

        jLabel_encryption.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_encryption.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_encryption.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_encryption.setText("Encryption");
        jLabel_encryption.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_encryption.setBackground(new java.awt.Color(0, 0, 0));

        jLabel_message.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_message.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_message.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_message.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_message.setText("Message:");
        jLabel_message.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jTextField_P_message_plain.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jTextField_P_message_plain.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField_P_message_plain.setToolTipText("only digits");
        jTextField_P_message_plain.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField_P_message_plainActionPerformed(evt);
            }
        });

        jButton_encryption.setText("Encrypt");
        jButton_encryption.setToolTipText("Encrypt");
        jButton_encryption.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_encryptionActionPerformed(evt);
            }
        });

        jLabel_message_encrypte.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_message_encrypte.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_message_encrypte.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_message_encrypte.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_message_encrypte.setText("Message encrypté:");
        jLabel_message_encrypte.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_message_encrypte.setBackground(new java.awt.Color(255, 255, 255));

        jLabel_E_message_crypted.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_E_message_crypted.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_E_message_crypted.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel_E_message_crypted.setToolTipText("Message encrypté");
        jLabel_E_message_crypted.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout jPanel_message_encrypteLayout = new javax.swing.GroupLayout(jPanel_message_encrypte);
        jPanel_message_encrypte.setLayout(jPanel_message_encrypteLayout);
        jPanel_message_encrypteLayout.setHorizontalGroup(
            jPanel_message_encrypteLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_message_encrypteLayout.createSequentialGroup()
                .addGap(25, 25, 25)
                .addComponent(jLabel_E_message_crypted, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(25, Short.MAX_VALUE))
        );
        jPanel_message_encrypteLayout.setVerticalGroup(
            jPanel_message_encrypteLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_message_encrypteLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel_E_message_crypted, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(8, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout jPanel_encryptionLayout = new javax.swing.GroupLayout(jPanel_encryption);
        jPanel_encryption.setLayout(jPanel_encryptionLayout);
        jPanel_encryptionLayout.setHorizontalGroup(
            jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                        .addComponent(jLabel_message, javax.swing.GroupLayout.PREFERRED_SIZE, 67, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jTextField_P_message_plain, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButton_encryption))
                    .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                        .addComponent(jLabel_message_encrypte, javax.swing.GroupLayout.DEFAULT_SIZE, 127, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel_message_encrypte, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(23, Short.MAX_VALUE))
        );
        jPanel_encryptionLayout.setVerticalGroup(
            jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_encryptionLayout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel_message, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField_P_message_plain, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton_encryption))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel_encryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel_message_encrypte, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jPanel_message_encrypte, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(20, Short.MAX_VALUE))
        );

        jLabel_decryption.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_decryption.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_decryption.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_decryption.setText("Décryption");
        jLabel_decryption.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_decryption.setBackground(new java.awt.Color(0, 0, 0));

        jLabel_private_key_try.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_private_key_try.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_private_key_try.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_private_key_try.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_private_key_try.setText("Private Key:");
        jLabel_private_key_try.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jTextField_j_private_key_try.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jTextField_j_private_key_try.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField_j_private_key_try.setToolTipText("Private Key");

        jButton_decryption.setText("Decrypt");
        jButton_decryption.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_decryptionActionPerformed(evt);
            }
        });

        jLabel_message_decryption.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_message_decryption.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_message_decryption.setForeground(new java.awt.Color(255, 255, 255));
        jLabel_message_decryption.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_message_decryption.setText("Message décrypté:");
        jLabel_message_decryption.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_message_decryption.setBackground(new java.awt.Color(255, 255, 255));

        jLabel_P_message_decrypted.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_P_message_decrypted.setFont(new java.awt.Font("Lucida Grande", 0, 14)); // NOI18N
        jLabel_P_message_decrypted.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel_P_message_decrypted.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout jPanel_message_decryptionLayout = new javax.swing.GroupLayout(jPanel_message_decryption);
        jPanel_message_decryption.setLayout(jPanel_message_decryptionLayout);
        jPanel_message_decryptionLayout.setHorizontalGroup(
            jPanel_message_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_message_decryptionLayout.createSequentialGroup()
                .addGap(25, 25, 25)
                .addComponent(jLabel_P_message_decrypted, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(25, Short.MAX_VALUE))
        );
        jPanel_message_decryptionLayout.setVerticalGroup(
            jPanel_message_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_message_decryptionLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel_P_message_decrypted, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(8, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout jPanel_decryptionLayout = new javax.swing.GroupLayout(jPanel_decryption);
        jPanel_decryption.setLayout(jPanel_decryptionLayout);
        jPanel_decryptionLayout.setHorizontalGroup(
            jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_decryptionLayout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel_decryptionLayout.createSequentialGroup()
                        .addComponent(jLabel_private_key_try)
                        .addGap(7, 7, 7)
                        .addComponent(jTextField_j_private_key_try, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButton_decryption))
                    .addGroup(jPanel_decryptionLayout.createSequentialGroup()
                        .addComponent(jLabel_message_decryption, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel_message_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(23, Short.MAX_VALUE))
        );
        jPanel_decryptionLayout.setVerticalGroup(
            jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_decryptionLayout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel_private_key_try, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField_j_private_key_try, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton_decryption))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel_decryptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel_message_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jPanel_message_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(20, Short.MAX_VALUE))
        );

        jLabel_log.setBackground(new java.awt.Color(255, 255, 255));
        jLabel_log.setFont(new java.awt.Font("Lucida Grande", 0, 24)); // NOI18N
        jLabel_log.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel_log.setText("Log");
        jLabel_log.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);

        jPanel_log.setBackground(new java.awt.Color(0, 0, 0));

        jScrollPane_log.setPreferredSize(new java.awt.Dimension(240, 80));

        jTextArea_log.setColumns(20);
        jTextArea_log.setRows(5);
        jTextArea_log.setToolTipText("");
        jScrollPane_log.setViewportView(jTextArea_log);

        javax.swing.GroupLayout jPanel_logLayout = new javax.swing.GroupLayout(jPanel_log);
        jPanel_log.setLayout(jPanel_logLayout);
        jPanel_logLayout.setHorizontalGroup(
            jPanel_logLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel_logLayout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jScrollPane_log, javax.swing.GroupLayout.PREFERRED_SIZE, 685, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
                .addContainerGap(35, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jPanel_log, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(jPanel_generate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jLabel_nombre_de_bits1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 248, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel_log, javax.swing.GroupLayout.PREFERRED_SIZE, 97, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(36, 36, 36)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jPanel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jPanel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, 153, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, 159, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(39, 39, 39))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel_encryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel_decryption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel_nombre_de_bits1, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel_generate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(50, 50, 50)
                        .addComponent(jLabel_log, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel_log, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(60, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton_generateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_generateActionPerformed
        String RSA = jTextField_RSA.getText();
        int bits = Integer.parseInt(RSA);
        this.generate(bits);
        String prime1 = String.valueOf((long)p);
        String prime2 = String.valueOf((long)q);
        String mod = String.valueOf(n);
        String totient = String.valueOf(z);
        String pubKey = String.valueOf(k);
        String privKey = String.valueOf(j);
        jTextArea_log.append("\n\n--- BEGIN RSA ALGORITHM OF " + bits + "-BITS ---\n\n");       
        jTextArea_log.append(this.log("1st random prime = ", prime1));       
        jTextArea_log.append(this.log("2nd random prime = ", prime2));
        jTextArea_log.append("modulo = (" + prime1 + " x " + prime2 + ")" + this.log(" = ", mod));       
        jTextArea_log.append("totient = ((" + prime1 + "-1) x (" + prime2 + "-1))" + this.log(" = ", totient));       
        jTextArea_log.append(this.log("public exponent (random and coprime to totient) = ", pubKey)); 
        jTextArea_log.append(this.log("private exponent (inverse of public exponent) = ", privKey));   
        jTextArea_log.append("verify = (" + pubKey + " x " + privKey + ") mod" + totient + " = 1\n\n");       
    }//GEN-LAST:event_jButton_generateActionPerformed

    private void jTextField_RSAActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField_RSAActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextField_RSAActionPerformed

    private void jTextField_P_message_plainActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField_P_message_plainActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextField_P_message_plainActionPerformed

    private void jButton_encryptionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_encryptionActionPerformed
        String messageIn = jTextField_P_message_plain.getText();
        //BigInteger P = BigInteger.valueOf(messageIn); 
        BigInteger E = this.cypher(messageIn, k, n);
        String messageEncrypted = String.valueOf(E);
        jLabel_E_message_crypted.setText(messageEncrypted);
        String mod = String.valueOf(n);
        String pubKey = String.valueOf(k);
        jTextArea_log.append("------- Begin Encryption -------\n\n");       
        jTextArea_log.append(this.log("plain text message = ", messageIn));       
        jTextArea_log.append(this.log("public exponent = ", pubKey));       
        jTextArea_log.append(this.log("modulo =  ", mod));       
        jTextArea_log.append("verify = (" + messageIn + " ^ " + pubKey + ") mod" + mod + " = " + messageEncrypted + "\n\n");
        jTextArea_log.append(this.log("encrypted message =  ", messageEncrypted) + "\n-------- End Encryption --------\n\n");       
    }//GEN-LAST:event_jButton_encryptionActionPerformed

    private void jButton_decryptionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_decryptionActionPerformed
        String privateKey = jTextField_j_private_key_try.getText();
        String crypted = jLabel_E_message_crypted.getText();
        //long E = Long.parseLong(crypted);
        BigInteger J = new BigInteger(privateKey);
        BigInteger P = this.cypher(crypted, J, n);
        String messageDecrypted = String.valueOf(P);
        jLabel_P_message_decrypted.setText(messageDecrypted);
        String privKey = String.valueOf(J);
        String mod = String.valueOf(n);
        jTextArea_log.append("------- Begin Decryption -------\n\n");       
        jTextArea_log.append(this.log("encrypted message = ", crypted));       
        jTextArea_log.append(this.log("private exponent = ", privKey));       
        jTextArea_log.append(this.log("modulo =  ", mod)); 
        jTextArea_log.append("verify = (" + crypted + " ^ " + privKey + ") mod" + mod + " = " + messageDecrypted + "\n\n");
        jTextArea_log.append(this.log("decrypted message =  ", messageDecrypted) + "\n-------- End Decryption --------\n\n");
    }//GEN-LAST:event_jButton_decryptionActionPerformed

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
    private javax.swing.JButton jButton_decryption;
    private javax.swing.JButton jButton_encryption;
    private javax.swing.JButton jButton_generate;
    private javax.swing.JLabel jLabel_E_message_crypted;
    private javax.swing.JLabel jLabel_P_message_decrypted;
    private javax.swing.JLabel jLabel_RSA;
    private javax.swing.JLabel jLabel_decryption;
    private javax.swing.JLabel jLabel_encryption;
    private javax.swing.JLabel jLabel_j_private_key;
    private javax.swing.JLabel jLabel_k_exponent;
    private javax.swing.JLabel jLabel_log;
    private javax.swing.JLabel jLabel_message;
    private javax.swing.JLabel jLabel_message_decryption;
    private javax.swing.JLabel jLabel_message_encrypte;
    private javax.swing.JLabel jLabel_n_modulo;
    private javax.swing.JLabel jLabel_nombre_de_bits1;
    private javax.swing.JLabel jLabel_private_key;
    private javax.swing.JLabel jLabel_private_key_try;
    private javax.swing.JLabel jLabel_public_key;
    private javax.swing.JPanel jPanel_decryption;
    private javax.swing.JPanel jPanel_encryption;
    private javax.swing.JPanel jPanel_generate;
    private javax.swing.JPanel jPanel_log;
    private javax.swing.JPanel jPanel_message_decryption;
    private javax.swing.JPanel jPanel_message_encrypte;
    private javax.swing.JPanel jPanel_private_key;
    private javax.swing.JPanel jPanel_public_key;
    private javax.swing.JScrollPane jScrollPane_log;
    private javax.swing.JTextArea jTextArea_log;
    private javax.swing.JTextField jTextField_P_message_plain;
    private javax.swing.JTextField jTextField_RSA;
    private javax.swing.JTextField jTextField_j_private_key_try;
    // End of variables declaration//GEN-END:variables
}
