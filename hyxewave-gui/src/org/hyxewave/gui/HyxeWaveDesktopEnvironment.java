/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.hyxewave.gui;

import io.vertx.core.Vertx;
import org.hyxewave.connect.AsyncLoopbackClient;
import org.hyxewave.util.Constants;
import org.hyxewave.util.DaemonParser;
import org.jdesktop.swingx.border.DropShadowBorder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author nologik
 */
public class HyxeWaveDesktopEnvironment extends JFrame implements ComponentListener {

    private static final ImageIcon greenCheck = new ImageIcon(new ImageIcon(Constants.GREEN_CHECK).getImage().getScaledInstance(48, 48, Image.SCALE_SMOOTH));
    public static DropShadowBorder shadow = new DropShadowBorder();
    public static HyxeWaveDesktopEnvironment window;
    public static Icon TAB_ICON_HOME = new ImageIcon(new ImageIcon(Constants.TAB_HOME).getImage().getScaledInstance(32, 32, Image.SCALE_SMOOTH));
    public JButton jButton1;
    public JCheckBoxMenuItem jCheckBoxMenuItem1;
    public JComboBox<String> jComboBox1;
    public JDesktopPane jDesktopPane1;
    public JLabel jLabel1;
    public JLabel jLabel2;
    public JLabel jLabel3;
    public JLabel jLabel4;
    public JLabel jLabel5;
    public JMenu jMenu1;
    public JMenu jMenu2;
    public JMenu jMenu3;
    public JMenuBar jMenuBar1;
    public JMenuItem jMenuItem1;
    public JPanel jPanel1;
    public JPanel jPanel2;
    public JPasswordField jPasswordField1;
    public JTabbedPane jTabbedPane1;
    public JTextField jTextField1;
    public JTextField jTextField2;
    public JProgressBar jProgressBar1;
    GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
    private volatile int draggedAtX, draggedAtY;
    private boolean isDone = false;
    private boolean isFullScreen = false;
    private AsyncLoopbackClient client;
    private Vertx vertx;

    /**
     * Creates new form ComsUI
     */
    public HyxeWaveDesktopEnvironment() {
        initComponents();
        this.client = new AsyncLoopbackClient(this);
        create_session_tab(null, null); //development
        this.jTabbedPane1.setSelectedIndex(0);
    }

    public static void main(String[] args) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
            Logger.getLogger(HyxeWaveDesktopEnvironment.class.getName()).log(Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        Toolkit.getDefaultToolkit().setDynamicLayout(false);
        SwingUtilities.invokeLater(() -> {

            window = new HyxeWaveDesktopEnvironment();
            window.setMinimumSize(new Dimension(1000, 550));
            window.rootPane.setDoubleBuffered(true);
            window.setSize(new Dimension(1427, 776));

            //JLabel picLabel = new JLabel(new ImageIcon(bg));
            //picLabel.setLayout(null);
            //picLabel.setBounds(8, 8, window.jPanel1.getWidth() - 16, window.jPanel1.getHeight() - 16);
            //picLabel.setOpaque(false);
            //picLabel.setBackground(new Color(30, 30, 30, 150));
            //window.jPanel2.setBackground(new Color(0,0,0,125));
            //JPanel login
            shadow.setShadowColor(Color.BLACK);
            //shadow.setCornerSize(10);
            shadow.setShadowOpacity(0.8f);
            shadow.setShadowSize(8);
            shadow.setShowLeftShadow(true);
            shadow.setShowRightShadow(true);
            shadow.setShowBottomShadow(true);
            shadow.setShowTopShadow(true);
            //window.rootPane.setBorder(shadow);

            setObjectInCenterRelativeTo(window.jPanel2, window.jDesktopPane1);

            window.jPanel1.repaint();
            centreWindow(window);
            Dimension desktopSize = window.jDesktopPane1.getSize();
            Dimension loginSize = window.jPanel1.getSize();
            int x = (desktopSize.width - loginSize.width) / 2;
            int y = (desktopSize.height - loginSize.height) / 2;
            window.jPanel1.setLocation(x, y);


            //window.jScrollPane1.setLayout(null);

            window.setVisible(true);
        });
    }

    public static void setObjectInCenterRelativeTo(JComponent obj, JComponent container) {
        Dimension containerSize = container.getSize();
        Dimension innerObjectSize = obj.getSize();
        int x = (containerSize.width - innerObjectSize.width) / 2;
        int y = (containerSize.height - innerObjectSize.height) / 2;
        obj.setLocation(x, y);
        obj.repaint();
    }

    public static void centerPanel(JPanel panel, JDesktopPane pane) {
        Dimension desktopSize = pane.getSize();
        Dimension loginSize = panel.getSize();

        int x = (desktopSize.width - loginSize.width) / 2;
        int y = (desktopSize.height - loginSize.height) / 2;
        panel.setLocation(x, y);
    }

    public static void centreWindow(Window frame) {
        Dimension dimension = Toolkit.getDefaultToolkit().getScreenSize();
        int x = (int) ((dimension.getWidth() - frame.getWidth()) / 2);
        int y = (int) ((dimension.getHeight() - frame.getHeight()) / 2);
        frame.setLocation(x, y);
    }

    public void do_connect(String username, String password, String server_ip, int security_level) {
        if (username.isEmpty() || password.isEmpty() || server_ip.isEmpty()) {
            new Thread(() -> {
                JOptionPane.showMessageDialog(this.jDesktopPane1, "The information you have entered is incomplete. Please fill out all the required fields", "Invalid Information", JOptionPane.ERROR_MESSAGE);
            }).start();

            return;
        }

        long eid = Math.abs(new SecureRandom().nextLong());
        System.out.println("Generated EID " + eid);
        String prepared_data = "[u]" + username + "[/u][p]" + password + "[/p][ip]" + server_ip + "[/ip][sec]" + security_level + "[/sec][eid]" + eid + "[/eid]";
        this.client.send(AsyncLoopbackClient.Command.CONNECT, prepared_data, eid);
        this.setLoginPanelFrozen(true);
        this.jProgressBar1.setIndeterminate(true);
    }

    private void setLoginPanelFrozen(boolean value) {
        value = !value;
        this.jTextField1.setEnabled(value);
        this.jTextField2.setEnabled(value);
        this.jPasswordField1.setEnabled(value);
        this.jComboBox1.setEnabled(value);
        this.jButton1.setEnabled(value);
    }

    private void create_session_tab(DaemonParser.DaemonPacket packet, Vertx vertx) {
        if (packet == null) {
            VirtualDesktop vd = new VirtualDesktop(null, this.jTabbedPane1, null);
            return;
        }
        VirtualDesktop vd = new VirtualDesktop(packet.sid, this.jTabbedPane1, vertx);
        vd.flashTab(true);
    }

    public void onSignalReceived(DaemonParser.DaemonPacket packet, Vertx vertx) {
        if (vertx == null) {
            this.vertx = vertx;
        }

        if (packet.isValid) {
            var vd = VirtualDesktop.getVirtualDesktopBySID(packet.sid);
            if (vd != null) {
                vd.handleSignal(packet, vertx);
            } else {
                System.err.println("[HyxeWaveDesktopEnvironment] Unable to find SID " + packet.sid + "; dropping packet");
            }
        }
    }

    public void onResponseReceived(DaemonParser.DaemonPacket packet, Vertx vertx, boolean timeout) {
        if (vertx == null) {
            this.vertx = vertx;
        }

        this.setLoginPanelFrozen(false);
        this.jProgressBar1.setIndeterminate(false);
        new Thread(() -> {
            if (timeout) {
                JOptionPane.showInternalMessageDialog(this.jDesktopPane1, "We were unable to connect to the local daemon or server. Please try again later", "Timeout", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (packet.isValid) {
                switch (packet.statusCode) {
                    case Constants.DO_CONNECT_SUCCESS:
                        System.out.println("CONNECT SUCCESS! Session ID: " + packet.sid);
                        new Thread(() -> {
                            JOptionPane.showInternalMessageDialog(this.jDesktopPane1, "Login Success! Confirm to enter your VHEDE session\n\n\nSID: " + packet.sid, "Virtual HyperEncrypted Desktop Environment", JOptionPane.PLAIN_MESSAGE, greenCheck);
                            //this.jTextField1.setText("");
                            //this.jTextField2.setText("");
                            //this.jPasswordField1.setText("");

                            this.create_session_tab(packet, vertx);
                        }).start();
                        break;

                    case Constants.DO_CONNECT_FAILURE:
                        System.out.println("CONNECT FAILURE!");
                        new Thread(() -> {
                            JOptionPane.showInternalMessageDialog(this.jDesktopPane1, "Please ensure your credentials are valid and that you have an active connection to the server", "Error Connecting", JOptionPane.ERROR_MESSAGE);
                        }).start();
                        break;

                    default:
                        System.err.println("Invalid status code " + packet.statusCode);
                }
            }
        }).start();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane1 = new JTabbedPane();


        jDesktopPane1 = new JDesktopPane();
        ImageIcon green_check = new ImageIcon(new ImageIcon(Constants.HEART).getImage().getScaledInstance(19, 19, Image.SCALE_SMOOTH));
        Image bg = Toolkit.getDefaultToolkit().getImage(Constants.JPANEL_BG).getScaledInstance(464, 258, Image.SCALE_SMOOTH);

        jPanel1 = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {

                Graphics2D graphics = (Graphics2D) g;
                g.drawImage(bg, 8, 24, null);
                g.setColor(Color.BLACK);
                g.fillRect(8, 8, 464, 16);
                //repaint();
                Dimension arcs = new Dimension(15, 15); //Border corners arcs {width,height}, change this to whatever you want

                graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                //Draws the rounded panel with borders.
                graphics.setColor(new Color(228, 243, 253, 180));
                graphics.fillRoundRect(jPanel2.getX(), jPanel2.getY(), jPanel2.getWidth(), jPanel2.getHeight(), arcs.width, arcs.height);
                graphics.fillRoundRect(jLabel5.getX(), jLabel5.getY(), jLabel5.getWidth(), jLabel5.getHeight(), arcs.width, arcs.height);
                graphics.setColor(new Color(228, 243, 253, 90));
                graphics.fillRoundRect(0, 0, jPanel1.getWidth(), jPanel1.getHeight(), arcs.width, arcs.height);
            }
        };
        Dimension desktopSize = jDesktopPane1.getSize();
        Dimension loginSize = jPanel1.getSize();
        int x = (desktopSize.width - loginSize.width) / 2;
        int y = (desktopSize.height - loginSize.height) / 2;
        jPanel1.setLocation(x, y);
        jPanel1.repaint();
        jLabel5 = new JLabel();
        jPanel2 = new JPanel();
        jLabel1 = new JLabel();
        jTextField1 = new JTextField();
        jLabel2 = new JLabel();
        jTextField2 = new JTextField();
        jLabel3 = new JLabel();
        jPasswordField1 = new JPasswordField();
        jComboBox1 = new JComboBox<>();
        jLabel4 = new JLabel();
        jButton1 = new JButton();
        jMenuBar1 = new JMenuBar();
        jMenu1 = new JMenu();
        jMenuItem1 = new JMenuItem();
        jMenu2 = new JMenu();
        jCheckBoxMenuItem1 = new JCheckBoxMenuItem();
        jMenu3 = new JMenu();
        jProgressBar1 = new JProgressBar();

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setTitle("HyxeWave| VHEDE Client"); // NOI18N
        setBackground(new Color(102, 102, 102));
        addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            public void mouseDragged(java.awt.event.MouseEvent evt) {
                formMouseDragged(evt);
            }
        });
        addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                formMousePressed(evt);
            }

            public void mouseReleased(java.awt.event.MouseEvent evt) {
                formMouseReleased(evt);
            }
        });
        addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                formKeyPressed(evt);
            }
        });

        jTabbedPane1.setName("jTabbedPane1"); // NOI18N

        jDesktopPane1.setName("jDesktopPane1"); // NOI18N
        jDesktopPane1.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentResized(java.awt.event.ComponentEvent evt) {
                jDesktopPane1ComponentResized(evt);
            }
        });
        jDesktopPane1.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());


        jPanel1.setBackground(new Color(0, 0, 0));
        jPanel1.setBorder(shadow);
        jPanel1.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        jPanel1.setName("jPanel1"); // NOI18N
        jPanel1.setOpaque(false);
        jPanel1.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel5.setFont(new Font("Calibri", 1, 22)); // NOI18N
        jLabel5.setHorizontalAlignment(SwingConstants.CENTER);
        jLabel5.setText("HyxeWave | Virtual Desktop"); // NOI18N
        jLabel5.setVerticalAlignment(SwingConstants.BOTTOM);
        jLabel5.setAlignmentY(0.0F);
        jLabel5.setBorder(shadow);
        jLabel5.setHorizontalTextPosition(SwingConstants.CENTER);
        jLabel5.setName("jLabel5"); // NOI18N
        jPanel1.add(jLabel5, new org.netbeans.lib.awtextra.AbsoluteConstraints(100, 20, 290, -1));

        jPanel2.setBorder(shadow);
        jPanel2.setName("jPanel2"); // NOI18N
        jPanel2.setOpaque(false);
        jPanel2.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentResized(java.awt.event.ComponentEvent evt) {
                jPanel2ComponentResized(evt);
            }
        });
        jPanel2.setLayout(null);

        jLabel1.setFont(new Font("Tahoma", 1, 12)); // NOI18N
        jLabel1.setText("Server:"); // NOI18N
        jLabel1.setName("jLabel1"); // NOI18N
        jPanel2.add(jLabel1);
        jLabel1.setBounds(20, 20, 50, 20);

        jTextField1.setText(Constants.MAINFRAME_SERVER);
        jTextField1.setCaretPosition(0);
        jTextField1.setName("jTextField1"); // NOI18N
        jPanel2.add(jTextField1);
        jTextField1.setBounds(100, 20, 170, 26);

        jLabel2.setFont(new Font("Tahoma", 1, 12)); // NOI18N
        jLabel2.setText("Username:"); // NOI18N
        jLabel2.setName("jLabel2"); // NOI18N
        jPanel2.add(jLabel2);
        jLabel2.setBounds(20, 50, 70, 20);

        jTextField2.setName("jTextField2"); // NOI18N
        jPanel2.add(jTextField2);
        jTextField2.setBounds(100, 50, 170, 26);

        jLabel3.setFont(new Font("Tahoma", 1, 12)); // NOI18N
        jLabel3.setText("Password:"); // NOI18N
        jLabel3.setName("jLabel3"); // NOI18N
        jPanel2.add(jLabel3);
        jLabel3.setBounds(20, 80, 62, 20);

        jPasswordField1.setName("jPasswordField1"); // NOI18N
        jPanel2.add(jPasswordField1);
        jPasswordField1.setBounds(100, 80, 170, 26);

        jComboBox1.setModel(new DefaultComboBoxModel<>(new String[]{"Low (obsolete)", "Medium", "High", "Ultra", "Divine"}));
        jComboBox1.setSelectedIndex(2);
        jComboBox1.setName("jComboBox1"); // NOI18N
        jPanel2.add(jComboBox1);
        jComboBox1.setBounds(100, 110, 170, 26);

        jLabel4.setFont(new Font("Tahoma", 1, 12)); // NOI18N
        jLabel4.setText("Security:"); // NOI18N
        jLabel4.setName("jLabel4"); // NOI18N
        jPanel2.add(jLabel4);
        jLabel4.setBounds(20, 110, 70, 20);

        jButton1.setText("Connect"); // NOI18N
        jButton1.setName("jButton1"); // NOI18N
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        jButton1.setIcon(green_check);

        jPanel2.add(jButton1);
        jButton1.setBounds(20, 140, 250, 30);

        jPanel1.add(jPanel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(100, 80, 290, 190));

        jDesktopPane1.add(jPanel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 120, 480, 290));

        jTabbedPane1.addTab("Home", TAB_ICON_HOME, jDesktopPane1); // NOI18N

        jMenuBar1.setBackground(new Color(51, 51, 51));
        jMenuBar1.setName("jMenuBar1"); // NOI18N

        jMenu1.setText("File"); // NOI18N
        jMenu1.setName("jMenu1"); // NOI18N

        jMenuItem1.setAccelerator(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_C, java.awt.event.InputEvent.CTRL_MASK));
        jMenuItem1.setText("Terminate"); // NOI18N
        jMenuItem1.setName("jMenuItem1"); // NOI18N
        jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem1ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem1);

        jMenuBar1.add(jMenu1);

        jMenu2.setText("Edit"); // NOI18N
        jMenu2.setName("jMenu2"); // NOI18N

        jCheckBoxMenuItem1.setAccelerator(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F, java.awt.event.InputEvent.ALT_MASK | java.awt.event.InputEvent.CTRL_MASK));
        jCheckBoxMenuItem1.setText("Fullscreen Mode"); // NOI18N
        jCheckBoxMenuItem1.setName("jCheckBoxMenuItem1"); // NOI18N
        jCheckBoxMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxMenuItem1ActionPerformed(evt);
            }
        });
        jMenu2.add(jCheckBoxMenuItem1);

        jMenuBar1.add(jMenu2);

        jMenu3.setText("Help"); // NOI18N
        jMenu3.setName("jMenu3"); // NOI18N
        jMenuBar1.add(jMenu3);

        jProgressBar1.setVisible(true);
        jProgressBar1.setMaximumSize(new Dimension(150, 30));
        jMenuBar1.add(Box.createHorizontalGlue());
        jMenuBar1.add(jProgressBar1);

        setJMenuBar(jMenuBar1);


        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(jTabbedPane1)
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(jTabbedPane1)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem1ActionPerformed
        Runtime.getRuntime().exit(0);
    }//GEN-LAST:event_jMenuItem1ActionPerformed

    private void formMouseDragged(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_formMouseDragged
        if (!isFullScreen) {
            try {
                window.setOpacity(0.9f);
                setLocation(evt.getX() - draggedAtX + getLocation().x,
                        evt.getY() - draggedAtY + getLocation().y);
            } catch (IllegalComponentStateException e) {

            }
        }
    }//GEN-LAST:event_formMouseDragged

    private void formMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_formMousePressed
        draggedAtX = evt.getX();
        draggedAtY = evt.getY();
    }//GEN-LAST:event_formMousePressed

    private void jCheckBoxMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxMenuItem1ActionPerformed
        if (jCheckBoxMenuItem1.isSelected()) {
            if (gd.isFullScreenSupported()) {
                gd.setFullScreenWindow(window);
                //window.rootPane.setBorder(null);
                window.isFullScreen = true;
            } else {
                JOptionPane.showInternalMessageDialog(window, "Fullscreen mode not supported on " + gd.getIDstring(), "Error", JOptionPane.ERROR_MESSAGE);
                window.isFullScreen = false;
            }
        } else {
            gd.setFullScreenWindow(null);
            //window.rootPane.setBorder(shadow);
            window.isFullScreen = false;
        }
    }//GEN-LAST:event_jCheckBoxMenuItem1ActionPerformed

    private void formKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_formKeyPressed

    }//GEN-LAST:event_formKeyPressed

    private void formMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_formMouseReleased
        window.setOpacity(1.0f);
    }//GEN-LAST:event_formMouseReleased

    private void jDesktopPane1ComponentResized(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_jDesktopPane1ComponentResized
        Dimension desktopSize = this.jDesktopPane1.getSize();
        Dimension loginSize = this.jPanel1.getSize();

        this.jDesktopPane1.setLayout(null);
        this.jPanel1.setLayout(null);
        int x = (desktopSize.width - loginSize.width) / 2;
        int y = (desktopSize.height - loginSize.height) / 2;
        this.jPanel1.setLocation(x, y);        // TODO add your handling code here:
    }//GEN-LAST:event_jDesktopPane1ComponentResized

    private void jPanel2ComponentResized(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_jPanel2ComponentResized

    }//GEN-LAST:event_jPanel2ComponentResized

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        new Thread(() -> {
            try {
                String clientID = this.jTextField2.getText();
                String password = new String(this.jPasswordField1.getPassword());
                String server = this.jTextField1.getText();
                int securitySetting = this.jComboBox1.getSelectedIndex();
                System.out.println("Server: " + server + "\nClientID: " + clientID + "\nPassword: " + password + " with security setting " + securitySetting);
                do_connect(clientID, password, server, securitySetting);
                /*String response = LoginHandler.doLoginFromJDesktopEnv(client, clientID, password, securitySetting);
                if (!response.equals("Login success!")) {
                    JOptionPane.showMessageDialog(null, response, "Error Connecting", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                window.jTabbedPane1.add(clientID + " (" + client + ")", LoginHandler.loadClientIntoDesktop(clientID));
*/
            } catch (IllegalArgumentException ex) {
                Logger.getLogger(HyxeWaveDesktopEnvironment.class.getName()).log(Level.SEVERE, null, ex);
            }

        }).start();


        this.jButton1.setSelected(false);
    }//GEN-LAST:event_jButton1ActionPerformed

    /**
     * Invoked when the component's size changes.
     *
     * @param e the event to be processed
     */
    @Override
    public void componentResized(ComponentEvent e) {
        this.repaint();
    }

    /**
     * Invoked when the component's position changes.
     *
     * @param e the event to be processed
     */
    @Override
    public void componentMoved(ComponentEvent e) {

    }

    /**
     * Invoked when the component has been made visible.
     *
     * @param e the event to be processed
     */
    @Override
    public void componentShown(ComponentEvent e) {

    }

    /**
     * Invoked when the component has been made invisible.
     *
     * @param e the event to be processed
     */
    @Override
    public void componentHidden(ComponentEvent e) {

    }


    // End of variables declaration//GEN-END:variables
}
