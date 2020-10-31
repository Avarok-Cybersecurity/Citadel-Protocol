/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

package org.hyxewave.util;

public class Constants {

    public static final String MAINFRAME_SERVER = "fe80::7a2b:cbff:fe1c:7411";

    /**
     * Images
     */
    public static final String JPANEL_BG = System.getProperty("user.home") + "/.HyxeWave/resources/jPanel1_bg.jpg";
    public static final String HEART = System.getProperty("user.home") + "/.HyxeWave/resources/heart.png";
    public static final String GREEN_CHECK = System.getProperty("user.home") + "/.HyxeWave/resources/green_check.png";
    public static final String TAB_SESSION = System.getProperty("user.home") + "/.HyxeWave/resources/tab_session.png";
    public static final String TAB_HOME = System.getProperty("user.home") + "/.HyxeWave/resources/tab_home.png";
    public static final String MENU_MESSAGE = System.getProperty("user.home") + "/.HyxeWave/resources/message.png";
    public static final String MENU_HOME = System.getProperty("user.home") + "/.HyxeWave/resources/home.png";
    public static final String MENU_SETTINGS = System.getProperty("user.home") + "/.HyxeWave/resources/settings.png";
    public static final String MENU_ENCRYPT = System.getProperty("user.home") + "/.HyxeWave/resources/encrypt.png";
    public static final String MENU_TERMINAL = System.getProperty("user.home") + "/.HyxeWave/resources/terminal.png";
    public static final String MENU_LOGOUT = System.getProperty("user.home") + "/.HyxeWave/resources/logout.png";

    public static final String HYXEWAVE_LOGO = System.getProperty("user.home") + "/.HyxeWave/resources/HyxeWaveLogo.png";
    /**
     * End Images
     */

    public static final int DAEMON_PORT = 25023;

    public static final int TIMEOUT = 3333; //The timeout in the rust client is 3000ms, so this gives the program 333 ms to react and alert the GUI


    public static final String ERROR_CONNECTING_TO_LOCAL_SERVICE = "ERR_CONNECT_LOCAL_SERVICE";
    public static final String INVALID_RESPONSE = "EMPTY";

    public static final String DO_CONNECT = "CONNECT";
    public static final String DO_CONNECT_SUCCESS = "CONNECT_SUCCESS";
    public static final String DO_CONNECT_FAILURE = "CONNECT_FAILURE";

    public static final String DO_KEEP_ALIVE_SUCCESS = "KEEP_ALIVE_SUCCESS";
    public static final String DO_KEEP_ALIVE_FAILURE = "KEEP_ALIVE_FAILURE";

    public static final String DO_DISCONNECT = "DISCONNECT";
    public static final String DO_DISCONNECT_SUCCESS = "DISCONNECT_SUCCESS";
    public static final String DO_DISCONNECT_FAILURE = "DISCONNECT_FAILURE";

    public static final String DO_SEND_MESSAGE = "SEND_MESSAGE";
    public static final String DO_SEND_MESSAGE_SUCCESS = "SEND_MESSAGE_SUCCESS";
    public static final String DO_SEND_MESSAGE_FAILURE = "SEND_MESSAGE_FAILURE";

    public static final String DO_SEND_FILE = "SEND_FILE";
    public static final String DO_SEND_FILE_SUCCESS = "SEND_FILE_SUCCESS";
    public static final String DO_SEND_FILE_FAILURE = "SEND_FILE_FAILURE";

    public static final String DO_CONFIRM_RECEIVE_FILE = "CONFIRM_RECEIVE_FILE";
    public static final String DO_CONFIRM_RECEIVE_FILE_SUCCESS = "CONFIRM_RECEIVE_FILE_SUCCESS";
    public static final String DO_CONFIRM_RECEIVE_FILE_FAILURE = "CONFIRM_RECEIVE_FILE_FAILURE";

    public static final int BUF_LEN = 64000;

    public class Tags {
        public static final String STATUS_OPEN = "[status]";
        public static final String STATUS_CLOSE = "[/status]";

        public static final String SID_OPEN = "[sid]";
        public static final String SID_CLOSE = "[/sid]";

        public static final String DATA_OPEN = "[data]";
        public static final String DATA_CLOSE = "[/data]";

        public static final String EID_OPEN = "[eid]";
        public static final String EID_CLOSE = "[/eid]";
    }

}
