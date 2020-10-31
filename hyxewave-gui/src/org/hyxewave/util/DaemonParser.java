/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

package org.hyxewave.util;

/**
 * This class handles the parsing of data to help determine what need to be done
 * next()
 */
public class DaemonParser {

    public static DaemonPacket parseInboundData(String data) {
        System.out.println("[DaemonPacketParser] Parsing data: " + data);
        //All inbound data MUST have a status tag as well as the session id (sid)
        if ((data.contains(Constants.Tags.STATUS_OPEN) && data.contains(Constants.Tags.STATUS_CLOSE))
                && (data.contains(Constants.Tags.SID_OPEN) && data.contains(Constants.Tags.SID_CLOSE))) {

            System.out.println("[DaemonPacketParser] Packet is valid. Extracting data...");

            String status = extractDataBetweenTags(data, Constants.Tags.STATUS_OPEN, Constants.Tags.STATUS_CLOSE);
            String sid = extractDataBetweenTags(data, Constants.Tags.SID_OPEN, Constants.Tags.SID_CLOSE);
            String _data = extractDataBetweenTags(data, Constants.Tags.DATA_OPEN, Constants.Tags.DATA_CLOSE);
            String eid = extractDataBetweenTags(data, Constants.Tags.EID_OPEN, Constants.Tags.EID_CLOSE);

            return new DaemonPacket(true, status, sid, _data, eid);
        } else return new DaemonPacket();
    }

    public static String extractDataBetweenTags(String data, String tagOpen, String tagClose) {
        if (data.contains(tagOpen) && data.contains(tagClose)) {
            return data.substring(data.indexOf(tagOpen) + tagOpen.length(), data.indexOf(tagClose));
        } else return "";
    }

    public static class DaemonPacket {
        public boolean isValid; //if false, then no-response received
        public String statusCode;
        public String sid;
        public String data;
        public String eid; //expectancy, for syncing coms between gui and daemon

        public DaemonPacket(boolean isValid, String statusCode, String sid, String data, String eid) {
            this.isValid = isValid;
            this.statusCode = statusCode;
            this.sid = sid;
            this.data = data;
            this.eid = eid;
        }

        public DaemonPacket() {
            this.isValid = false;
        }
    }

}
