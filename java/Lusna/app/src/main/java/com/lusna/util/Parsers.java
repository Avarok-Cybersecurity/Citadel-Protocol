package com.lusna.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Parsers {
    public static Optional<InetAddress> tryParseAddr(String addr) {
        try {
            return Optional.of(InetAddress.getByName(addr));
        } catch (UnknownHostException e) {
            return Optional.empty();
        }
    }
    
    public static Optional<List<InetAddress>> mapIpsToList(List<String> ips_raw) {
        ArrayList<InetAddress> ret = new ArrayList<>(ips_raw.size());
        for (String ip : ips_raw) {
            try {
                ret.add(InetAddress.getByName(ip));
            } catch (Exception e) {
                return Optional.empty();
            }
        }

        return Optional.of(ret);
    }
}
