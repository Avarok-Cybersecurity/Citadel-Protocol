package com.lusna.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class Parsers {
    public static Optional<InetAddress> tryParseAddr(String addr) {
        try {
            return Optional.of(InetAddress.getByName(addr));
        } catch (UnknownHostException e) {
            return Optional.empty();
        }
    }

    /*
    takes a list of R's, and converts them to T's via the supplied function. The function may throw an exception, in which case,
    empty is returned (upon first exception)
 */
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
