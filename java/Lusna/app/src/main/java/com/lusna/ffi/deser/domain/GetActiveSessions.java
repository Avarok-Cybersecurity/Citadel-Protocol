package com.lusna.ffi.deser.domain;

import androidx.annotation.NonNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.DomainSpecificResponseType;
import com.lusna.ffi.Ticket;
import com.lusna.util.Iterators;
import com.lusna.util.Parsers;

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

// usernames: Vec<String>,
// cids: Vec<u64>,
// ips: Vec<String>,
// is_personals: Vec<bool>,
// runtime_sec: Vec<u64>
public class GetActiveSessions implements DomainSpecificResponse {
    public List<String> usernames;
    public List<Long> cids;
    public List<InetAddress> ips;
    public List<Boolean> is_personals;
    public List<Long> runtime_secs;

    @Override
    public DomainSpecificResponseType getType() {
        return DomainSpecificResponseType.GetActiveSessions;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return Optional.empty();
    }

    @Override
    public Optional<String> getMessage() {
        return Optional.empty();
    }

    @Override
    public Optional<DomainSpecificResponse> deserializeFrom(JsonNode node) {
        JsonNode usernames_node = node.findValue("usernames");
        List<String> usernames = Iterators.iterToStream(usernames_node.iterator()).map(JsonNode::textValue).collect(Collectors.toList());

        JsonNode cids_node = node.findValue("cids");
        List<Long> cids = Iterators.iterToStream(cids_node.iterator()).map(JsonNode::longValue).collect(Collectors.toList());

        JsonNode ips_node = node.findValue("ips");
        List<String> ips_raw = Iterators.iterToStream(ips_node.iterator()).map(JsonNode::textValue).collect(Collectors.toList());

        Optional<List<InetAddress>> ips_opt = Parsers.mapIpsToList(ips_raw);

        if (!ips_opt.isPresent()) {
            return Optional.empty();
        }

        List<InetAddress> ips = ips_opt.get();

        JsonNode ispersonals_node = node.findValue("is_personals");
        List<Boolean> is_personals = Iterators.iterToStream(ispersonals_node.iterator()).map(JsonNode::booleanValue).collect(Collectors.toList());

        JsonNode runtimesecs_node = node.findValue("runtime_sec");
        List<Long> runtimesec_dates = Iterators.iterToStream(runtimesecs_node.iterator()).map(JsonNode::longValue).collect(Collectors.toList());

        if (cids.size() != usernames.size() || cids.size() != ips.size() || cids.size() != is_personals.size() || cids.size() != runtimesec_dates.size()) {
            return Optional.empty();
        } else {
            this.usernames = usernames;
            this.cids = cids;
            this.ips = ips;
            this.is_personals = is_personals;
            this.runtime_secs = runtimesec_dates;
            return Optional.of(this);
        }
    }

    public Optional<SessionView> getAccountByIndex(int index) {
        return index < this.cids.size() ? Optional.of(new SessionView(index)) : Optional.empty();
    }

    public Optional<SessionView> getAccountByCID(long cid) {
        for (int idx = 0; idx < this.cids.size(); idx++) {
            if (this.cids.get(idx) == cid) {
                return Optional.of(new SessionView(idx));
            }
        }

        return Optional.empty();
    }

    public Optional<SessionView> getAccountByUsername(String username) {
        for (int idx = 0; idx < this.usernames.size(); idx++) {
            if (this.usernames.get(idx).equals(username)) {
                return Optional.of(new SessionView(idx));
            }
        }

        return Optional.empty();
    }

    public class SessionView {
        private long cid;
        private String username;
        private InetAddress ip;
        private boolean is_personal;
        private long runtime_seconds;

        private SessionView(int idx) {
            this.cid = cids.get(idx);
            this.username = usernames.get(idx);
            this.ip = ips.get(idx);
            this.is_personal = is_personals.get(idx);
            this.runtime_seconds = runtime_secs.get(idx);
        }

        @NonNull
        @Override
        public String toString() {
            return "CID: " + this.getCID() + " | Username: " + this.getUsername() + " | IP: " + this.getInetAddress() + " | Is personal: " + this.isPersonal() + " | Runtime (s): " + this.getRuntimeSeconds();
        }

        public long getCID() {
            return cid;
        }

        public String getUsername() {
            return username;
        }

        public InetAddress getInetAddress() {
            return ip;
        }

        public boolean isPersonal() {
            return is_personal;
        }

        public long getRuntimeSeconds() {
            return runtime_seconds;
        }
    }
}
