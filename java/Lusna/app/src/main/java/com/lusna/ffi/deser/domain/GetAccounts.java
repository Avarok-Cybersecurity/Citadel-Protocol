package com.lusna.ffi.deser.domain;

import android.provider.CalendarContract;

import androidx.annotation.NonNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.DomainSpecificResponseType;
import com.lusna.ffi.Ticket;
import com.lusna.util.Iterators;

import java.util.List;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

//    cids: Vec<u64>,
//    usernames: Vec<String>,
//    full_names: Vec<String>,
//    is_personals: Vec<bool>,
//    creation_dates: Vec<String>
public class GetAccounts implements DomainSpecificResponse {
    public List<Long> cids;
    public List<String> usernames;
    public List<String> full_names;
    public List<Boolean> is_personals;
    public List<String> creation_dates;

    public GetAccounts() {}

    @Override
    public DomainSpecificResponseType getType() {
        return DomainSpecificResponseType.GetAccounts;
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
        JsonNode cids_node = node.findValue("cids");
        List<Long> cids = Iterators.iterToStream(cids_node.iterator()).map(JsonNode::longValue).collect(Collectors.toList());

        JsonNode usernames_node = node.findValue("usernames");
        List<String> usernames = Iterators.iterToStream(usernames_node.iterator()).map(JsonNode::textValue).collect(Collectors.toList());

        JsonNode fullnames_node = node.findValue("full_names");
        List<String> fullnames = Iterators.iterToStream(fullnames_node.iterator()).map(JsonNode::textValue).collect(Collectors.toList());

        JsonNode ispersonals_node = node.findValue("is_personals");
        List<Boolean> is_personals = Iterators.iterToStream(ispersonals_node.iterator()).map(JsonNode::booleanValue).collect(Collectors.toList());

        JsonNode creationdates_node = node.findValue("creation_dates");
        List<String> creation_dates = Iterators.iterToStream(creationdates_node.iterator()).map(JsonNode::textValue).collect(Collectors.toList());

        if (cids.size() != usernames.size() || cids.size() != fullnames.size() || cids.size() != is_personals.size() || cids.size() != creation_dates.size()) {
            return Optional.empty();
        } else {
            this.cids = cids;
            this.usernames = usernames;
            this.full_names = fullnames;
            this.is_personals = is_personals;
            this.creation_dates = creation_dates;

            return Optional.of(this);
        }
    }

    public Optional<AccountView> getAccountByIndex(int index) {
        return index < this.cids.size() ? Optional.of(new AccountView(index)) : Optional.empty();
    }

    public Optional<AccountView> getAccountByCID(long cid) {
        for (int idx = 0; idx < this.cids.size(); idx++) {
            if (this.cids.get(idx) == cid) {
                return Optional.of(new AccountView(idx));
            }
        }

        return Optional.empty();
    }

    public Optional<AccountView> getAccountByUsername(String username) {
        for (int idx = 0; idx < this.usernames.size(); idx++) {
            if (this.usernames.get(idx).equals(username)) {
                return Optional.of(new AccountView(idx));
            }
        }

        return Optional.empty();
    }

    public class AccountView {
        private long cid;
        private String username;
        private String full_name;
        private boolean is_personal;
        private String creation_date;

        private AccountView(int idx) {
            this.cid = cids.get(idx);
            this.username = usernames.get(idx);
            this.full_name = full_names.get(idx);
            this.is_personal = is_personals.get(idx);
            this.creation_date = creation_dates.get(idx);
        }

        public long getCID() {
            return cid;
        }

        public String getUsername() {
            return username;
        }

        public String getFullname() {
            return full_name;
        }

        public boolean isPersonal() {
            return is_personal;
        }

        public String getCreationDate() {
            return creation_date;
        }

        @NonNull
        @Override
        public String toString() {
            return "CID: " + this.cid + " | Username: " + this.username + " | Fullname: " + this.full_name + " | Is personal: " + this.is_personal + " | Creation date: " + this.creation_date;
        }
    }
}
