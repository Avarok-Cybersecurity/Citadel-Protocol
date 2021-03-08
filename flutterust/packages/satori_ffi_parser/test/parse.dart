import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/dsr/deregister_response.dart';
import 'package:satori_ffi_parser/types/dsr/disconnect_response.dart';
import 'package:satori_ffi_parser/types/dsr/get_accounts_response.dart';
import 'package:satori_ffi_parser/types/dsr/get_active_sessions.dart';
import 'package:satori_ffi_parser/types/dsr/peer_list.dart';
import 'package:satori_ffi_parser/types/dsr/register_response.dart';
import 'package:satori_ffi_parser/types/fcm_ticket.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/domain_specific.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/root/hybrid.dart';
import 'package:satori_ffi_parser/types/root/kernel_shutdown.dart';
import 'package:satori_ffi_parser/types/root/message.dart';
import 'package:satori_ffi_parser/types/root/node_message.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:satori_ffi_parser/types/virtual_connection_type.dart';
import 'package:test/test.dart';


void main() {
  group('parsers', () {
    print("Starting test");

    test('u64 impl', () {
      assert(u64.tryFrom("0").isPresent);
      assert(u64.tryFrom("18446744073709551615").isPresent);
      assert(u64.tryFrom("18446744073709551616").isEmpty);
      assert(u64.zero == u64.zero);
      assert(u64.zero < u64.one);
      assert(u64.one > u64.zero);
      assert(u64.one != u64.zero);
      assert(u64.from(999) > u64.from(990));
      assert(u64.from(990) < u64.from(999));
      assert(u64.from(990) != u64.from(999));
      assert(u64.from(999) == u64.from(999));
    });

    test('ticket impl', () {
      StandardTicket stdTicket = StandardTicket(u64.two);
      StandardTicket stdTicket2 = StandardTicket(u64.two);
      FcmTicket fcmTicket = FcmTicket(u64.one, u64.two, u64.MAX);
      FcmTicket fcmTicket2 = FcmTicket(u64.one, u64.two, u64.MAX);
      expect(fcmTicket.hashCode, fcmTicket2.hashCode);
      assert(stdTicket.eq(stdTicket2));
      assert((stdTicket as Ticket).eq(stdTicket2 as Ticket));
      assert((stdTicket as Ticket).eq(stdTicket2));

      assert(fcmTicket as Ticket == fcmTicket2 as Ticket);
      assert(!(fcmTicket as Ticket).eq(stdTicket as Ticket));
    });

    test('fcm-message', () {
      String str = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"FcmMessage\",\"fcm_ticket\":{\"source_cid\":\"123\",\"target_cid\":\"456\",\"ticket\":\"789\"},\"message\":\"SGVsbG8sIHdvcmxkIQ==\"}}";
      print("Parsing: " + str);
      KernelResponse resp = FFIParser.tryFrom(str).value;
      expect(resp.getMessage().value, "Hello, world!");
      FcmTicket ticket = resp.getTicket().value;
      expect(ticket.sourceCid, u64.tryFrom("123").value);
      expect(ticket.targetCid, u64.tryFrom("456").value);
      expect(ticket.ticket, u64.tryFrom("789").value);
    });

    test('fcm-ticket', () {
      String str = "{\"type\":\"ResponseFcmTicket\",\"info\":{\"source_cid\":\"123\",\"target_cid\":\"456\",\"ticket\":\"789\"}}";
      print("Parsing: " + str);
      KernelResponse resp = FFIParser.tryFrom(str).value;

      FcmTicket ticket = resp.getTicket().value;
      expect(ticket.sourceCid, u64.tryFrom("123").value);
      expect(ticket.targetCid, u64.tryFrom("456").value);
      expect(ticket.ticket, u64.tryFrom("789").value);
    });

    test('kernel-shutdown', () {
      String messageTypeExample = "{\"type\":\"KernelShutdown\",\"info\":\"SGVsbG8sIHdvcmxkIQ==\"}";
      print("Parsing: " + messageTypeExample);
      KernelResponse resp = FFIParser.tryFrom(messageTypeExample).value;
      assert(resp is KernelShutdown);
      expect(resp.getMessage().value, "Hello, world!");
      assert(resp.getDSR().isEmpty);
      assert(resp.getTicket().isEmpty);
      print("Success");
    });

    test('message', () {
      String messageTypeExample = "{\"type\":\"Message\",\"info\":\"Asynchronous kernel running. FFI Static is about to be set\"}";
      print("Parsing: " + messageTypeExample);
      KernelResponse resp = FFIParser.tryFrom(messageTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is MessageKernelResponse);
      expect(resp.getMessage().value, "Asynchronous kernel running. FFI Static is about to be set");
      assert(resp.getDSR().isEmpty);
      assert(resp.getTicket().isEmpty);
      print("Success");
    });

    test('hybrid', () {
      String hybridResponseTypeExample = "{\"type\":\"ResponseHybrid\",\"info\":[\"123\", \"Hello world!\"]}";

      print("Parsing: " + hybridResponseTypeExample);
      KernelResponse resp = FFIParser.tryFrom(hybridResponseTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is HybridKernelResponse);
      expect(resp.getMessage().value, "Hello world!");
      assert(resp.getDSR().isEmpty);
      expect(resp.getTicket().value.id, u64.from(123));
      print("Success");
    });

    test('error-std', () {
      String errorTypeExample = "{\"type\":\"Error\",\"info\":[\"10\",\"User nologik.test is already an active session ...\"]}";
      print("Parsing: " + errorTypeExample);
      KernelResponse resp = FFIParser.tryFrom(errorTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is ErrorKernelResponse);
      expect(resp.getMessage().value, "User nologik.test is already an active session ...");
      assert(resp.getDSR().isEmpty);
      expect(resp.getTicket().value.id, u64.from(10));
      print("Success");
    });

    test('fcm-error', () {
      // {"type":"FcmError","info":[{"source_cid":"123","target_cid":"456","ticket":"789"},"SGVsbG8sIHdvcmxkIQ=="]}
      String errorTypeExample = "{\"type\":\"FcmError\",\"info\":[{\"source_cid\":\"123\",\"target_cid\":\"456\",\"ticket\":\"789\"},\"SGVsbG8sIHdvcmxkIQ==\"]}";
      print("Parsing: " + errorTypeExample);
      KernelResponse resp = FFIParser.tryFrom(errorTypeExample, mapBase64Strings: MessageParseMode.UTF8).value;
      assert(resp is ErrorKernelResponse);
      expect(resp.getMessage().value, "Hello, world!");
      assert(resp.getDSR().isEmpty);
      expect(resp.getTicket().value, FcmTicket(u64.from(123), u64.from(456), u64.from(789)));
      print("Success");
    });

    test('error no-ticket', () {
      String errorTypeExample = "{\"type\":\"Error\",\"info\":[\"0\",\"User nologik.test is already an active session ...\"]}";
      print("Parsing: " + errorTypeExample);
      KernelResponse resp = FFIParser.tryFrom(errorTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is ErrorKernelResponse);
      expect(resp.getMessage().value, "User nologik.test is already an active session ...");
      assert(resp.getDSR().isEmpty);
      assert(resp.getTicket().isEmpty);
      print("Success");
    });

    test('node message', () {
      String nodeMessageTypeExample = "{\"type\":\"NodeMessage\",\"info\":[\"10\", \"1\", \"2\", \"3\", \"Hello, message!\"]}";
      print("Parsing: " + nodeMessageTypeExample);
      KernelResponse resp = FFIParser.tryFrom(nodeMessageTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is NodeMessageKernelResponse);
      NodeMessageKernelResponse nResp = resp;
      expect(nResp.cid, u64.one);
      expect(nResp.icid, u64.two);
      expect(nResp.peerCid, u64.tryFrom("3").value);
      expect(nResp.message, "Hello, message!");
      expect(resp.getMessage().value, "Hello, message!");
      assert(resp.getDSR().isEmpty);
      expect(resp.getTicket().value.id, u64.from(10));
      print("Success");
    });

    test('DSR - Register - Failure', () {
      String DSRRegisterTypeExample = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Register\",\"Failure\":[\"2\",\"Invalid username\"]}}";

      print("Parsing: " + DSRRegisterTypeExample);
      KernelResponse resp = FFIParser.tryFrom(DSRRegisterTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      expect(resp.getMessage().value, "Invalid username");
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is RegisterResponse);
      RegisterResponse dResp = resp.getDSR().value;
      assert(!dResp.success);
      expect(dResp.getType(), DomainSpecificResponseType.Register);
      expect(resp.getTicket().value.id, u64.from(2));
      expect(dResp.getTicket().value.id, u64.from(2));
      print("Success");
    });

    test('DSR - Register - Success', () {
      String DSRRegisterTypeExample2 = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Register\",\"Success\":[\"18446744073709551615\",\"Valid username\"]}}";
      print("Parsing: " + DSRRegisterTypeExample2);
      KernelResponse resp = FFIParser.tryFrom(DSRRegisterTypeExample2, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      expect(resp.getMessage().value, "Valid username");
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is RegisterResponse);
      RegisterResponse dResp = resp.getDSR().value;
      assert(dResp.success);

      expect(dResp.getType(), DomainSpecificResponseType.Register);
      assert(resp.getTicket().value.id == u64.tryFrom("18446744073709551615").value);
      print("Success");
    });

    test('DSR - Connect - Failure', () {
      String DSRConnectTypeExample = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Connect\",\"Failure\":[\"2\",\"999\",\"Invalid username\"]}}";

      print("Parsing: " + DSRConnectTypeExample);
      KernelResponse resp = FFIParser.tryFrom(DSRConnectTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      expect(resp.getMessage().value, "Invalid username");
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is ConnectResponse);
      ConnectResponse dResp = resp.getDSR().value;
      assert(!dResp.success);
      expect(dResp.getType(), DomainSpecificResponseType.Connect);
      expect(resp.getTicket().value.id, u64.from(2));
      expect(dResp.getTicket().value.id, u64.from(2));
      expect(dResp.implicated_cid, u64.from(999));
      print("Success");
    });

    test('DSR - Connect - Success', () {
      String DSRConnectTypeExample = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Connect\",\"Success\":[\"2\",\"999\",\"Invalid username\"]}}";

      print("Parsing: " + DSRConnectTypeExample);
      KernelResponse resp = FFIParser.tryFrom(DSRConnectTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      expect(resp.getMessage().value, "Invalid username");
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is ConnectResponse);
      ConnectResponse dResp = resp.getDSR().value;
      assert(dResp.success);
      expect(dResp.getType(), DomainSpecificResponseType.Connect);
      expect(resp.getTicket().value.id, u64.from(2));
      expect(dResp.getTicket().value.id, u64.from(2));
      expect(dResp.implicated_cid, u64.from(999));
      print("Success");
    });

    test('DSR - GetAccounts', () {
      String DSRgetAccounts = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"GetAccounts\",\"cids\":[\"2865279923\",\"2865279924\",\"2865279925\",\"2865279926\"],\"usernames\":[\"nologik.test\",\"nologik.test2\",\"nologik.test3\",\"nologik.test4\"],\"full_names\":[\"thomas braun\",\"thomas braun2\",\"thomas braun3\",\"thomas braun4\"],\"is_personals\":[true,true,true,false],\"creation_dates\":[\"Thu Sep  3 20:43:12 2020\",\"Fri Sep  4 20:40:50 2020\",\"Mon Sep  7 01:22:46 2020\",\"Mon Sep  7 01:47:05 2020\"]}}";

      print("Parsing: " + DSRgetAccounts);
      KernelResponse resp = FFIParser.tryFrom(DSRgetAccounts, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      assert(!resp.getMessage().isPresent);
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is GetAccountsResponse);
      expect(resp.getDSR().value.getType(), DomainSpecificResponseType.GetAccounts);
      assert(!resp.getTicket().isPresent);
      GetAccountsResponse accounts = resp.getDSR().value;
      expect(accounts.cids.length, 4);

      expect(accounts.cids[0], u64.from(2865279923));
      expect(accounts.usernames[0], "nologik.test");
      expect(accounts.full_names[0], "thomas braun");
      expect(accounts.is_personals[0], true);
      expect(accounts.creation_dates[0], "Thu Sep  3 20:43:12 2020");

      expect(accounts.cids[3], u64.from(2865279926));
      expect(accounts.usernames[3], "nologik.test4");
      expect(accounts.full_names[3], "thomas braun4");
      expect(accounts.is_personals[3], false);
      expect(accounts.creation_dates[3], "Mon Sep  7 01:47:05 2020");

      print("Success");

    });


    test('DSR - GetSessions', () {
      String DSRlistSessions = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"GetActiveSessions\",\"usernames\":[\"nologik.test4\", \"nologik.test5\"],\"cids\":[\"2865279926\", \"123456789\"],\"endpoints\":[\"51.81.35.200:25000\", \"51.81.35.201:25001\"],\"is_personals\":[true, false],\"runtime_sec\":[\"8\", \"1000\"]}}";

      print("Parsing: " + DSRlistSessions);
      KernelResponse resp = FFIParser.tryFrom(DSRlistSessions, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      assert(resp.getMessage().isEmpty);
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is GetSessionsResponse);
      GetSessionsResponse dResp = resp.getDSR().value;
      expect(dResp.getType(), DomainSpecificResponseType.GetActiveSessions);
      assert(resp.getTicket().isEmpty);

      expect(dResp.cids.length, 2);

      print("Success");

    });

    test('DSR - Disconnect - HyperLANPeerToHyperLANServer', () {
      String DSRDisconnectTypeExample = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Disconnect\",\"HyperLANPeerToHyperLANServer\":[\"2\",\"999\"]}}";

      print("Parsing: " + DSRDisconnectTypeExample);
      KernelResponse resp = FFIParser.tryFrom(DSRDisconnectTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      assert(resp.getMessage().isEmpty);
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is DisconnectResponse);
      DisconnectResponse dResp = resp.getDSR().value;
      assert(dResp.virtualConnectionType == VirtualConnectionType.HyperLANPeerToHyperLANServer);
      expect(dResp.getType(), DomainSpecificResponseType.Disconnect);
      expect(resp.getTicket().value.id, u64.from(2));
      expect(dResp.getTicket().value.id, u64.from(2));
      expect(dResp.implicated_cid, u64.from(999));
      expect(dResp.peer_cid, u64.zero);
      expect(dResp.icid, u64.zero);
      print("Success");
    });

    test('DSR - Disconnect - HyperLANPeerToHyperLANPeer', () {
      String DSRDisconnectTypeExample = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Disconnect\",\"HyperLANPeerToHyperLANPeer\":[\"2\",\"999\",\"1000\"]}}";

      print("Parsing: " + DSRDisconnectTypeExample);
      KernelResponse resp = FFIParser.tryFrom(DSRDisconnectTypeExample, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      assert(resp.getMessage().isEmpty);
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is DisconnectResponse);
      DisconnectResponse dResp = resp.getDSR().value;
      assert(dResp.virtualConnectionType == VirtualConnectionType.HyperLANPeerToHyperLANPeer);
      expect(dResp.getType(), DomainSpecificResponseType.Disconnect);
      expect(resp.getTicket().value.id, u64.from(2));
      expect(dResp.getTicket().value.id, u64.from(2));
      expect(dResp.implicated_cid, u64.from(999));
      expect(dResp.peer_cid, u64.from(1000));
      expect(dResp.icid, u64.zero);
      print("Success");
    });

    test('DSR - PeerList', () {
      String DSRlistSessions = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"PeerList\",\"cids\":[\"123456789\", \"987654321\"],\"is_onlines\":[true, false],\"ticket\":\"98\"}}";

      print("Parsing: " + DSRlistSessions);
      KernelResponse resp = FFIParser.tryFrom(DSRlistSessions, mapBase64Strings: MessageParseMode.None).value;
      assert(resp is DomainSpecificKernelResponse);
      assert(resp.getMessage().isEmpty);
      assert(resp.getDSR().isPresent);
      assert(resp.getDSR().value is PeerListResponse);
      PeerListResponse dResp = resp.getDSR().value;
      expect(dResp.getType(), DomainSpecificResponseType.PeerList);
      expect(resp.getTicket().value.id, u64.from(98));

      expect(dResp.cids.length, 2);

      print("Success");

    });

    test('DSR - deregister', () {
      String input = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"DeregisterResponse\",\"implicated_cid\":\"456\",\"peer_cid\":\"123\",\"ticket\":\"789\",\"success\":true}}";

      print("Parsing $input");

      KernelResponse kResp = FFIParser.tryFrom(input).value;
      DeregisterResponse dResp = kResp.getDSR().value;

      expect(dResp.implicatedCid, u64.from(456));
      expect(dResp.peerCid, u64.from(123));
      expect(dResp.ticket.value, StandardTicket.from(789));
      expect(dResp.success, true);
    });

  });
}