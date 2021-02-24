import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/utils.dart';

import '../u64.dart';

class GetAccountsResponse extends DomainSpecificResponse {
  List<u64> cids;
  List<String> usernames;
  List<String> full_names;
  List<bool> is_personals;
  List<String> creation_dates;

  GetAccountsResponse._(List<u64> cids, List<String> usernames, List<String> full_names, List<bool> is_personals, List<String> creation_dates) {
    this.cids = cids;
    this.usernames = usernames;
    this.full_names = full_names;
    this.is_personals = is_personals;
    this.creation_dates = creation_dates;
  }

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<Ticket> getTicket() {
    return Optional.empty();
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.GetAccounts;
  }

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      List<u64> cids = filterMap(infoNode["cids"], transform: u64.tryFrom);
      List<String> usernames= filterMap(infoNode["usernames"]);
      List<String> full_names = filterMap(infoNode["full_names"]);
      List<bool> is_personals = filterMap(infoNode["is_personals"]);
      List<String> creation_dates = filterMap(infoNode["creation_dates"]);

      if (!sameLengths([cids, usernames, full_names, is_personals, creation_dates])) {
        return Optional.empty();
      }

      return Optional.of(GetAccountsResponse._(cids, usernames, full_names, is_personals, creation_dates));
    } on Exception catch(_) {
      return Optional.empty();
    }
  }

}