import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/utils.dart';

import '../u64.dart';

class GetAccountsResponse extends DomainSpecificResponse {
  final List<u64> cids;
  final List<String> usernames;
  final List<String> full_names;
  final List<bool> is_personals;
  final List<String> creation_dates;

  GetAccountsResponse._(this.cids, this.usernames, this.full_names, this.is_personals, this.creation_dates);

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<StandardTicket> getTicket() {
    return Optional.empty();
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.GetAccounts;
  }

  @override
  bool isFcm() {
    return false;
  }

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      List<u64> cids = typeCastMap(infoNode["cids"], transform: u64.tryFrom);
      List<String> usernames= typeCastMap(infoNode["usernames"]);
      List<String> full_names = typeCastMap(infoNode["full_names"]);
      List<bool> is_personals = typeCastMap(infoNode["is_personals"]);
      List<String> creation_dates = typeCastMap(infoNode["creation_dates"]);

      if (!sameLengths([cids, usernames, full_names, is_personals, creation_dates])) {
        return Optional.empty();
      }

      return Optional.of(GetAccountsResponse._(cids, usernames, full_names, is_personals, creation_dates));
    } catch(_) {
      return Optional.empty();
    }
  }

}