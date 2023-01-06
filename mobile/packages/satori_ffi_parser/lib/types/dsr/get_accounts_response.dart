import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/utils.dart';

import '../u64.dart';

class GetAccountsResponse extends DomainSpecificResponse {
  final List<u64> cids;
  final List<String> usernames;
  final List<String> fullNames;
  final List<bool> isPersonals;
  final List<String> creationDates;

  GetAccountsResponse._(this.cids, this.usernames, this.fullNames, this.isPersonals, this.creationDates);

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
      List<String> fullNames = typeCastMap(infoNode["full_names"]);
      List<bool> isPersonals = typeCastMap(infoNode["is_personals"]);
      List<String> creationDates = typeCastMap(infoNode["creation_dates"]);

      if (!sameLengths([cids, usernames, fullNames, isPersonals, creationDates])) {
        return Optional.empty();
      }

      return Optional.of(GetAccountsResponse._(cids, usernames, fullNames, isPersonals, creationDates));
    } catch(_) {
      return Optional.empty();
    }
  }

}