//! What an opened path tells the core (`PathReport`), read from the establisher's path handle.

use citadel_link::{Link, LinkEstablisher, PathHandle, PathReport, Pathed};

pub(super) fn path_report<E: LinkEstablisher>(link: &Link<E, Pathed>) -> PathReport {
    let path = link.path();
    PathReport {
        kind: path.kind(),
        route: path.route_id(),
        migratable: path.migratable(),
        extra_stages: Vec::new(),
        reused_socket: false,
        local_nat: path.local_nat(),
        peer_nat: path.peer_nat(),
    }
}
