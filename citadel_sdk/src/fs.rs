use crate::prelude::{ObjectSource, ProtocolRemoteTargetExt, SecurityLevel, TargetLockedRemote};
use bytes::BytesMut;
use citadel_proto::prelude::NetworkError;
use std::path::PathBuf;

pub async fn write<T: ObjectSource, R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    source: T,
    virtual_path: R,
) -> Result<(), NetworkError> {
    write_with_security_level(remote, source, virtual_path, Default::default()).await
}

pub async fn write_with_security_level<T: ObjectSource, R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    source: T,
    security_level: SecurityLevel,
    virtual_path: R,
) -> Result<(), NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_push(source, virtual_path, security_level)
        .await
}

pub async fn read<R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    virtual_path: R,
) -> Result<BytesMut, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, false)
        .await
}

pub async fn take<R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    virtual_path: R,
) -> Result<BytesMut, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, true)
        .await
}

pub async fn delete<R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    virtual_path: R,
) -> Result<(), NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_delete(virtual_path)
        .await
}
