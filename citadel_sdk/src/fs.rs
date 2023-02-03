use crate::prelude::{ObjectSource, ProtocolRemoteTargetExt, SecurityLevel, TargetLockedRemote};
use bytes::BytesMut;
use citadel_proto::prelude::NetworkError;
use std::path::PathBuf;

pub async fn write<T: ObjectSource, R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    source: T,
    virtual_path: R,
) -> Result<(), NetworkError> {
    write_with_security_level(remote, source, Default::default(), virtual_path).await
}

pub async fn write_with_security_level<T: ObjectSource, R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    source: T,
    transfer_security_level: SecurityLevel,
    virtual_path: R,
) -> Result<(), NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_push(source, virtual_path, transfer_security_level)
        .await
}

pub async fn read<R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    virtual_path: R,
) -> Result<BytesMut, NetworkError> {
    read_with_security_level(remote, Default::default(), virtual_path).await
}

pub async fn read_with_security_level<R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    transfer_security_level: SecurityLevel,
    virtual_path: R,
) -> Result<BytesMut, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, transfer_security_level, false)
        .await
}

pub async fn take<R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    virtual_path: R,
) -> Result<BytesMut, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, Default::default(), true)
        .await
}

pub async fn take_with_security_level<R: Into<PathBuf> + Send>(
    remote: &mut impl TargetLockedRemote,
    transfer_security_level: SecurityLevel,
    virtual_path: R,
) -> Result<BytesMut, NetworkError> {
    remote
        .remote_encrypted_virtual_filesystem_pull(virtual_path, transfer_security_level, true)
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
