"""
A Python script containing exactly the same logic as rtmr3.tsx, but without the clutter of React things.
"""
import hashlib
import json

INIT_MR = "0" * 96
DSTACK_EVENT_TAG = 0x08000001  # event type, taken from Dstack source code


def calc_rtmr3(root_fs_hash: str, app_id: str, compose_manifest_path: str,
               ca_cert_hash: str, instance_id: str):
    """
    Calculate the RTMR3 value from the given values.

    :param root_fs_hash: Hash of the root filesystem. Not available publicly.
    The verified app should provide it. Available publicly on Phala Cloud
    is the *digest* of this hash.
    :param app_id: Application ID. Available publicly on Phala Cloud.
    :param compose_manifest_path: Path to the compose manifest file. Downloaded from
    Phala Cloud.
    :param ca_cert_hash: Hash of the CA certificate. Not available publicly.
    The verified app should provide it.
    :param instance_id: Instance ID. Available publicly on Phala Cloud.
    :return: Calculated RTMR3 value.
    """
    compose_hash = get_compose_hash(compose_manifest_path)
    return calc_rtmr3_from_hashes(root_fs_hash, app_id, compose_hash, ca_cert_hash,
                                  instance_id)


def get_compose_hash(path: str) -> str:
    """
    Get the compose hash from the compose file at a given path.

    Adjusts the manifest file by removing the docker_config field and removing
    formatting. Then calculates the hash of the adjusted manifest file.

    :param path: Path to the compose file. It should be a compose-manifest.json file
    downloaded from Phala Cloud.
    :return: Hash to be used in RTMR3 calculation.
    """
    with open(path, "rb") as f:
        original_manifest_dict = json.load(f)
    adjusted_manifest_string = json.dumps(
        original_manifest_dict | {"docker_config": dict()}, separators=(',', ':')
    )
    print(adjusted_manifest_string)
    compose_hash = hashlib.sha256(adjusted_manifest_string.encode()).hexdigest()
    return compose_hash


def calc_rtmr3_from_hashes(root_fs_hash: str, app_id: str, compose_hash: str,
                           ca_cert_hash: str, instance_id: str):
    """
    Calculate the RTMR3 value from the given values.

    :param root_fs_hash: Hash of the root filesystem. Available publicly on Phala Cloud.
    :param app_id: Application ID. Available publicly on Phala Cloud.
    :param compose_hash: Hash of the compose file. Get it by calling get_compose_hash.
    :param ca_cert_hash: Hash of the CA certificate. Not available publicly.
    The verified app should provide it.
    :param instance_id: Instance ID. Available publicly on Phala Cloud.
    :return: Calculated RTMR3 value.
    """
    rootfs_digest = calc_digest("rootfs-hash", root_fs_hash)
    app_id_digest = calc_digest("app-id", app_id)
    compose_digest = calc_digest("compose-hash", compose_hash)
    ca_cert_digest = calc_digest("ca-cert-hash", ca_cert_hash)
    instance_id_digest = calc_digest("instance-id", instance_id)

    print(f"rootfs_digest: {rootfs_digest}")
    print(f"app_id_digest: {app_id_digest}")
    print(f"compose_digest: {compose_digest}")
    print(f"ca_cert_digest: {ca_cert_digest}")
    print(f"instance_id_digest: {instance_id_digest}")

    return calc_rtmr3_from_digests(
        rootfs_digest,
        app_id_digest,
        compose_digest,
        ca_cert_digest,
        instance_id_digest
    )


def calc_digest(event_name: str, event_value: str):
    """
    Calculate the digest for a given event name and value.

    Replicates this code of DStack: https://github.com/Dstack-TEE/dstack/blob/master/cc-eventlog/src/lib.rs#L54-L63

    :param event_name: Name of the event.
    :param event_value: Value of the event.
    :return: Calculated digest.
    """
    hasher = hashlib.sha384()
    hasher.update(DSTACK_EVENT_TAG.to_bytes(4, 'little'))
    hasher.update(b':')
    hasher.update(event_name.encode())
    hasher.update(b':')
    hasher.update(bytes.fromhex(event_value))
    compose_hash_digest = hasher.hexdigest()
    return compose_hash_digest


def calc_rtmr3_from_digests(rootfs_hash_digest: str, app_id_digest: str,
                            compose_hash_digest: str, ca_cert_hash_digest: str,
                            instance_id_digest: str):
    """
    Calculate the RTMR3 value from the given digests.

    Replicates this code of DStack: https://github.com/Dstack-TEE/dstack/blob/master/tdxctl/src/fde_setup.rs#L437

    :param rootfs_hash_digest: Digest of the root filesystem hash.
    :param app_id_digest: Digest of the application ID.
    :param compose_hash_digest: Digest of the compose file hash.
    :param ca_cert_hash_digest: Digest of the CA certificate hash.
    :param instance_id_digest: Digest of the instance ID.
    :return: Calculated RTMR3 value.
    """
    return rtmr_replay(
        [rootfs_hash_digest, app_id_digest, compose_hash_digest, ca_cert_hash_digest,
         instance_id_digest])


def rtmr_replay(history: list[str]):
    """
    Replay the event history to calculate the current RTMR value.

    Taken from DStack Python SDK: https://github.com/Dstack-TEE/dstack/blob/master/python/tappd_client/tappd_client.py#L49

    :param history: List of values to be used to calculate RTMR value.
    :return: Calculated RTMR value.
    """
    if len(history) == 0:
        return INIT_MR
    mr = bytes.fromhex(INIT_MR)
    for content in history:
        content = bytes.fromhex(content)
        if len(content) < 48:
            content = content.ljust(48, b'\0')
        mr = hashlib.sha384(mr + content).digest()
    return mr.hex()


if __name__ == "__main__":
    rtmr3 = calc_rtmr3(
        root_fs_hash="...",
        app_id="...",
        compose_manifest_path="...",
        ca_cert_hash="...",
        instance_id="..."
    )
    print("RTMR3:", rtmr3)
