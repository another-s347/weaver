use iroh::SecretKey;
use weaver_config::{EpochSecrets, NetworkConfigV1, NetworkPolicy};
use weaver_crypto::{
    AppBinding, AppRegistration, AppRole, AppRootKey, EndpointBinding, MemberCertificate,
    MemberRoles, NetworkRootKey, SigningKeypair, derive_device_id,
};
use weaver_net::{ConfigAuthorizationError, NodeConfig};

#[test]
fn signed_config_builds_multi_app_endpoint_authorizations() {
    let now = 500;
    let expires = 10_000;
    let root = NetworkRootKey::generate().unwrap();
    let network = root.public().network_id();
    let server_endpoint = SecretKey::generate();
    let client_endpoint = SecretKey::generate();
    let server_signing = SigningKeypair::generate().unwrap();
    let client_signing = SigningKeypair::generate().unwrap();
    let server_member = MemberCertificate::issue(
        &root,
        server_signing.public_bytes(),
        [0x11; 32],
        MemberRoles::MEMBER.union(MemberRoles::SERVICE),
        1,
        100,
        expires,
    )
    .unwrap();
    let client_member = MemberCertificate::issue(
        &root,
        client_signing.public_bytes(),
        [0x12; 32],
        MemberRoles::MEMBER,
        2,
        100,
        expires,
    )
    .unwrap();
    let server_endpoint_binding = EndpointBinding::issue(
        &server_signing,
        server_member.payload(),
        *server_endpoint.public().as_bytes(),
        0,
        expires,
    )
    .unwrap();
    let client_endpoint_binding = EndpointBinding::issue(
        &client_signing,
        client_member.payload(),
        *client_endpoint.public().as_bytes(),
        0,
        expires,
    )
    .unwrap();

    let server_app = AppRootKey::generate().unwrap();
    let first_client_app = AppRootKey::generate().unwrap();
    let second_client_app = AppRootKey::generate().unwrap();
    let server_registration = AppRegistration::issue(&root, &server_app, 0);
    let first_registration = AppRegistration::issue(&root, &first_client_app, 0);
    let second_registration = AppRegistration::issue(&root, &second_client_app, 0);
    let server_binding = AppBinding::issue(
        &server_app,
        network,
        server_member.payload().member_id,
        AppRole::Server,
        None,
        expires,
        Vec::new(),
    )
    .unwrap();
    let first_device = derive_device_id(
        network,
        first_client_app.app_addr(),
        &client_signing.public_bytes(),
    );
    let second_device = derive_device_id(
        network,
        second_client_app.app_addr(),
        &client_signing.public_bytes(),
    );
    let first_binding = AppBinding::issue(
        &first_client_app,
        network,
        client_member.payload().member_id,
        AppRole::Client,
        Some(first_device),
        expires,
        Vec::new(),
    )
    .unwrap();
    let second_binding = AppBinding::issue(
        &second_client_app,
        network,
        client_member.payload().member_id,
        AppRole::Client,
        Some(second_device),
        expires,
        Vec::new(),
    )
    .unwrap();
    let config = NetworkConfigV1 {
        network_id: network,
        epoch: 0,
        revision: 0,
        previous_hash: [0; 32],
        issued_at_ms: 100,
        expires_at_ms: expires,
        admin_keys: Vec::new(),
        members: vec![server_member.to_bytes(), client_member.to_bytes()],
        endpoint_bindings: vec![
            server_endpoint_binding.to_bytes(),
            client_endpoint_binding.to_bytes(),
        ],
        revoked_serials: Vec::new(),
        apps: vec![
            server_registration.to_bytes(),
            first_registration.to_bytes(),
            second_registration.to_bytes(),
        ],
        app_bindings: vec![
            server_binding.to_bytes(),
            first_binding.to_bytes(),
            second_binding.to_bytes(),
        ],
        relays: Vec::new(),
        presence_services: Vec::new(),
        epoch_secrets: EpochSecrets::from_bytes([[0x71; 32]; 4]),
        policies: NetworkPolicy::default(),
    }
    .validate(&root.public(), network, now)
    .unwrap();

    let server =
        NodeConfig::tcp_server_from_config(server_endpoint, &config, server_app.app_addr())
            .unwrap();
    let authorized = server
        .allowed_clients
        .get(&client_endpoint.public())
        .unwrap();
    assert_eq!(authorized.len(), 2);
    assert!(
        authorized.contains(&weaver_core::ScopedVirtualAddr::Client {
            app: first_client_app.app_addr(),
            device: first_device,
        })
    );
    assert!(
        authorized.contains(&weaver_core::ScopedVirtualAddr::Client {
            app: second_client_app.app_addr(),
            device: second_device,
        })
    );

    let client =
        NodeConfig::client_from_config(client_endpoint, &config, first_client_app.app_addr())
            .unwrap();
    assert_eq!(
        client.local_addr,
        weaver_core::ScopedVirtualAddr::Client {
            app: first_client_app.app_addr(),
            device: first_device,
        }
    );

    assert_eq!(
        NodeConfig::client_from_config(SecretKey::generate(), &config, first_client_app.app_addr())
            .unwrap_err(),
        ConfigAuthorizationError::LocalEndpointNotMember
    );
}
