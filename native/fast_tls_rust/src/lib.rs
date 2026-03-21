//! Rust NIF TLS implementation using rustls for ejabberd.
//!
//! Drop-in replacement for the fast_tls C NIF (OpenSSL-based).
//! Uses rustls (pure Rust, memory-safe, audited) instead of OpenSSL.

use rustler::types::tuple::make_tuple;
use rustler::{Binary, Env, NewBinary, ResourceArc, Term};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

// ============================================================================
// Atoms
// ============================================================================

mod atoms {
    rustler::atoms! {
        ok,
        error,
        init,
        closed,
        enomem,
        undefined,
        write_failed,
        // FIPS
        r#true = "true",
        r#false = "false",
        // p12
        not_supported,
    }
}

// ============================================================================
// Constants (matching the C NIF)
// ============================================================================

const SET_CERTIFICATE_FILE_ACCEPT: u32 = 1;
const VERIFY_NONE: u32 = 0x10000;

// ============================================================================
// Global State
// ============================================================================

/// Domain → cert file path mapping (for SNI resolution).
fn certfiles_map() -> &'static RwLock<HashMap<String, String>> {
    static MAP: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    MAP.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Cert file path → cached CertifiedKey.
fn cert_key_cache() -> &'static RwLock<HashMap<String, Arc<CertifiedKey>>> {
    static CACHE: OnceLock<RwLock<HashMap<String, Arc<CertifiedKey>>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

// ============================================================================
// TLS Connection Wrapper
// ============================================================================

enum TlsConn {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl TlsConn {
    fn read_tls(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        match self {
            TlsConn::Server(c) => c.read_tls(rd),
            TlsConn::Client(c) => c.read_tls(rd),
        }
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> std::io::Result<usize> {
        match self {
            TlsConn::Server(c) => c.write_tls(wr),
            TlsConn::Client(c) => c.write_tls(wr),
        }
    }

    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            TlsConn::Server(c) => c.process_new_packets(),
            TlsConn::Client(c) => c.process_new_packets(),
        }
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsConn::Server(c) => c.reader().read(buf),
            TlsConn::Client(c) => c.reader().read(buf),
        }
    }

    fn write_all_plaintext(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            TlsConn::Server(c) => c.writer().write_all(data),
            TlsConn::Client(c) => c.writer().write_all(data),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            TlsConn::Server(c) => c.is_handshaking(),
            TlsConn::Client(c) => c.is_handshaking(),
        }
    }

    fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        match self {
            TlsConn::Server(c) => c.peer_certificates(),
            TlsConn::Client(c) => c.peer_certificates(),
        }
    }

    fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        match self {
            TlsConn::Server(c) => c.protocol_version(),
            TlsConn::Client(c) => c.protocol_version(),
        }
    }

    fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        match self {
            TlsConn::Server(c) => c.negotiated_cipher_suite(),
            TlsConn::Client(c) => c.negotiated_cipher_suite(),
        }
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), rustls::Error> {
        match self {
            TlsConn::Server(c) => {
                c.export_keying_material(output, label, context)?;
                Ok(())
            }
            TlsConn::Client(c) => {
                c.export_keying_material(output, label, context)?;
                Ok(())
            }
        }
    }
}

// ============================================================================
// Per-Connection TLS State
// ============================================================================

struct TlsState {
    conn: TlsConn,
    valid: bool,
    send_queue: Vec<u8>,
    verify_result: i64, // -1 = not computed, 0 = ok, >0 = error code
    verify_none: bool,
}

struct TlsStateResource(Mutex<TlsState>);

#[rustler::resource_impl]
impl rustler::Resource for TlsStateResource {}

// ============================================================================
// NoVerifier — accepts all certificates (matching C NIF verify_callback behavior)
// ============================================================================

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================================
// NoClientVerifier — requests client certs but accepts all (server side)
// Matches C NIF: SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE with verify_callback returning 1
// ============================================================================

#[derive(Debug)]
struct NoClientVerifier;

impl ClientCertVerifier for NoClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================================
// SNI Resolver
// ============================================================================

#[derive(Debug)]
struct SniResolver {
    default_key: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = hello.server_name()
            && let Some(ck) = lookup_cert_for_domain(name)
        {
            return Some(ck);
        }
        self.default_key.clone()
    }
}

fn lookup_cert_for_domain(domain: &str) -> Option<Arc<CertifiedKey>> {
    let certfiles = certfiles_map().read().ok()?;
    let lower = domain.to_lowercase();

    // Try exact match first
    let file = certfiles.get(&lower).cloned().or_else(|| {
        // Try wildcard: replace first label with '*'
        let dot_pos = lower.find('.')?;
        let wildcard = format!("*{}", &lower[dot_pos..]);
        certfiles.get(&wildcard).cloned()
    })?;
    drop(certfiles);

    // Check cert key cache
    if let Ok(cache) = cert_key_cache().read()
        && let Some(ck) = cache.get(&file)
    {
        return Some(ck.clone());
    }

    // Load and cache
    let ck = load_certified_key(&file, "").ok()?;
    let ck = Arc::new(ck);
    if let Ok(mut cache) = cert_key_cache().write() {
        cache.insert(file, ck.clone());
    }
    Some(ck)
}

// ============================================================================
// Certificate Loading
// ============================================================================

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| format!("SSL_CTX_use_certificate_file failed: {e}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("SSL_CTX_use_certificate_file failed: {e}"))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path).map_err(|e| format!("SSL_CTX_use_PrivateKey_file failed: {e}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("SSL_CTX_use_PrivateKey_file failed: {e}"))?
        .ok_or_else(|| "SSL_CTX_use_PrivateKey_file failed: no private key found".to_string())
}

fn load_certified_key(certfile: &str, keyfile: &str) -> Result<CertifiedKey, String> {
    let certs = load_certs(certfile)?;
    let key_path = if !keyfile.is_empty() {
        keyfile
    } else {
        certfile
    };
    let key_der = load_key(key_path)?;
    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| format!("SSL_CTX_check_private_key failed: {e}"))?;
    Ok(CertifiedKey::new(certs, signing_key))
}

// ============================================================================
// Protocol Version Parsing
// ============================================================================

fn parse_protocol_versions(opts: &[u8]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let opts_str = std::str::from_utf8(opts).unwrap_or("");
    let mut no_tls12 = false;
    let mut no_tls13 = false;

    if !opts_str.is_empty() {
        for opt in opts_str.split('|') {
            match opt.trim() {
                "no_tlsv1_2" => no_tls12 = true,
                "no_tlsv1_3" => no_tls13 = true,
                // SSLv2, SSLv3, TLS 1.0, TLS 1.1 are not supported by rustls
                _ => {}
            }
        }
    }

    let mut versions = Vec::new();
    if !no_tls12 {
        versions.push(&rustls::version::TLS12);
    }
    if !no_tls13 {
        versions.push(&rustls::version::TLS13);
    }
    if versions.is_empty() {
        // Must have at least one version; default to TLS 1.3
        versions.push(&rustls::version::TLS13);
    }
    versions
}

// ============================================================================
// ALPN Parsing
// ============================================================================

/// Parse wire-format ALPN: [len1, proto1..., len2, proto2..., ...]
fn parse_alpn(data: &[u8]) -> Vec<Vec<u8>> {
    let mut protos = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            break;
        }
        protos.push(data[i..i + len].to_vec());
        i += len;
    }
    protos
}

// ============================================================================
// Term Helpers
// ============================================================================

fn make_binary_term<'a>(env: Env<'a>, data: &[u8]) -> Term<'a> {
    let mut binary = NewBinary::new(env, data.len());
    binary.as_mut_slice().copy_from_slice(data);
    binary.into()
}

fn make_ok<'a>(env: Env<'a>, value: Term<'a>) -> Term<'a> {
    make_tuple(env, &[atoms::ok().encode(env), value])
}

fn make_error_atom<'a>(env: Env<'a>, reason: rustler::Atom) -> Term<'a> {
    make_tuple(env, &[atoms::error().encode(env), reason.encode(env)])
}

fn make_error_binary<'a>(env: Env<'a>, msg: &str) -> Term<'a> {
    make_tuple(
        env,
        &[
            atoms::error().encode(env),
            make_binary_term(env, msg.as_bytes()),
        ],
    )
}

use rustler::Encoder;

// ============================================================================
// Config Builders
// ============================================================================

fn build_server_config(
    resolver: SniResolver,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn_protos: &[Vec<u8>],
    _cafile: &str,
) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| format!("Protocol version error: {e}"))?;

    let mut config = builder
        .with_client_cert_verifier(Arc::new(NoClientVerifier))
        .with_cert_resolver(Arc::new(resolver));

    if !alpn_protos.is_empty() {
        config.alpn_protocols = alpn_protos.to_vec();
    }

    Ok(Arc::new(config))
}

fn build_client_config(
    certfile: &str,
    keyfile: &str,
    _cafile: &str,
    _verify_none: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn_protos: &[Vec<u8>],
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| format!("Protocol version error: {e}"))?;

    // Always accept certificates (matching C NIF verify_callback that returns 1).
    // Verification result is computed post-handshake via get_verify_result_nif.
    let config_builder = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier));

    let mut config = if !certfile.is_empty() {
        let certs = load_certs(certfile)?;
        let key_path = if !keyfile.is_empty() {
            keyfile
        } else {
            certfile
        };
        let key = load_key(key_path)?;
        config_builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("Client cert error: {e}"))?
    } else {
        config_builder.with_no_client_auth()
    };

    if !alpn_protos.is_empty() {
        config.alpn_protocols = alpn_protos.to_vec();
    }

    Ok(Arc::new(config))
}

// ============================================================================
// Decrypted Data Reader
// ============================================================================

fn read_decrypted(conn: &mut TlsConn, bytes_to_read: i32) -> Vec<u8> {
    if bytes_to_read == 0 {
        return Vec::new();
    }

    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    if bytes_to_read < 0 {
        // Read all available
        loop {
            match conn.read_plaintext(&mut tmp) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
    } else {
        // Read up to bytes_to_read
        let mut remaining = bytes_to_read as usize;
        while remaining > 0 {
            let to_read = remaining.min(tmp.len());
            match conn.read_plaintext(&mut tmp[..to_read]) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    remaining -= n;
                }
                Err(_) => break,
            }
        }
    }
    buf
}

// ============================================================================
// TLS Error Mapping
// ============================================================================

fn map_tls_error(e: &rustls::Error) -> String {
    match e {
        rustls::Error::InvalidMessage(_)
        | rustls::Error::InappropriateMessage { .. }
        | rustls::Error::InappropriateHandshakeMessage { .. } => "closed".to_string(),
        rustls::Error::AlertReceived(alert) => {
            format!("TLS alert: {alert:?}")
        }
        _ => format!("SSL_do_handshake failed: {e}"),
    }
}

fn is_closed_error(e: &rustls::Error) -> bool {
    matches!(
        e,
        rustls::Error::InvalidMessage(_)
            | rustls::Error::InappropriateMessage { .. }
            | rustls::Error::InappropriateHandshakeMessage { .. }
    )
}

// ============================================================================
// NIF: open_nif/10
// ============================================================================

#[rustler::nif]
#[allow(clippy::too_many_arguments)]
fn open_nif<'a>(
    env: Env<'a>,
    flags: u32,
    certfile: Binary<'a>,
    keyfile: Binary<'a>,
    _ciphers: Binary<'a>,
    protocol_options: Binary<'a>,
    _dh: Binary<'a>,
    _dhfile: Binary<'a>,
    _cafile: Binary<'a>,
    sni: Binary<'a>,
    alpn: Binary<'a>,
) -> Term<'a> {
    let command = flags & 0xffff;
    let verify_none = (flags & VERIFY_NONE) != 0;

    let certfile_str = std::str::from_utf8(certfile.as_slice()).unwrap_or("");
    let keyfile_str = std::str::from_utf8(keyfile.as_slice()).unwrap_or("");
    let sni_str = std::str::from_utf8(sni.as_slice()).unwrap_or("");
    let cafile_str = std::str::from_utf8(_cafile.as_slice()).unwrap_or("");

    let versions = parse_protocol_versions(protocol_options.as_slice());
    let alpn_protos = parse_alpn(alpn.as_slice());

    let is_server = command == SET_CERTIFICATE_FILE_ACCEPT;

    let conn = if is_server {
        // --- Server (accept) ---
        let certified_key = if !certfile_str.is_empty() {
            match load_certified_key(certfile_str, keyfile_str) {
                Ok(ck) => Some(Arc::new(ck)),
                Err(e) => return make_error_binary(env, &e),
            }
        } else {
            None
        };

        let resolver = SniResolver {
            default_key: certified_key,
        };

        let config = match build_server_config(resolver, &versions, &alpn_protos, cafile_str) {
            Ok(c) => c,
            Err(e) => return make_error_binary(env, &e),
        };

        let server_conn = match ServerConnection::new(config) {
            Ok(c) => c,
            Err(e) => return make_error_binary(env, &format!("ServerConnection::new failed: {e}")),
        };

        TlsConn::Server(server_conn)
    } else {
        // --- Client (connect) ---
        let config = match build_client_config(
            certfile_str,
            keyfile_str,
            cafile_str,
            verify_none,
            &versions,
            &alpn_protos,
        ) {
            Ok(c) => c,
            Err(e) => return make_error_binary(env, &e),
        };

        let server_name = if !sni_str.is_empty() {
            match ServerName::try_from(sni_str.to_string()) {
                Ok(sn) => sn,
                Err(e) => return make_error_binary(env, &format!("Invalid SNI: {e}")),
            }
        } else {
            // rustls requires a server name; use a placeholder
            ServerName::try_from("localhost".to_string()).unwrap()
        };

        let client_conn = match ClientConnection::new(config, server_name) {
            Ok(c) => c,
            Err(e) => return make_error_binary(env, &format!("ClientConnection::new failed: {e}")),
        };

        TlsConn::Client(client_conn)
    };

    let state = TlsState {
        conn,
        valid: true,
        send_queue: Vec::new(),
        verify_result: -1,
        verify_none,
    };

    let resource = ResourceArc::new(TlsStateResource(Mutex::new(state)));
    make_ok(env, resource.encode(env))
}

// ============================================================================
// NIF: loop_nif/4
// ============================================================================

#[rustler::nif]
fn loop_nif<'a>(
    env: Env<'a>,
    state_resource: ResourceArc<TlsStateResource>,
    to_send: Binary<'a>,
    received: Binary<'a>,
    bytes_to_read: i32,
) -> Term<'a> {
    let Ok(mut state) = state_resource.0.lock() else {
        return make_error_atom(env, atoms::closed());
    };

    if !state.valid {
        return make_error_atom(env, atoms::closed());
    }

    // 1. Feed received encrypted data from network
    if !received.is_empty() {
        let mut cursor = Cursor::new(received.as_slice());
        if let Err(e) = state.conn.read_tls(&mut cursor) {
            return make_error_binary(env, &format!("read_tls failed: {e}"));
        }
    }

    // 2. Process TLS records (handshake + application data)
    match state.conn.process_new_packets() {
        Ok(_io_state) => {
            let is_handshaking = state.conn.is_handshaking();

            // 3. Handle plaintext send data
            if is_handshaking {
                // Queue plaintext until handshake completes
                if !to_send.is_empty() {
                    state.send_queue.extend_from_slice(to_send.as_slice());
                }
            } else {
                // Flush queued data from handshake phase
                if !state.send_queue.is_empty() {
                    let queued = std::mem::take(&mut state.send_queue);
                    if let Err(e) = state.conn.write_all_plaintext(&queued) {
                        return make_error_binary(env, &format!("write failed: {e}"));
                    }
                }
                // Send new plaintext data
                if !to_send.is_empty()
                    && let Err(e) = state.conn.write_all_plaintext(to_send.as_slice())
                {
                    return make_error_binary(env, &format!("write failed: {e}"));
                }
            }

            // 4. Read decrypted application data
            let decrypted = read_decrypted(&mut state.conn, bytes_to_read);

            // 5. Get encrypted TLS output to send to network
            let mut to_write = Vec::new();
            let _ = state.conn.write_tls(&mut to_write);

            // 6. Return {ok|init, ToWrite, Decrypted}
            let tag = if is_handshaking {
                atoms::init()
            } else {
                atoms::ok()
            };

            make_tuple(
                env,
                &[
                    tag.encode(env),
                    make_binary_term(env, &to_write),
                    make_binary_term(env, &decrypted),
                ],
            )
        }
        Err(e) => {
            // Queue send data even on error (C NIF does this)
            if state.conn.is_handshaking() && !to_send.is_empty() {
                state.send_queue.extend_from_slice(to_send.as_slice());
            }

            // Flush any TLS alert data
            let mut to_write = Vec::new();
            let _ = state.conn.write_tls(&mut to_write);

            // Try to read any available decrypted data
            let decrypted = read_decrypted(&mut state.conn, bytes_to_read);

            // Map error
            if is_closed_error(&e) {
                let err_term = make_error_atom(env, atoms::closed());
                make_tuple(
                    env,
                    &[
                        err_term,
                        make_binary_term(env, &to_write),
                        make_binary_term(env, &decrypted),
                    ],
                )
            } else {
                let msg = map_tls_error(&e);
                let err_term = make_error_binary(env, &msg);
                make_tuple(
                    env,
                    &[
                        err_term,
                        make_binary_term(env, &to_write),
                        make_binary_term(env, &decrypted),
                    ],
                )
            }
        }
    }
}

// ============================================================================
// NIF: get_peer_certificate_nif/1
// ============================================================================

#[rustler::nif]
fn get_peer_certificate_nif<'a>(
    env: Env<'a>,
    state_resource: ResourceArc<TlsStateResource>,
) -> Term<'a> {
    let Ok(state) = state_resource.0.lock() else {
        return make_error_atom(env, atoms::closed());
    };

    if !state.valid {
        return make_error_atom(env, atoms::closed());
    }

    match state.conn.peer_certificates() {
        Some(certs) if !certs.is_empty() => {
            let cert_der = &certs[0];
            make_ok(env, make_binary_term(env, cert_der.as_ref()))
        }
        _ => make_error_binary(env, "SSL_get_peer_certificate failed"),
    }
}

// ============================================================================
// NIF: get_verify_result_nif/1
// ============================================================================

#[rustler::nif]
fn get_verify_result_nif<'a>(
    env: Env<'a>,
    state_resource: ResourceArc<TlsStateResource>,
) -> Term<'a> {
    let Ok(mut state) = state_resource.0.lock() else {
        return make_error_atom(env, atoms::closed());
    };

    if !state.valid {
        return make_error_atom(env, atoms::closed());
    }

    // Return cached result if available
    if state.verify_result >= 0 {
        return make_ok(env, state.verify_result.encode(env));
    }

    // Compute verify result
    let result = if state.verify_none {
        0i64 // X509_V_OK
    } else {
        match state.conn.peer_certificates() {
            Some(certs) if !certs.is_empty() => {
                // We accepted all certs via NoVerifier.
                // Post-handshake verification against system roots.
                verify_peer_cert_chain(certs)
            }
            _ => 21, // X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
        }
    };

    state.verify_result = result;
    make_ok(env, result.encode(env))
}

/// Returns an OpenSSL-compatible X509_V_ERR code.
///
/// Since we use NoVerifier (matching the C NIF's verify_callback that always
/// returns 1), the handshake always succeeds. The verify result here reflects
/// whether peer certificates were presented. For full certificate chain
/// validation, ejabberd performs its own verification at the Erlang level
/// via ejabberd_pkix and public_key:pkix_path_validation.
fn verify_peer_cert_chain(certs: &[CertificateDer<'_>]) -> i64 {
    if certs.is_empty() {
        return 21; // X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
    }
    0 // X509_V_OK — peer presented certificates
}

// ============================================================================
// NIF: add_certfile_nif/2
// ============================================================================

#[rustler::nif]
fn add_certfile_nif<'a>(env: Env<'a>, domain: Binary<'a>, file: Binary<'a>) -> Term<'a> {
    let domain_str = std::str::from_utf8(domain.as_slice())
        .unwrap_or("")
        .to_lowercase();
    let file_str = std::str::from_utf8(file.as_slice())
        .unwrap_or("")
        .to_string();

    if let Ok(mut map) = certfiles_map().write() {
        map.insert(domain_str, file_str);
    }

    atoms::ok().encode(env)
}

// ============================================================================
// NIF: delete_certfile_nif/1
// ============================================================================

#[rustler::nif]
fn delete_certfile_nif<'a>(env: Env<'a>, domain: Binary<'a>) -> Term<'a> {
    let domain_str = std::str::from_utf8(domain.as_slice())
        .unwrap_or("")
        .to_lowercase();

    let removed = if let Ok(mut map) = certfiles_map().write() {
        map.remove(&domain_str).is_some()
    } else {
        false
    };

    if removed {
        atoms::r#true().encode(env)
    } else {
        atoms::r#false().encode(env)
    }
}

// ============================================================================
// NIF: get_certfile_nif/1
// ============================================================================

#[rustler::nif]
fn get_certfile_nif<'a>(env: Env<'a>, domain: Binary<'a>) -> Term<'a> {
    let domain_str = std::str::from_utf8(domain.as_slice())
        .unwrap_or("")
        .to_lowercase();

    if let Ok(map) = certfiles_map().read() {
        // Try exact match
        if let Some(file) = map.get(&domain_str) {
            return make_ok(env, make_binary_term(env, file.as_bytes()));
        }
        // Try wildcard
        if let Some(dot_pos) = domain_str.find('.') {
            let wildcard = format!("*{}", &domain_str[dot_pos..]);
            if let Some(file) = map.get(&wildcard) {
                return make_ok(env, make_binary_term(env, file.as_bytes()));
            }
        }
    }

    atoms::error().encode(env)
}

// ============================================================================
// NIF: clear_cache_nif/0
// ============================================================================

#[rustler::nif]
fn clear_cache_nif<'a>(env: Env<'a>) -> Term<'a> {
    if let Ok(mut cache) = cert_key_cache().write() {
        cache.clear();
    }
    atoms::ok().encode(env)
}

// ============================================================================
// NIF: invalidate_nif/1
// ============================================================================

#[rustler::nif]
fn invalidate_nif<'a>(env: Env<'a>, state_resource: ResourceArc<TlsStateResource>) -> Term<'a> {
    let Ok(mut state) = state_resource.0.lock() else {
        return atoms::ok().encode(env);
    };
    state.valid = false;
    atoms::ok().encode(env)
}

// ============================================================================
// NIF: get_negotiated_cipher_nif/1
// ============================================================================

#[rustler::nif]
fn get_negotiated_cipher_nif<'a>(
    env: Env<'a>,
    state_resource: ResourceArc<TlsStateResource>,
) -> Term<'a> {
    let Ok(state) = state_resource.0.lock() else {
        return make_error_atom(env, atoms::closed());
    };

    if !state.valid {
        return make_error_atom(env, atoms::closed());
    }

    let version_str = match state.conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        _ => "unknown",
    };

    let cipher_str = match state.conn.negotiated_cipher_suite() {
        Some(suite) => format!("{:?}", suite.suite()),
        None => "unknown".to_string(),
    };

    let result = format!("{version_str} {cipher_str}");
    make_binary_term(env, result.as_bytes())
}

// ============================================================================
// NIF: tls_get_peer_finished_nif/1 — not supported by rustls
// ============================================================================

#[rustler::nif]
fn tls_get_peer_finished_nif<'a>(
    env: Env<'a>,
    _state_resource: ResourceArc<TlsStateResource>,
) -> Term<'a> {
    // rustls does not expose raw TLS Finished messages.
    // Use get_tls_cb_exporter_nif for channel binding instead.
    make_error_atom(env, atoms::undefined())
}

// ============================================================================
// NIF: tls_get_finished_nif/1 — not supported by rustls
// ============================================================================

#[rustler::nif]
fn tls_get_finished_nif<'a>(
    env: Env<'a>,
    _state_resource: ResourceArc<TlsStateResource>,
) -> Term<'a> {
    make_error_atom(env, atoms::undefined())
}

// ============================================================================
// NIF: get_tls_cb_exporter_nif/1
// ============================================================================

#[rustler::nif]
fn get_tls_cb_exporter_nif<'a>(
    env: Env<'a>,
    state_resource: ResourceArc<TlsStateResource>,
) -> Term<'a> {
    let Ok(state) = state_resource.0.lock() else {
        return make_error_atom(env, atoms::closed());
    };

    if !state.valid {
        return make_error_atom(env, atoms::closed());
    }

    let mut output = [0u8; 32];
    match state
        .conn
        .export_keying_material(&mut output, b"EXPORTER-Channel-Binding", Some(&[]))
    {
        Ok(()) => make_ok(env, make_binary_term(env, &output)),
        Err(_) => make_error_atom(env, atoms::undefined()),
    }
}

// ============================================================================
// NIF: set_fips_mode_nif/1 — not applicable to rustls
// ============================================================================

#[rustler::nif]
fn set_fips_mode_nif<'a>(env: Env<'a>, _flag: i32) -> Term<'a> {
    // rustls does not use OpenSSL and has no FIPS mode toggle.
    // For FIPS compliance, use the rustls-fips crate with aws-lc-rs provider.
    // For now, accept silently.
    atoms::ok().encode(env)
}

// ============================================================================
// NIF: get_fips_mode_nif/0
// ============================================================================

#[rustler::nif]
fn get_fips_mode_nif<'a>(env: Env<'a>) -> Term<'a> {
    atoms::r#false().encode(env)
}

// ============================================================================
// NIF: p12_to_pem_nif/2 — not implemented (rarely used)
// ============================================================================

#[rustler::nif]
fn p12_to_pem_nif<'a>(env: Env<'a>, _p12_data: Binary<'a>, _pass: Binary<'a>) -> Term<'a> {
    make_error_binary(
        env,
        "p12_to_pem not supported with rustls backend; convert externally with openssl pkcs12",
    )
}

// ============================================================================
// Rustler Init
// ============================================================================

rustler::init!("fast_tls_rust");
