%%%----------------------------------------------------------------------
%%% File    : fast_tls_rust.erl
%%% Purpose : Rust NIF TLS interface (rustls-based drop-in for fast_tls)
%%% License : Apache-2.0
%%%----------------------------------------------------------------------

-module(fast_tls_rust).
-on_load(init/0).

%% NIF stubs
-export([open_nif/10, loop_nif/4, get_peer_certificate_nif/1,
         get_verify_result_nif/1, invalidate_nif/1,
         get_negotiated_cipher_nif/1, set_fips_mode_nif/1,
         get_fips_mode_nif/0, get_tls_cb_exporter_nif/1,
         p12_to_pem_nif/2]).

%% Public API
-export([tcp_to_tls/2,
         tls_to_tcp/1, send/2, recv/2, recv/3, recv_data/2,
         setopts/2, sockname/1, peername/1,
         controlling_process/2, close/1,
         get_peer_certificate/1, get_peer_certificate/2,
         get_verify_result/1, get_cert_verify_string/2,
         add_certfile/2, get_certfile/1, delete_certfile/1,
         clear_cache/0, get_negotiated_cipher/1,
         get_tls_last_message/2, set_fips_mode/1, get_fips_mode/0,
         get_tls_cb_exporter/1, p12_to_pem/2, finish_handshake/2]).

-include_lib("public_key/include/public_key.hrl").

-define(SET_CERTIFICATE_FILE_ACCEPT, 1).
-define(SET_CERTIFICATE_FILE_CONNECT, 2).
-define(VERIFY_NONE, 16#10000).
-define(COMPRESSION_NONE, 16#100000).
-define(OVERRIDE_CERT_PURPOSE, 16#200000).

-record(tlssock, {tcpsock :: inet:socket(),
                  tlsport :: reference()}).

-type tls_socket() :: #tlssock{}.
-type cert() :: #'Certificate'{} | #'OTPCertificate'{}.

-export_type([tls_socket/0]).

%% ============================================================
%% NIF Loading
%% ============================================================

init() ->
    SOPath = filename:join([code:priv_dir(fast_tls_rust),
                            "crates", "fast_tls_rust", "fast_tls_rust"]),
    erlang:load_nif(SOPath, 0).

%% ============================================================
%% NIF Stubs
%% ============================================================

open_nif(_Flags, _CertFile, _KeyFile, _Ciphers, _ProtocolOpts,
         _DH, _DHFile, _CAFile, _SNI, _ALPN) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

loop_nif(_Port, _ToSend, _Received, _ReceiveBytes) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_peer_certificate_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_verify_result_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

add_certfile_nif(_Domain, _File) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_certfile_nif(_Domain) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

delete_certfile_nif(_Domain) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

invalidate_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

clear_cache_nif() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_negotiated_cipher_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

tls_get_peer_finished_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

tls_get_finished_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_tls_cb_exporter_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

set_fips_mode_nif(_Flag) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_fips_mode_nif() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

p12_to_pem_nif(_P12Data, _Pass) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% ============================================================
%% Public API
%% ============================================================

-spec tcp_to_tls(inet:socket(), [atom() | {atom(), any()}]) ->
    {ok, tls_socket()} | {'error', 'no_certfile' | binary()}.
tcp_to_tls(TCPSocket, Options) ->
    Command = case lists:member(connect, Options) of
                  true -> ?SET_CERTIFICATE_FILE_CONNECT;
                  false -> ?SET_CERTIFICATE_FILE_ACCEPT
              end,
    CertFile = proplists:get_value(certfile, Options, ""),
    if CertFile /= [] orelse Command == ?SET_CERTIFICATE_FILE_CONNECT ->
        Flags1 = case lists:member(verify_none, Options) of
                     true -> ?VERIFY_NONE;
                     false -> 0
                 end,
        Flags2 = case lists:member(compression_none, Options) of
                     true -> ?COMPRESSION_NONE;
                     false -> 0
                 end,
        Flags3 = case lists:member(override_cert_purpose, Options) of
                     true -> ?OVERRIDE_CERT_PURPOSE;
                     false -> 0
                 end,
        Flags = Flags1 bor Flags2 bor Flags3,
        Ciphers =
        case lists:keysearch(ciphers, 1, Options) of
            {value, {ciphers, C}} ->
                iolist_to_binary(C);
            false ->
                <<>>
        end,
        ProtocolOpts = case lists:keysearch(protocol_options, 1, Options) of
                           {value, {protocol_options, P}} ->
                               iolist_to_binary(P);
                           false ->
                               <<>>
                       end,
        DH = case lists:keysearch(dh, 1, Options) of
                     {value, {dh, Der}} ->
                         iolist_to_binary(Der);
                     false ->
                         <<>>
                 end,
        DHFile = case lists:keysearch(dhfile, 1, Options) of
                     {value, {dhfile, D}} ->
                         iolist_to_binary(D);
                     false ->
                         <<>>
                 end,
        CAFile = case lists:keysearch(cafile, 1, Options) of
                     {value, {cafile, CA}} ->
                         iolist_to_binary(CA);
                     false ->
                         <<>>
                 end,
        KeyFile = case lists:keysearch(keyfile, 1, Options) of
                      {value, {keyfile, KF}} when CertFile /= "" ->
                          iolist_to_binary(KF);
                      _ ->
                          <<>>
                  end,
        ServerName = case lists:keysearch(sni, 1, Options) of
                         {value, {sni, SNI}} ->
                             iolist_to_binary(SNI);
                         false ->
                             <<>>
                     end,
        ALPN = case lists:keysearch(alpn, 1, Options) of
                   {value, {alpn, ProtoList}} ->
                       encode_alpn(ProtoList);
                   false ->
                       <<>>
               end,
        case open_nif(Command bor Flags, iolist_to_binary(CertFile),
                      KeyFile, Ciphers, ProtocolOpts, DH, DHFile,
                      CAFile, ServerName, iolist_to_binary(ALPN)) of
            {ok, Port} ->
                {ok, #tlssock{tcpsock = TCPSocket, tlsport = Port}};
            Err = {error, _} ->
                Err
        end;
        true -> {error, no_certfile}
    end.

-spec tls_to_tcp(tls_socket()) -> inet:socket().
tls_to_tcp(#tlssock{tcpsock = TCPSocket, tlsport = Port}) ->
    invalidate_nif(Port),
    TCPSocket.

-spec recv(tls_socket(), non_neg_integer()) ->
    {error, inet:posix()} | {error, binary()} | {ok, binary()}.
recv(Socket, Length) -> recv(Socket, Length, infinity).

-spec recv(tls_socket(), non_neg_integer(), timeout()) ->
    {error, inet:posix()} | {error, binary()} | {ok, binary()}.
recv(TLSSock, Length, Timeout) ->
    recv_and_loop(TLSSock, <<>>, <<>>, <<>>,
                  case Length of 0 -> -1; _ -> Length end, Timeout).

-spec recv_data(tls_socket(), binary()) ->
    {error, inet:posix() | binary()} | {ok, binary()}.
recv_data(TLSSock, Packet) ->
    loop(TLSSock, <<>>, Packet, <<>>, -1).

-spec loop(tls_socket(), binary(), binary(), binary(), integer()) ->
    {error, inet:posix() | binary()} | {ok, binary()}.
loop(#tlssock{tcpsock = TCPSocket,
              tlsport = Port} = Socket,
     ToSend, Received, DecBuf, Length) ->
    try loop_nif(Port, ToSend, Received, Length) of
        {error, _} = Err ->
            Err;
        {Tag, <<>>, Decrypted} when Tag == ok; Tag == init ->
            {ok, <<DecBuf/binary, Decrypted/binary>>};
        {Tag, ToWrite, Decrypted} when Tag == ok; Tag == init ->
            case gen_tcp:send(TCPSocket, ToWrite) of
                ok ->
                    loop(Socket, <<>>, <<>>, <<DecBuf/binary, Decrypted/binary>>,
                         Length - byte_size(Decrypted));
                {error, _} = Err ->
                    Err
            end;
        {{error, _} = Err, ToWrite, _} ->
            _ = gen_tcp:send(TCPSocket, ToWrite),
            Err
    catch error:badarg ->
        {error, einval}
    end.

-spec recv_and_loop(tls_socket(), binary(), binary(), binary(), integer(), timeout()) ->
    {error, inet:posix() | binary()} | {ok, binary()}.
recv_and_loop(#tlssock{tcpsock = TCPSocket} = Socket,
              ToSend, Received, DecBuf, Length, Timeout) ->
    case loop(Socket, ToSend, Received, DecBuf, Length) of
        {error, _} = Err ->
            Err;
        {ok, Decrypted} ->
            case size(Decrypted) - size(DecBuf) of
                V when V == 0 ->
                    case gen_tcp:recv(TCPSocket, 0, Timeout) of
                        {ok, Received2} ->
                            recv_and_loop(Socket, <<>>, Received2, Decrypted,
                                          Length - V, Timeout);
                        {error, _} = Err ->
                            Err
                    end;
                V when Length > V ->
                    recv_and_loop(Socket, <<>>, <<>>, Decrypted,
                                  Length - V, Timeout);
                _ when Length < 0 ->
                    {ok, Decrypted};
                V when Length == V ->
                    {ok, Decrypted};
                _ ->
                    {error, too_much_data_received}
            end
    end.

-spec finish_handshake(tls_socket(), timeout()) ->
    {error, inet:posix() | binary()} | ok.
finish_handshake(#tlssock{tcpsock = TCPSocket, tlsport = Port}, Timeout) ->
    OurLoop = fun OurLoop(Received) ->
        try loop_nif(Port, <<>>, Received, 0) of
            {error, _} = Err ->
                Err;
            {Tag, ToWrite, <<>>} when Tag == ok; Tag == init ->
                case gen_tcp:send(TCPSocket, ToWrite) of
                    ok when Tag == init ->
                        case gen_tcp:recv(TCPSocket, 0, Timeout) of
                            {ok, Received2} ->
                                OurLoop(Received2);
                            {error, _} = Err ->
                                Err
                        end;
                    ok ->
                        ok;
                    {error, _} = Err ->
                        Err
                end;
            {Tag, _ToWrite, _Data} when Tag == ok; Tag == init ->
                {error, too_much_data_received};
            {{error, _} = Err, ToWrite, _} ->
                _ = gen_tcp:send(TCPSocket, ToWrite),
                Err
        catch error:badarg ->
            {error, einval}
        end
    end,
    OurLoop(<<>>).

-spec send(tls_socket(), binary()) ->
    ok | {error, inet:posix() | binary() | timeout}.
send(Socket, Packet) ->
    case loop(Socket, Packet, <<>>, <<>>, 0) of
        {ok, <<>>} ->
            ok;
        {ok, Data} ->
            Data;
        Other ->
            Other
    end.

-spec setopts(tls_socket(), list()) ->
    ok | {error, inet:posix()}.
setopts(#tlssock{tcpsock = TCPSocket}, Opts) ->
    inet:setopts(TCPSocket, Opts).

-spec sockname(tls_socket()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, inet:posix()}.
sockname(#tlssock{tcpsock = TCPSocket}) ->
    inet:sockname(TCPSocket).

peername(#tlssock{tcpsock = TCPSocket}) ->
    inet:peername(TCPSocket).

controlling_process(#tlssock{tcpsock = TCPSocket},
                    Pid) ->
    gen_tcp:controlling_process(TCPSocket, Pid).

close(#tlssock{tcpsock = TCPSocket, tlsport = Port}) ->
    invalidate_nif(Port),
    gen_tcp:close(TCPSocket).

-spec get_peer_certificate(tls_socket()) -> {ok, cert()} | error.
get_peer_certificate(TLSSock) ->
    get_peer_certificate(TLSSock, plain).

-spec get_peer_certificate(tls_socket(), otp|plain) -> {ok, cert()} | error;
			  (tls_socket(), der) -> {ok, binary()} | error.
get_peer_certificate(#tlssock{tlsport = Port}, Type) ->
    case catch get_peer_certificate_nif(Port) of
        {'EXIT', {badarg, _}} ->
            error;
	{ok, BCert} when Type == der ->
	    {ok, BCert};
        {ok, BCert} ->
            try public_key:pkix_decode_cert(BCert, Type) of
                Cert -> {ok, Cert}
            catch _:_ ->
                error
            end;
        {error, _} -> error
    end.

-spec get_negotiated_cipher(tls_socket()) -> error | {ok, binary()}.
get_negotiated_cipher(#tlssock{tlsport = Port}) ->
    case catch get_negotiated_cipher_nif(Port) of
        Val when is_binary(Val) ->
            {ok, Val};
        _ ->
            error
    end.

-spec get_tls_last_message(peer | self, tls_socket()) -> {ok, binary()} | {error, term()}.
get_tls_last_message(peer, #tlssock{tlsport = Port}) ->
    tls_get_peer_finished_nif(Port);
get_tls_last_message(self, #tlssock{tlsport = Port}) ->
    tls_get_finished_nif(Port).

-spec get_tls_cb_exporter(tls_socket()) -> {ok, binary()} | {error, term()}.
get_tls_cb_exporter(#tlssock{tlsport = Port}) ->
    get_tls_cb_exporter_nif(Port).

-spec get_verify_result(tls_socket()) -> byte().
get_verify_result(#tlssock{tlsport = Port}) ->
    {ok, Res} = get_verify_result_nif(Port),
    Res.

-spec get_cert_verify_string(number(), cert() | binary()) -> binary().
get_cert_verify_string(CertVerifyRes, Cert) ->
    IsSelfsigned = cert_is_self_signed(Cert),
    case {CertVerifyRes, IsSelfsigned} of
	{21, true} -> <<"self-signed certificate">>;
	_ -> cert_verify_code(CertVerifyRes)
    end.

-spec cert_is_self_signed(cert() | binary()) -> boolean().
cert_is_self_signed(#'Certificate'{} = Cert) ->
    BCert = public_key:pkix_encode('Certificate', Cert, plain),
    cert_is_self_signed(BCert);
cert_is_self_signed(Cert) ->
    public_key:pkix_is_self_signed(Cert).

-spec add_certfile(iodata(), iodata()) -> ok.
add_certfile(Domain, File) ->
    add_certfile_nif(iolist_to_binary(Domain), iolist_to_binary(File)).

-spec get_certfile(iodata()) -> {ok, binary()} | error.
get_certfile(Domain) ->
    get_certfile_nif(iolist_to_binary(Domain)).

-spec delete_certfile(iodata()) -> boolean().
delete_certfile(Domain) ->
    delete_certfile_nif(iolist_to_binary(Domain)).

-spec clear_cache() -> ok.
clear_cache() ->
    clear_cache_nif().

-spec set_fips_mode(boolean()) -> ok | {error, binary()}.
set_fips_mode(true) ->
    set_fips_mode_nif(1);
set_fips_mode(false) ->
    set_fips_mode_nif(0).

-spec get_fips_mode() -> boolean().
get_fips_mode() ->
    get_fips_mode_nif().

-spec p12_to_pem(binary(), binary()) -> {ok, {binary(), binary()}} | {error, atom() | binary()}.
p12_to_pem(P12Data, Pass) ->
    p12_to_pem_nif(P12Data, <<Pass/binary, 0>>).

%% ============================================================
%% Internal: Certificate Verification Code Strings
%% ============================================================

cert_verify_code(0)  -> <<"ok">>;
cert_verify_code(2) ->
    <<"unable to get issuer certificate">>;
cert_verify_code(3) ->
    <<"unable to get certificate CRL">>;
cert_verify_code(4) ->
    <<"unable to decrypt certificate's signature">>;
cert_verify_code(5) ->
    <<"unable to decrypt CRL's signature">>;
cert_verify_code(6) ->
    <<"unable to decode issuer public key">>;
cert_verify_code(7) ->
    <<"certificate signature failure">>;
cert_verify_code(8)  -> <<"CRL signature failure">>;
cert_verify_code(9) ->
    <<"certificate is not yet valid">>;
cert_verify_code(10) -> <<"certificate has expired">>;
cert_verify_code(11) -> <<"CRL is not yet valid">>;
cert_verify_code(12) -> <<"CRL has expired">>;
cert_verify_code(13) ->
    <<"format error in certificate's notBefore "
      "field">>;
cert_verify_code(14) ->
    <<"format error in certificate's notAfter "
      "field">>;
cert_verify_code(15) ->
    <<"format error in CRL's lastUpdate field">>;
cert_verify_code(16) ->
    <<"format error in CRL's nextUpdate field">>;
cert_verify_code(17) -> <<"out of memory">>;
cert_verify_code(18) -> <<"self signed certificate">>;
cert_verify_code(19) ->
    <<"self signed certificate in certificate "
      "chain">>;
cert_verify_code(20) ->
    <<"unable to get local issuer certificate">>;
cert_verify_code(21) ->
    <<"unable to verify the first certificate">>;
cert_verify_code(22) ->
    <<"certificate chain too long">>;
cert_verify_code(23) -> <<"certificate revoked">>;
cert_verify_code(24) -> <<"invalid CA certificate">>;
cert_verify_code(25) ->
    <<"path length constraint exceeded">>;
cert_verify_code(26) ->
    <<"unsupported certificate purpose">>;
cert_verify_code(27) -> <<"certificate not trusted">>;
cert_verify_code(28) -> <<"certificate rejected">>;
cert_verify_code(29) -> <<"subject issuer mismatch">>;
cert_verify_code(30) ->
    <<"authority and subject key identifier "
      "mismatch">>;
cert_verify_code(31) ->
    <<"authority and issuer serial number mismatch">>;
cert_verify_code(32) ->
    <<"key usage does not include certificate "
      "signing">>;
cert_verify_code(50) ->
    <<"application verification failure">>;
cert_verify_code(X) ->
    <<"Unknown verify code: ", (integer_to_binary(X))/binary>>.

encode_alpn(ProtoList) ->
    iolist_to_binary([<<(size(Proto)), Proto/binary>> || Proto <- ProtoList, Proto /= <<>>]).
