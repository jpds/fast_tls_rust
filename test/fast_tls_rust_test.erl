-module(fast_tls_rust_test).
-include_lib("eunit/include/eunit.hrl").

%% DER encoded DH parameters (2048 bits) — accepted but ignored by rustls backend
-define(DH, <<48,130,1,8,2,130,1,1,0,146,218,14,246,
              227,231,225,122,39,149,89,115,73,249,41,
              239,197,168,101,114,1,121,135,30,206,
              169,127,254,204,228,53,170,194,229,198,
              217,154,137,237,225,70,196,242,42,25,16,
              129,6,212,231,247,91,254,86,232,151,113,
              176,135,120,61,177,224,162,198,69,68,
              120,113,192,110,70,64,129,180,122,160,
              155,34,145,186,59,199,202,64,186,246,36,
              145,192,24,51,9,255,128,224,249,184,241,
              108,19,170,54,148,113,249,232,106,118,
              228,15,95,90,29,67,140,245,210,158,147,
              244,254,16,109,40,49,179,160,209,228,
              204,21,57,197,168,138,78,22,197,141,183,
              50,31,96,32,138,187,94,99,132,191,8,26,
              98,43,229,49,132,164,146,145,161,232,
              205,44,233,41,18,207,47,11,112,31,201,
              163,151,71,179,128,78,129,38,32,133,165,
              189,187,144,150,186,223,215,91,85,192,
              214,31,143,66,194,29,184,23,60,134,74,
              143,253,33,171,29,79,136,25,197,125,66,
              177,186,76,206,61,138,152,91,88,86,231,
              196,100,76,1,197,196,160,88,120,161,185,
              212,240,103,92,198,221,189,102,246,17,
              77,78,187,121,152,68,227,2,1,2>>).

certificate() ->
    {certfile, <<"test/cert.pem">>}.

%% -----------------------------------------------------------
%% Tests
%% -----------------------------------------------------------

transmission_with_client_certificate_test() ->
    transmission_test_with_opts([certificate()], [certificate()]).

transmission_without_client_certificate_test() ->
    transmission_test_with_opts([certificate()], []).

transmission_without_server_cert_fails_test() ->
    TestPid = self(),
    {ok, ListenSocket} = gen_tcp:listen(0, [binary, {packet, 0},
                                            {active, false},
                                            {reuseaddr, true},
                                            {nodelay, true}]),
    {ok, Port} = inet:port(ListenSocket),
    _ListenerPid = spawn(fun() ->
        {ok, Socket} = gen_tcp:accept(ListenSocket),
        Res = fast_tls_rust:tcp_to_tls(Socket, []),
        TestPid ! {listener_tcp_to_tls, Res}
    end),
    {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port,
                                   [binary, {packet, 0},
                                    {active, false},
                                    {reuseaddr, true},
                                    {nodelay, true}]),
    {ok, TLSSock} = fast_tls_rust:tcp_to_tls(Socket, [connect]),
    fast_tls_rust:close(TLSSock),
    receive
        {listener_tcp_to_tls, Res} ->
            ?assertEqual({error, no_certfile}, Res)
    end.

certfile_cache_test() ->
    ok = fast_tls_rust:add_certfile(<<"example.org">>, <<"test/cert.pem">>),
    ?assertEqual({ok, <<"test/cert.pem">>},
                 fast_tls_rust:get_certfile(<<"example.org">>)),
    ?assertEqual(true, fast_tls_rust:delete_certfile(<<"example.org">>)),
    ?assertEqual(error, fast_tls_rust:get_certfile(<<"example.org">>)),
    ?assertEqual(false, fast_tls_rust:delete_certfile(<<"example.org">>)).

clear_cache_test() ->
    ok = fast_tls_rust:add_certfile(<<"test.org">>, <<"test/cert.pem">>),
    ok = fast_tls_rust:clear_cache(),
    %% clear_cache only clears the SSL context cache, not the certfiles map
    ?assertEqual({ok, <<"test/cert.pem">>},
                 fast_tls_rust:get_certfile(<<"test.org">>)),
    fast_tls_rust:delete_certfile(<<"test.org">>).

fips_mode_test() ->
    %% FIPS is not supported by the rustls backend
    ?assertEqual(false, fast_tls_rust:get_fips_mode()),
    ?assertEqual(ok, fast_tls_rust:set_fips_mode(true)),
    ?assertEqual(false, fast_tls_rust:get_fips_mode()).

%% -----------------------------------------------------------
%% Helpers
%% -----------------------------------------------------------

transmission_test_with_opts(ListenerOpts, SenderOpts) ->
    {LPid, Port} = setup_listener(ListenerOpts),
    SPid = setup_sender(Port, SenderOpts),
    SPid ! {stop, self()},
    receive
        {result, Res} ->
            ?assertEqual(ok, Res)
    end,
    LPid ! {stop, self()},
    receive
        {received, Msg} ->
            ?assertEqual(<<"abcdefghi">>, Msg)
    end,
    receive
        {certfile, Cert} ->
            case lists:keymember(certfile, 1, SenderOpts) of
                true -> ?assertNotEqual(error, Cert);
                false -> ?assertEqual(error, Cert)
            end
    end.

setup_listener(Opts) ->
    {ok, ListenSocket} = gen_tcp:listen(0,
                                        [binary, {packet, 0}, {active, false},
                                         {reuseaddr, true}, {nodelay, true}]),
    Pid = spawn(fun() ->
        {ok, Socket} = gen_tcp:accept(ListenSocket),
        {ok, TLSSock} = fast_tls_rust:tcp_to_tls(Socket, [{dh, ?DH}|Opts]),
        listener_loop(TLSSock, <<>>)
    end),
    {ok, Port} = inet:port(ListenSocket),
    {Pid, Port}.

listener_loop(TLSSock, Msg) ->
    case fast_tls_rust:recv(TLSSock, 1, 1000) of
        {error, timeout} ->
            receive
                {stop, Pid} ->
                    Pid ! {received, Msg},
                    Cert = fast_tls_rust:get_peer_certificate(TLSSock),
                    Pid ! {certfile, Cert}
            after 0 ->
                listener_loop(TLSSock, Msg)
            end;
        {error, closed} ->
            receive
                {stop, Pid} ->
                    Pid ! {received, Msg},
                    Cert = fast_tls_rust:get_peer_certificate(TLSSock),
                    Pid ! {certfile, Cert}
            end;
        {error, _Err} ->
            receive
                {stop, Pid} ->
                    Pid ! {received, Msg},
                    Pid ! {certfile, error}
            end;
        {ok, Data} ->
            listener_loop(TLSSock, <<Msg/binary, Data/binary>>)
    end.

setup_sender(Port, Opts) ->
    {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port, [
        binary, {packet, 0}, {active, false},
        {reuseaddr, true}, {nodelay, true}]),
    spawn(fun() ->
        {ok, TLSSock} = fast_tls_rust:tcp_to_tls(Socket, [connect | Opts]),
        sender_loop(TLSSock)
    end).

sender_loop(TLSSock) ->
    Res = try
              fast_tls_rust:recv(TLSSock, 0, 100),
              ok = fast_tls_rust:send(TLSSock, <<"abc">>),
              fast_tls_rust:recv(TLSSock, 0, 100),
              ok = fast_tls_rust:send(TLSSock, <<"def">>),
              fast_tls_rust:recv(TLSSock, 0, 100),
              ok = fast_tls_rust:send(TLSSock, <<"ghi">>),
              fast_tls_rust:recv(TLSSock, 0, 100),
              fast_tls_rust:close(TLSSock),
              ok
          catch
              _:Err ->
                  fast_tls_rust:close(TLSSock),
                  Err
          end,
    receive
        {stop, Pid} ->
            Pid ! {result, Res}
    end.
