-module(oauth2_s2s).
-export([start/0, stop/0]).

-export([get_access_token/0, get_access_token/1]).

-include_lib("public_key/include/public_key.hrl").

-define(JWT_HEADER,[{alg, <<"RS256">>}, {typ, <<"JWT">>}]).

start() ->
    start(?MODULE).

stop() ->
    application:stop(?MODULE).

%% internal
start(AppName) ->
    F = fun({App, _, _}) -> App end,
    RunningApps = lists:map(F, application:which_applications()),
    ok = load(AppName),
    {ok, Dependencies} = application:get_key(AppName, applications),
    [begin
        ok = start(A)
    end || A <- Dependencies, not lists:member(A, RunningApps)],
    ok = application:start(AppName).

load(AppName) ->
    F = fun({App, _, _}) -> App end,
    LoadedApps = lists:map(F, application:loaded_applications()),
    case lists:member(AppName, LoadedApps) of
        true ->
            ok;
        false ->
            ok = application:load(AppName)
    end.

%% access token for pubsub api (default here as present in the config file)
get_access_token() ->
    {ok, Scope} = application:get_env(oauth2_s2s, scope),
    access_token(Scope).

get_access_token(Scope) ->
    access_token(Scope).

access_token(Scope) ->
    {ok, Host} = application:get_env(oauth2_s2s, host),
    {ok, Aud} = application:get_env(oauth2_s2s, aud),
    {ok, Iss} = application:get_env(oauth2_s2s,iss),
    {ok, GrantType} = application:get_env(oauth2_s2s, grant_type),
    {ok, RsaKeyPath} = application:get_env(oauth2_s2s, rsa_key_path),
    TokenExpTime = application:get_env(oauth2_s2s, token_exp_time, 3600),
    {ok, EncodedPrivateKey} = file:read_file(RsaKeyPath),
    [PemEntry] = public_key:pem_decode(EncodedPrivateKey),
    PrivateKey = public_key:pem_entry_decode(PemEntry),
    EncodedJWTHeader = encode_base64(?JWT_HEADER),
    EncodedJWTClaimSet = encode_base64(jwt_claim_set(Iss, Scope, Aud, TokenExpTime)),
    Signature = compute_signature(EncodedJWTHeader, EncodedJWTClaimSet, PrivateKey),
    Bytes = <<EncodedJWTHeader/binary, ".", EncodedJWTClaimSet/binary, ".", Signature/binary>>,
    Jwt = binary:replace(
        binary:replace(Bytes, <<"+">>, <<"-">>, [global]), <<"/">>, <<"_">>, [global]),
    Body = <<"grant_type=",GrantType/binary,"&assertion=",Jwt/binary>>,
    http_req(post, Host, "application/x-www-form-urlencoded", Body).

encode_base64(Json) ->
    base64:encode(jsx:encode(Json)).

jwt_claim_set(Iss, Scope, Aud, TokenExpTime) ->
    [{iss, Iss},
     {scope, Scope},
     {aud, Aud},
     {exp, unix_time() + TokenExpTime},
     {iat, unix_time()}].

compute_signature(Header, ClaimSet, #'RSAPrivateKey'{publicExponent=Exponent,
                                                    modulus=Modulus,
                                                    privateExponent=PrivateExp}) ->
    HeaderClaimSet = <<Header/binary, ".", ClaimSet/binary>>,
    Key = [Exponent, Modulus, PrivateExp],
    base64:encode(crypto:sign(rsa, sha256, HeaderClaimSet, Key)).


http_req(Method, Url, ContType, Body) ->
    Request = {binary_to_list(Url), [], ContType, Body},
    OptsReq = [{body_format, binary}],
    case httpc:request(Method, Request, [{ssl, [{verify, 0}]}], OptsReq) of
        {ok, {{_ ,200, _State}, _Head, ResponseBody}} ->
            jsx:decode(ResponseBody);
        {ok, {{_ ,_ResponseCode, _State}, _Head, ResponseBody}} ->
            jsx:decode(ResponseBody);
        {error, Reason} ->
            {error, Reason}
    end.

unix_time() ->
    UTC = calendar:universal_time(),
    calendar:datetime_to_gregorian_seconds(UTC) - 62167219200.

