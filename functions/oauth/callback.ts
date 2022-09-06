import jwt_decode from "jwt-decode";
import rs from "jsrsasign";

export const onRequest: API = async (context) => {
  const {
    env: {
      GOOGLE_CLIENT_SECRET,
      GOOGLE_CLIENT_ID,
      API_HOST,
      RETURN_HOSTS,
      JWT_SECRET,
    },
  } = context;
  const { protocol, host } = new URL(context.request.url);
  const inferredUrl = `${protocol}//${host}`;
  const baseUrl = API_HOST || inferredUrl;
  const redirectUri = new URL("/oauth/callback", baseUrl);

  const url = new URL(context.request.url);
  const code = url.searchParams.get("code");
  const state = JSON.parse(url.searchParams.get("state") as string) as {
    returnUrl: string;
  };
  const returnUrl = state.returnUrl;
  const returnHosts = RETURN_HOSTS.split(",");
  if (!returnHosts.includes(new URL(returnUrl).hostname))
    return new Response("Invalid return host.", {
      status: 401,
      statusText: "forbidden",
    });

  const body = new FormData();
  body.append("code", code!);
  body.append("client_id", GOOGLE_CLIENT_ID);
  body.append("client_secret", GOOGLE_CLIENT_SECRET);
  body.append("redirect_uri", redirectUri.toString());
  body.append("grant_type", "authorization_code");
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    body,
  });

  const json = await res.json<GoogleAuthorizationCodeResponse>();
  const { id_token, access_token, expires_in, refresh_token } = json;
  const { email } = jwt_decode<{ email: string }>(id_token);

  const header = JSON.stringify({ alg: "HS256", typ: "JWT" });
  const payload = JSON.stringify({
    email,
    expires_in,
    access_token,
    refresh_token,
  });

  const newTok = (rs as any).jws.JWS.sign("HS256", header, payload, JWT_SECRET);
  return Response.redirect(`${returnUrl}?id=${newTok}`);
};
