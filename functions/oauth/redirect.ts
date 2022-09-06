const SCOPES = [
  "openid",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/photoslibrary.readonly",
];

export const onRequest: API = async (context) => {
  const {
    env: { GOOGLE_CLIENT_ID, API_HOST },
  } = context;
  const url = new URL(context.request.url);
  const returnUrl = url.searchParams.get("returnUrl") as string;

  const redirectUri = new URL(API_HOST || context.request.url);
  redirectUri.pathname = "/oauth/callback";

  for (const key in redirectUri.searchParams.keys())
    redirectUri.searchParams.delete(key);
  const redirectUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  redirectUrl.searchParams.append("client_id", GOOGLE_CLIENT_ID);
  redirectUrl.searchParams.append("redirect_uri", redirectUri.toString());
  redirectUrl.searchParams.append("access_type", "offline");
  redirectUrl.searchParams.append("response_type", "code");
  redirectUrl.searchParams.append("state", JSON.stringify({ returnUrl }));
  redirectUrl.searchParams.append("scope", SCOPES.join(" "));
  redirectUrl.searchParams.append("include_granted_scopes", "true");
  redirectUrl.searchParams.append("prompt", "consent select_account");

  return Response.redirect(redirectUrl.toString());
};
