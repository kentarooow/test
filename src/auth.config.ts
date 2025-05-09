import jwt, { JwtPayload } from "jsonwebtoken";
import type { NextAuthConfig } from "next-auth";
import { ConfidentialClientApplication } from "@azure/msal-node";
import MicrosoftEntraID from "next-auth/providers/microsoft-entra-id";

const msalInstance = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.AUTH_MICROSOFT_ENTRA_ID_CLIENT_ID!,
    clientSecret: process.env.AUTH_MICROSOFT_ENTRA_ID_CLIENT_SECRET!,
    authority: `https://login.microsoftonline.com/${process.env.AUTH_MICROSOFT_ENTRA_ID_TENANT_ID}/v2.0`,
  },
});

async function refreshAccessToken(refreshToken: string) {
  console.log("🔄 Starting token refresh with refreshToken:", refreshToken);

  try {
    const response = await msalInstance.acquireTokenByRefreshToken({
      refreshToken,
      scopes: ["openid", "profile", "email"],
    });

    console.log("✅ Token refresh response:", response);

    if (!response?.accessToken) throw new Error("No access token returned");

    return {
      idToken: response.idToken,
      accessToken: response.accessToken,
      expiresAt: response.expiresOn?.getTime() ?? Date.now() + 3600 * 1000,
    };
  } catch (error) {
    console.error("❌ refreshAccessToken error:", error);
    return null;
  }
}

export const authConfig: NextAuthConfig = {
  secret: process.env.NEXTAUTH_SECRET,
  trustHost: true,
  session: { strategy: "jwt" },

  providers: [
    MicrosoftEntraID({
      clientId: process.env.AUTH_MICROSOFT_ENTRA_ID_CLIENT_ID!,
      clientSecret: process.env.AUTH_MICROSOFT_ENTRA_ID_CLIENT_SECRET!,
      issuer: `https://login.microsoftonline.com/${process.env.AUTH_MICROSOFT_ENTRA_ID_TENANT_ID}/v2.0`,
      authorization: { params: { scope: "openid profile email offline_access" } },
    }),
  ],

  pages: {
    error: "/login",
  },

  callbacks: {
    async signIn({ user, profile }) {
      console.log("🚪 signIn callback triggered");
      console.log("👤 user:", user);
      console.log("📄 profile:", profile);

      try {
        const resolvedEmail =
          user.email || profile?.email || profile?.preferred_username;

        console.log("📧 resolvedEmail:", resolvedEmail);

        if (!resolvedEmail) {
          console.warn("⚠️ Email not resolved, allowing login for debug");
          return true;
        }

        const apiUrl = `${process.env.BASE_API_URL_PYTHON}/get_employee_callback?employee_address=${resolvedEmail}`;
        console.log("🌐 Calling backend API:", apiUrl);

        const res = await fetch(apiUrl);

        console.log("📡 API response status:", res.status);

        if (!res.ok) {
          const text = await res.text();
          console.error("❌ API fetch failed:", text);
          return true;
        }

        const data = await res.json();
        console.log("📦 API data:", data);

        if (!data.employee_role || data.employee_role === "権限なし") {
          console.warn("🚫 No valid role or role is '権限なし'");
          return true;
        }

        user.role = data.employee_role;
        user.location_id = data.location_id;
        user.employee_number = data.employee_number;
        user.employee_name = data.employee_name;

        console.log("✅ User enriched:", user);

        return true;
      } catch (error) {
        console.error("❌ signIn callback error:", error);
        return true;
      }
    },

    async jwt({ token, user, account }) {
      console.log("🔐 jwt callback triggered");
      console.log("📨 account:", account);
      console.log("👤 user:", user);
      console.log("🔑 token before:", token);

      if (account) {
        const decoded = account.id_token
          ? (jwt.decode(account.id_token) as JwtPayload)
          : null;

        console.log("🧾 Decoded id_token:", decoded);

        token.emailVerified = decoded?.email_verified ?? null;
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.expiresAt = account.expires_in
          ? Date.now() + account.expires_in * 1000
          : undefined;
      }

      if (user) {
        token.role = user.role;
        token.location_id = user.location_id;
        token.employee_number = user.employee_number;
        token.employee_name = user.employee_name;
      }

      if (token.expiresAt && Date.now() >= token.expiresAt && token.refreshToken) {
        console.log("⏳ Token expired, attempting refresh...");
        const refreshed = await refreshAccessToken(token.refreshToken);

        if (refreshed) {
          console.log("✅ Token refreshed");
          token.idToken = refreshed.idToken;
          token.accessToken = refreshed.accessToken;
          token.expiresAt = refreshed.expiresAt;
        } else {
          console.error("❌ Failed to refresh token");
          token.error = "FAILED_TO_REFRESH_ACCESS_TOKEN";
        }
      }

      console.log("🔑 token after:", token);
      return token;
    },

    async session({ session, token }) {
      console.log("💼 session callback triggered");
      console.log("🪪 token:", token);

      session.user = {
        id: token.sub!,
        name: token.employee_name || token.name || "不明なユーザー",
        email: token.email!,
        emailVerified: token.emailVerified === true ? new Date() : null,
        role: token.role ?? "",
        location_id: token.location_id ?? 0,
        employee_number: token.employee_number ?? 0,
        employee_name: token.employee_name ?? "",
      };

      session.error = token.error ?? null;

      console.log("📤 session:", session);

      return session;
    },
  },
};
