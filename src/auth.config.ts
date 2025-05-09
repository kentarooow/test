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
  console.log("🔄 Refreshing access token with refreshToken:", refreshToken);

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
    console.error("❌ Error refreshing access token:", error);
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
      authorization: {
        params: {
          scope: "openid profile email offline_access",
        },
      },
    }),
  ],

  pages: {
    error: "/login",
  },

  callbacks: {
    async signIn({ user, profile }) {
      console.log("🚪 [signIn] triggered");
      console.log("👤 user:", user);
      console.log("📄 profile:", profile);

      try {
        let resolvedEmail =
          user.email || profile?.email || profile?.preferred_username;

        if (!resolvedEmail) {
          console.warn("⚠️ resolvedEmail is undefined! Using fallback email");
          resolvedEmail = "unknown@example.com";
        }

        const apiUrl = `${process.env.BASE_API_URL_PYTHON}/get_employee_callback?employee_address=${encodeURIComponent(resolvedEmail)}`;
        console.log("🌐 Backend API URL:", apiUrl);

        const res = await fetch(apiUrl);
        console.log("📡 Backend response status:", res.status);

        if (!res.ok) {
          const text = await res.text();
          console.error("❌ Backend fetch error:", text);
          return true;
        }

        const data = await res.json();
        console.log("📦 Backend API data:", data);

        if (!data.employee_role || data.employee_role === "権限なし") {
          console.warn("🚫 Role is invalid or missing");
          return true;
        }

        user.role = data.employee_role;
        user.location_id = data.location_id;
        user.employee_number = data.employee_number;
        user.employee_name = data.employee_name;

        console.log("✅ User enriched from backend:", user);

        return true;
      } catch (err) {
        console.error("❌ signIn callback exception:", err);
        return true;
      }
    },

    async jwt({ token, user, account }) {
      console.log("🔐 [jwt] triggered");
      console.log("📨 account:", account);
      console.log("👤 user:", user);
      console.log("🔑 token before:", token);

      if (account?.id_token) {
        const decoded = jwt.decode(account.id_token) as JwtPayload;
        console.log("🧾 Decoded id_token:", decoded);

        token.email = decoded?.email ?? decoded?.preferred_username ?? null;
        token.emailVerified = decoded?.email_verified ?? null;
        token.sub = decoded?.sub ?? account.providerAccountId;
      }

      if (account) {
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
        console.log("⏳ Access token expired — attempting refresh...");
        const refreshed = await refreshAccessToken(token.refreshToken);

        if (refreshed) {
          console.log("✅ Access token refreshed");
          token.idToken = refreshed.idToken;
          token.accessToken = refreshed.accessToken;
          token.expiresAt = refreshed.expiresAt;
        } else {
          console.error("❌ Failed to refresh access token");
          token.error = "FAILED_TO_REFRESH_ACCESS_TOKEN";
        }
      }

      console.log("🔑 token after:", token);
      return token;
    },

    async session({ session, token }) {
      console.log("💼 [session] triggered");
      console.log("🪪 token:", token);

      session.user = {
        id: token.sub ?? "unknown",
        name: token.employee_name || token.name || "不明なユーザー",
        email: token.email ?? "undefined@example.com",
        emailVerified: token.emailVerified === true ? new Date() : null,
        role: token.role ?? "",
        location_id: token.location_id ?? 0,
        employee_number: token.employee_number ?? 0,
        employee_name: token.employee_name ?? "",
      };

      session.error = token.error ?? null;

      console.log("📤 Final session:", session);

      return session;
    },
  },
};
