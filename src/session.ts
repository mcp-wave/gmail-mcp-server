// Shared session types used by both the MCP server core (index.ts) and the
// remote transport (http/server.ts). Kept in its own module so http/server.ts
// never imports index.ts (which would execute main()).

// gmail_v1.Gmail — typed as `any` here to avoid pulling googleapis types into
// every consumer; the tool dispatch in index.ts re-narrows it.
export type GmailClient = any;

/**
 * Per-account outbound send policy. Sending to the account's OWN address is
 * always allowed. Otherwise a recipient must match the allowlist (exact email,
 * `@domain.com`, or bare `domain.com`), unless `dangerouslyAllowAll` is set.
 */
export type SendPolicy = {
    allowlist: string[];
    dangerouslyAllowAll: boolean;
};

/** A single linked Gmail account within a principal. */
export type Account = {
    sub: string;
    email: string;
    primary: boolean;
    scopeNames: string[];
    sendPolicy?: SendPolicy;
};

/**
 * A principal = one claude.ai connection, which may own MULTIPLE linked Gmail
 * accounts. Tools select an account; reads fan out across all by default.
 */
export type PrincipalSession = {
    principalId: string;
    accounts: Account[];
    getClient: (sub: string) => { gmail: GmailClient; authorizedScopes: string[] };
    // Account-management ops, present only on the hosted (multi-account) server.
    linkAccount?: () => Promise<string>; // returns a sign-in URL for the user
    unlinkAccount?: (sub: string) => Promise<void>;
    // Persist a per-account send policy (hosted only).
    setSendPolicy?: (sub: string, policy: SendPolicy) => Promise<void>;
};

export type ResolveSession = (extra?: any) => Promise<PrincipalSession> | PrincipalSession;
