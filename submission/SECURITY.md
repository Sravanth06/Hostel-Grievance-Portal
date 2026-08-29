# Security Posture — HostelGrievance

## Overview

HostelGrievance is a web application used by students and wardens to
submit, review, communicate about, and manage hostel grievances.

The application was hardened before deployment with the primary objective
of reducing unauthorized access and limiting the blast radius of security
failures while preserving the existing Student and Warden workflows.

---

## Security Objectives

The hardened application focuses on:

1. Protecting student and grievance data.
2. Enforcing authentication and authorization on the server.
3. Preventing unauthorized object access.
4. Treating browser-controlled input as untrusted.
5. Safely handling uploaded files.
6. Protecting authentication sessions.
7. Preventing accidental exposure of internal application details.
8. Providing security-relevant audit visibility.
9. Preserving normal Student and Warden functionality.

---

## Authentication

Authentication is performed server-side.

The browser does not determine whether a user is authenticated or which
role the user has.

Sessions are stored server-side in the SQLite database.

Session tokens are generated using cryptographically secure random bytes.

Password authentication uses Argon2id for new password hashes. Legacy
password hashes are upgraded to Argon2id after successful authentication.

Authentication failures return a generic authentication error rather than
revealing whether a particular account exists.

The application also verifies that the authenticated user still exists in
the database when `/api/me` is accessed.

---

## Session Security

Authentication uses an opaque server-side session token.

The authentication cookie is configured with:

- `HttpOnly`
- `SameSite=Lax`
- `Secure` in production
- A finite session lifetime

Expired sessions are rejected and removed from the database.

Logout destroys the server-side session and clears the authentication
cookie.

Session tokens are not written to audit logs.

---

## Authorization

Authorization decisions are enforced by the API.

### Students

Students can:

- View their own grievances.
- Create grievances.
- Edit their own unresolved grievances.
- Add comments to their own grievances.
- Add attachments to their own grievances.
- View attachments belonging to their own grievances.

Students cannot:

- View another student's grievance.
- Modify another student's grievance.
- View another student's attachments.
- Change grievance status.
- Perform Warden-only management actions.

### Wardens

Wardens can:

- View grievances for management purposes.
- View grievance comments.
- Comment on grievances.
- Update grievance status.
- Access attachments associated with grievances they are authorized to
  manage.

Wardens cannot modify student-authored grievance content through the
student content update path.

Authorization is based on the authenticated server-side identity rather
than frontend state.

---

## Object-Level Authorization

Resource identifiers supplied by the client are not treated as proof of
ownership.

For grievance and attachment operations, the server retrieves the
resource and verifies the relationship between the authenticated user and
the resource before returning or modifying it.

This reduces the risk of insecure direct object reference (IDOR) style
attacks.

---

## Input Handling

User-controlled values are validated before being used.

Examples include:

- Grievance title length.
- Grievance description length.
- Grievance category.
- Grievance status.
- Comment content.
- Attachment type.
- Attachment size.
- Attachment filename metadata.

Database operations use parameterized SQL statements rather than
constructing SQL queries from user-controlled strings.

Invalid requests receive controlled application errors.

---

## File Upload Security

Attachments remain enabled because attachments are required application
functionality.

The following controls are applied:

- Only JPEG, PNG, GIF, and WebP MIME types are permitted.
- Files are limited to 2 MB.
- Empty files are rejected.
- Actual file signatures/magic bytes are checked.
- The browser-supplied MIME type is not trusted by itself.
- User-provided filenames are never used as physical storage filenames.
- Server-generated random filenames are used for stored files.
- Original filenames are treated as metadata only.
- Path traversal characters are rejected when resolving stored files.
- A resolved filesystem boundary check prevents access outside the upload
  directory.
- Stored files are accessed through authenticated API routes.
- Students cannot retrieve attachments belonging to other students.

The application therefore preserves attachment functionality while
reducing risks associated with malicious filenames, MIME spoofing, and
filesystem traversal.

---

## Error Handling

Expected application errors are returned using controlled HTTP responses.

Unexpected errors are handled centrally.

Internal error details such as:

- database errors,
- filesystem paths,
- runtime information,
- stack traces,

are not returned to clients.

Unexpected errors are logged server-side for investigation.

---

## CORS

Credentialed CORS requests are restricted to configured trusted origins.

The application does not reflect arbitrary browser origins when session
credentials are enabled.

The default development origins are:

- `http://localhost:5173`
- `http://127.0.0.1:5173`

Additional trusted origins can be supplied through:

`HOSTEL_ALLOWED_ORIGINS`

This value should contain only origins controlled by the deployment.

---

## Security Headers

The application applies browser-facing security controls where configured
by the application layer.

These controls are intended to reduce risks such as:

- MIME sniffing.
- Framing/clickjacking.
- Unnecessary browser feature access.
- Referrer information leakage.
- Caching of sensitive API responses.

The production reverse proxy or hosting environment should also enforce
appropriate HTTPS and security headers.

---

## Database Security

SQLite foreign-key enforcement is enabled.

Relationships between:

- users,
- sessions,
- grievances,
- comments,
- attachments,
- audit records

are represented using database constraints where appropriate.

Database access is performed by the server and is not directly exposed to
the browser.

---

## Audit Logging

Security-relevant authentication activity is recorded in an audit log.

Examples include:

- Invalid authentication requests.
- Missing authentication credentials.
- Failed login attempts.
- Successful login events.
- Logout events.
- Invalid sessions.

Audit records include investigation-oriented metadata such as:

- Event type.
- User ID when available.
- Request method.
- Request path.
- Client IP information when supplied by the deployment.
- Timestamp.
- Limited event details.

The audit system deliberately does not store:

- Passwords.
- Password hashes as event data.
- Session tokens.
- Uploaded file contents.

Audit logging is designed not to break normal application functionality if
the logging operation itself fails.

---

## Trust Boundaries

The important trust boundaries are:

```text
Browser
   |
   | Untrusted requests, cookies, form data, filenames
   v
Frontend
   |
   v
HTTP/API Server
   |
   +---- Authentication / Session
   |
   +---- Authorization
   |
   +---- SQLite Database
   |
   +---- Upload Storage