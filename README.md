#  Password Manager CLI

A Rust-based command-line tool to manage server access control, track login activity, and export audit logs.

---

##  Available Commands

### 1. `grant-access`
**Description:** Grants temporary access to an IP on a specific server.

```bash
cargo run -- grant-access <superuser> <ip> <server> --duration <minutes>
```
Example:

```bash
cargo run -- grant-access admin 192.168.1.101 server2 --duration 60
```

### 2. `revoke-access`
**Description:** Revokes access for an IP from a specific server.

```bash
cargo run -- revoke-access <superuser> <ip> <server>
```
Example:

```bash
cargo run -- revoke-access admin 192.168.1.101 server
```
### 3. `cleanup-expired`
**Description:** Removes all expired access records.

```bash
cargo run -- cleanup-expired <superuser>
```
Example:

```bash
cargo run -- cleanup-expired admin
```

### 4. `extend-access`
**Description:** Extends access duration for an IP on a server.

```bash
cargo run -- extend-access <superuser> <ip> <server> <duration_in_minutes>
```
Example:

```bash
cargo run -- extend-access admin 192.168.1.101 server2 120
```
### 5. login
**Description:** Logs user login timestamps for a given IP and server.

**Usage:**
```bash
cargo run -- login <IP_ADDRESS> <SERVER_ID>
```
Example:

```bash
cargo run -- login 192.168.1.101 server1
```
### 6.  view-access
**Description:** Views all access records. Requires superuser.

**Usage:**
```bash
cargo run -- view-access <SUPERUSER>
```
Example:

```bash
cargo run -- view-access admin
```
### 7.  shell
**Description:** Launches a monitored shell session for a given IP and server with logging of all commands executed.

**Usage:**
```bash
cargo run -- shell <IP_ADDRESS> <SERVER_ID>
```
Example:

```bash
cargo run -- shell 192.168.1.101 server1
```


