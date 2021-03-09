NOTE: This is an actix boilerplate repo

- Uses sqlx so set up database and carryout migrations before `cargo run`
- also change `placeholder` to github username and `placeholder-repo`
  to repo name
- change `PLACEHOLDER` to app name as mentioned in `./src/settings.rs`

# placeholder-repo

![CI (Linux)](<https://github.com/placeholder/placeholder-repo/workflows/CI%20(Linux)/badge.svg>)
[![codecov](https://codecov.io/gh/placeholder/placeholder-repo/branch/master/graph/badge.svg?token=4HjfPHCBEN)](https://codecov.io/gh/placeholder/placeholder-repo)
[![AGPL License](https://img.shields.io/badge/license-AGPL-blue.svg)](http://www.gnu.org/licenses/agpl-3.0)
[![dependency status](https://deps.rs/repo/github/placeholder/placeholder-repo/status.svg)](https://deps.rs/repo/github/placeholder/placeholder-repo)

### STATUS: ACTIVE DEVELOPMENT (fancy word for unusable)

</div>

**placeholder-repo** is an placeholder-repo and access management platform built for the
[IndieWeb](indieweb.org)

### How to build

- Install Cargo using [rustup](https://rustup.rs/) with:

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

- Clone the repository with:

```
$ git clone https://github.com/placeholder/placeholder-repo
```

- Build with Cargo:

```
$ cd placeholder-repo && cargo build
```

### Configuration:

placeholder-repo is highly configurable.
Configuration is applied/merged in the following order:

1. `config/default.toml`
2. environment variables.

To make installation process seamless, placeholder-repo ships with a CLI tool to
assist in database migrations.

#### Setup

##### Environment variables:

Setting environment variables are optional. The configuration files have
all the necessary parameters listed. By setting environment variables,
you will be overriding the values set in the configuration files.

###### Database:

| Name                            | Value                                  |
| ------------------------------- | -------------------------------------- |
| `PLACEHOLDER_DATEBASE_PASSWORD` | Postgres password                      |
| `PLACEHOLDER_DATEBASE_NAME`     | Postgres database name                 |
| `PLACEHOLDER_DATEBASE_PORT`     | Postgres port                          |
| `PLACEHOLDER_DATEBASE_HOSTNAME` | Postgres hostmane                      |
| `PLACEHOLDER_DATEBASE_USERNAME` | Postgres username                      |
| `PLACEHOLDER_DATEBASE_POOL`     | Postgres database connection pool size |

###### Redis cache:

| Name                         | Value          |
| ---------------------------- | -------------- |
| `PLACEHOLDER_REDIS_PORT`     | Redis port     |
| `PLACEHOLDER_REDIS_HOSTNAME` | Redis hostmane |

###### Server:

| Name                                      | Value                                               |
| ----------------------------------------- | --------------------------------------------------- |
| `PLACEHOLDER_SERVER_PORT` (or) `PORT`\*\* | The port on which you want wagon to listen to       |
| `PLACEHOLDER_SERVER_IP`                   | The IP address on which you want wagon to listen to |
| `PLACEHOLDER_SERVER_STATIC_FILES_DIR`     | Path to directory containing static files           |
