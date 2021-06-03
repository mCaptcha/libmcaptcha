<div align="center">
  <h1>libmcaptcha</h1>
  <p>
    <strong>mCaptcha - PoW based DoS protection</strong>
  </p>

[![Documentation](https://img.shields.io/badge/docs-master-yellow)](https://mcaptcha.github.io/mCaptcha/libmcaptcha/index.html)
[![Documentation](https://img.shields.io/badge/docs-0.1.3-blue)](https://mcaptcha.org/docs/api/mcaptcha-system)
[![dependency status](https://deps.rs/repo/github/mCaptcha/libmcaptcha/status.svg)](https://deps.rs/repo/github/mCaptcha/libmcaptcha)
[![AGPL License](https://img.shields.io/badge/license-AGPL-blue.svg)](http://www.gnu.org/licenses/agpl-3.0)
![CI (Linux)](<https://github.com/mCaptcha/libmcaptcha/workflows/CI%20(Linux)/badge.svg>)
<br />
[![codecov](https://codecov.io/gh/mCaptcha/libmcaptcha/branch/master/graph/badge.svg)](https://codecov.io/gh/mCaptcha/libmcaptcha)
[![Documentation](https://img.shields.io/badge/matrix-community-purple)](https://matrix.to/#/+mcaptcha:matrix.batsense.net)

</div>

mCaptcha uses SHA256 based proof-of-work(PoW) to rate limit users.

If someone wants to hammer your site, they will have to do more work to
send requests than your server will have to do to respond to their
request.

> **NOTE:** `0.1.x` is out, expect breaking changes as ergonomics and
> performance is improved. Checkout [changelog](./CHANGELOG.md) for
> changes and migration pointers. Breaking changes will be frequent
> through `0.1.x`.

## Why use mCaptcha?

- Free software, privacy focused
- Seamless UX - No more annoying captchas!
- IP address independent(sort of) - your users are behind a NAT? We got you covered!
- Automatic bot throttling
- Resistant to replay attacks - bye-bye captcha farms!

## Demo

### Demo servers are available at:

- https://demo.mcaptcha.org/
- https://demo2.mcaptcha.org/ (runs on a Raspberry Pi!)

> Core functionality is working but it's still very much
> work-in-progress.

Feel free to provide bogus information while signing up(project under
development, database frequently wiped).

### Self-hosted:

Please refer to [mCaptcha/mCaptcha](https://github.com/mCaptcha/mCaptcha) for
instructions.

## Documentation

- [master-branch](https://mcaptcha.github.io/mCaptcha/libmcaptcha/index.html)
- [All published versions](https://mcaptcha.org/docs/api/mcaptcha-system)

## Usage

mCaptcha is made up of three components:

#### 1. Front-end library

We have a WASM library now, Android and iOS libraries soon

#### 2. Back-end library

We have Rust library, other languages will have support soon

#### 3. Rate limiting service

Under development.

A paid, managed service will be made available soon but
I([@realaravinth](https://batsense.net)) encourage you guys to
self-host. Go decentralisation!

## Contributing

yes please!
