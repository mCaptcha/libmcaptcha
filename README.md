<div align="center">
  <h1>mCaptcha</h1>
  <p>
    <strong>mCaptcha - PoW based DoS protection</strong>
  </p>

[![Documentation](https://img.shields.io/badge/docs-master-blue)](https://mcaptcha.github.io/mCaptcha/m_captcha/index.html)
![CI (Linux)](<https://github.com/mCaptcha/mCaptcha/workflows/CI%20(Linux)/badge.svg>)
[![dependency status](https://deps.rs/repo/github/mCaptcha/mCaptcha/status.svg)](https://deps.rs/repo/github/mCaptcha/mCaptcha)
<br />
[![codecov](https://codecov.io/gh/mCaptcha/mCaptcha/branch/master/graph/badge.svg)](https://codecov.io/gh/mCaptcha/mCaptcha) 

</div>

### STATUS: ACTIVE DEVELOPMENT (fancy word for unusable)

mCaptcha uses SHA256 based proof-of-work(PoW) to rate limit users. 

**If someone wants to hammer your site, they will have to do more work to
send requests than your server will have to do to respond to their
request.**

## Why use mCaptcha?
- Free software, privacy focused
- Seamless UX - No more annoying captchas!
- IP address independent(sort of) - your users are behind a NAT? We got you covered!
- Automatic bot throttling
- Resistant to replay attacks - bye-bye captcha farms!

## Demo

I'll try to write a dedicated demo server but until then you can try
[Shuttlecraft/identity](github.com/shuttlecraft/identity)'s sign up page
available at https://accounts.shuttlecraft.io/signup. Feel free to
provide bogus information while signing up(project under development,
database frequently wiped).

Be sure to open dev tools' network tab to witness the magic!

## Usage:

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
